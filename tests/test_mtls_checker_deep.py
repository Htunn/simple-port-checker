"""
Deep coverage tests for MTLSChecker and utility functions.
Targets: _perform_mtls_check, batch_check_mtls, generate_self_signed_cert,
validate_certificate_files, _parse_certificate, _execute_with_retry.
"""

from __future__ import annotations

import asyncio
import ssl
import socket
import tempfile
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from offensive_ai.core.mtls_checker import (
    MTLSChecker,
    generate_self_signed_cert,
    validate_certificate_files,
)
from offensive_ai.models.mtls_result import CertificateInfo, MTLSResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mtls_result(target="example.com", port=443, **kwargs) -> MTLSResult:
    defaults = dict(
        supports_mtls=False,
        requires_client_cert=False,
        server_cert_info=None,
        client_cert_requested=False,
        handshake_successful=False,
        error_message=None,
        cipher_suite=None,
        tls_version=None,
        verification_mode=None,
        ca_bundle_path=None,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    defaults.update(kwargs)
    return MTLSResult(target=target, port=port, **defaults)


# ---------------------------------------------------------------------------
# _execute_with_retry
# ---------------------------------------------------------------------------

class TestExecuteWithRetry:
    @pytest.mark.asyncio
    async def test_succeeds_on_first_attempt(self):
        checker = MTLSChecker(max_retries=2, retry_delay=0.1)
        op = AsyncMock(return_value="success")
        result = await checker._execute_with_retry("test_op", op)
        assert result == "success"
        assert op.call_count == 1

    @pytest.mark.asyncio
    async def test_retries_and_succeeds_on_second(self):
        checker = MTLSChecker(max_retries=2, retry_delay=0.1)
        results = iter(["fail", "ok"])
        call_count = {"n": 0}

        async def flaky_op():
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise ConnectionError("transient")
            return "ok"

        result = await checker._execute_with_retry("flaky", flaky_op)
        assert result == "ok"
        assert call_count["n"] == 2

    @pytest.mark.asyncio
    async def test_exhausts_retries_and_raises(self):
        checker = MTLSChecker(max_retries=2, retry_delay=0.1)

        async def always_fail():
            raise ConnectionError("permanent")

        with pytest.raises(ConnectionError, match="permanent"):
            await checker._execute_with_retry("always_fail", always_fail)

    @pytest.mark.asyncio
    async def test_sync_function_wrapped(self):
        """Non-async callables should also work."""
        checker = MTLSChecker(max_retries=1, retry_delay=0.1)

        def sync_func():
            return "sync_result"

        result = await checker._execute_with_retry("sync_test", sync_func)
        assert result == "sync_result"


# ---------------------------------------------------------------------------
# _perform_mtls_check — mocked internal helpers
# ---------------------------------------------------------------------------

class TestPerformMtlsCheck:
    @pytest.mark.asyncio
    async def test_no_client_cert_requested(self):
        checker = MTLSChecker(max_retries=0)
        ts = datetime.now(timezone.utc).isoformat()

        with (
            patch.object(checker, "_get_server_certificate_info", AsyncMock(return_value=None)),
            patch.object(checker, "_check_client_cert_requirement", AsyncMock(return_value=(False, False))),
        ):
            result = await checker._perform_mtls_check(
                "example.com", 443, None, None, None, ts
            )

        assert result.supports_mtls is False
        assert result.requires_client_cert is False
        assert result.handshake_successful is False

    @pytest.mark.asyncio
    async def test_client_cert_requested_but_none_provided(self):
        checker = MTLSChecker(max_retries=0)
        ts = datetime.now(timezone.utc).isoformat()

        with (
            patch.object(checker, "_get_server_certificate_info", AsyncMock(return_value=None)),
            patch.object(checker, "_check_client_cert_requirement", AsyncMock(return_value=(True, True))),
        ):
            result = await checker._perform_mtls_check(
                "example.com", 443, None, None, None, ts
            )

        assert result.client_cert_requested is True
        assert result.requires_client_cert is True
        assert "client certificate" in (result.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_mtls_handshake_with_provided_certs(self):
        checker = MTLSChecker(max_retries=0)
        ts = datetime.now(timezone.utc).isoformat()

        handshake_result = {
            "success": True,
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "tls_version": "TLSv1.3",
            "error": None,
        }

        with (
            patch.object(checker, "_get_server_certificate_info", AsyncMock(return_value=None)),
            patch.object(checker, "_check_client_cert_requirement", AsyncMock(return_value=(True, True))),
            patch.object(checker, "_perform_mtls_handshake", AsyncMock(return_value=handshake_result)),
        ):
            result = await checker._perform_mtls_check(
                "example.com", 443, "/fake/cert.pem", "/fake/key.pem", None, ts
            )

        assert result.handshake_successful is True
        assert result.cipher_suite == "TLS_AES_256_GCM_SHA384"
        assert result.tls_version == "TLSv1.3"

    @pytest.mark.asyncio
    async def test_mtls_handshake_exception_sets_error_message(self):
        checker = MTLSChecker(max_retries=0)
        ts = datetime.now(timezone.utc).isoformat()

        with (
            patch.object(checker, "_get_server_certificate_info", AsyncMock(return_value=None)),
            patch.object(checker, "_check_client_cert_requirement", AsyncMock(return_value=(True, True))),
            patch.object(
                checker,
                "_perform_mtls_handshake",
                AsyncMock(side_effect=ssl.SSLError("cert verify failed")),
            ),
        ):
            result = await checker._perform_mtls_check(
                "example.com", 443, "/fake/cert.pem", "/fake/key.pem", None, ts
            )

        assert result.handshake_successful is False
        assert result.error_message is not None
        assert "mTLS handshake failed" in result.error_message


# ---------------------------------------------------------------------------
# check_mtls — full flow with mocked _perform_mtls_check
# ---------------------------------------------------------------------------

class TestCheckMtlsFull:
    @pytest.mark.asyncio
    async def test_mtls_supported_increments_metric(self):
        checker = MTLSChecker(max_retries=0)
        mock_result = _make_mtls_result(supports_mtls=True)

        with patch.object(checker, "_perform_mtls_check", AsyncMock(return_value=mock_result)):
            await checker.check_mtls("example.com")

        assert checker.get_metrics()["mtls_supported"] == 1

    @pytest.mark.asyncio
    async def test_client_cert_required_increments_metric(self):
        checker = MTLSChecker(max_retries=0)
        mock_result = _make_mtls_result(requires_client_cert=True)

        with patch.object(checker, "_perform_mtls_check", AsyncMock(return_value=mock_result)):
            await checker.check_mtls("example.com")

        assert checker.get_metrics()["client_cert_required"] == 1

    @pytest.mark.asyncio
    async def test_failed_handshake_increments_metric(self):
        checker = MTLSChecker(max_retries=0)
        mock_result = _make_mtls_result(handshake_successful=False)

        with patch.object(checker, "_perform_mtls_check", AsyncMock(return_value=mock_result)):
            await checker.check_mtls("example.com")

        assert checker.get_metrics()["handshake_failures"] == 1

    @pytest.mark.asyncio
    async def test_timeout_error_increments_timeout_metric(self):
        checker = MTLSChecker(max_retries=0)

        with patch.object(
            checker,
            "_perform_mtls_check",
            AsyncMock(side_effect=asyncio.TimeoutError()),
        ):
            result = await checker.check_mtls("example.com")

        assert checker.get_metrics()["timeout_errors"] == 1
        assert result.error_message is not None

    @pytest.mark.asyncio
    async def test_network_error_increments_network_metric(self):
        checker = MTLSChecker(max_retries=0)

        with patch.object(
            checker,
            "_perform_mtls_check",
            AsyncMock(side_effect=ConnectionError("reset by peer")),
        ):
            result = await checker.check_mtls("example.com")

        assert checker.get_metrics()["network_errors"] == 1

    @pytest.mark.asyncio
    async def test_certificate_error_increments_cert_metric(self):
        checker = MTLSChecker(max_retries=0)

        with patch.object(
            checker,
            "_perform_mtls_check",
            AsyncMock(side_effect=Exception("certificate verify failed")),
        ):
            result = await checker.check_mtls("example.com")

        assert checker.get_metrics()["certificate_errors"] == 1


# ---------------------------------------------------------------------------
# batch_check_mtls
# ---------------------------------------------------------------------------

class TestBatchCheckMtls:
    @pytest.mark.asyncio
    async def test_empty_targets_raises(self):
        checker = MTLSChecker()
        with pytest.raises(ValueError, match="least one"):
            await checker.batch_check_mtls([])

    @pytest.mark.asyncio
    async def test_invalid_max_concurrent_raises(self):
        checker = MTLSChecker()
        with pytest.raises(ValueError, match="max_concurrent"):
            await checker.batch_check_mtls(["example.com"], max_concurrent=0)

    @pytest.mark.asyncio
    async def test_invalid_target_format_raises(self):
        checker = MTLSChecker()
        with pytest.raises(ValueError, match="Invalid target"):
            await checker.batch_check_mtls([("a", "b", "c")])  # tuple of wrong length

    @pytest.mark.asyncio
    async def test_batch_with_string_targets(self):
        checker = MTLSChecker(max_retries=0)
        mock_result = _make_mtls_result()

        with patch.object(checker, "_perform_mtls_check", AsyncMock(return_value=mock_result)):
            results = await checker.batch_check_mtls(["example.com", "test.com"])

        assert len(results) == 2
        assert all(isinstance(r, MTLSResult) for r in results)

    @pytest.mark.asyncio
    async def test_batch_with_tuple_targets(self):
        checker = MTLSChecker(max_retries=0)
        mock_result = _make_mtls_result()

        with patch.object(checker, "_perform_mtls_check", AsyncMock(return_value=mock_result)):
            results = await checker.batch_check_mtls([("example.com", 443), ("test.com", 8443)])

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_batch_progress_callback_called(self):
        checker = MTLSChecker(max_retries=0)
        mock_result = _make_mtls_result()
        progress_calls = []

        def on_progress(completed, total, result):
            progress_calls.append((completed, total))

        with patch.object(checker, "_perform_mtls_check", AsyncMock(return_value=mock_result)):
            results = await checker.batch_check_mtls(
                ["a.com", "b.com"],
                progress_callback=on_progress,
            )

        assert len(progress_calls) == 2
        assert all(total == 2 for _, total in progress_calls)

    @pytest.mark.asyncio
    async def test_batch_handles_individual_failure(self):
        """Errors in individual checks should not stop the batch."""
        checker = MTLSChecker(max_retries=0)
        call_count = {"n": 0}

        async def flaky_check(target, port, *args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise ConnectionError("first fails")
            return _make_mtls_result(target=target, port=port)

        with patch.object(checker, "_perform_mtls_check", side_effect=flaky_check):
            results = await checker.batch_check_mtls(["a.com", "b.com"])

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_batch_max_concurrent_limited(self):
        """batch_check_mtls respects max_concurrent semaphore."""
        checker = MTLSChecker(max_retries=0)
        mock_result = _make_mtls_result()

        with patch.object(checker, "_perform_mtls_check", AsyncMock(return_value=mock_result)):
            results = await checker.batch_check_mtls(
                ["a.com", "b.com", "c.com"],
                max_concurrent=2,
            )

        assert len(results) == 3


# ---------------------------------------------------------------------------
# generate_self_signed_cert utility function
# ---------------------------------------------------------------------------

class TestGenerateSelfSignedCert:
    def test_generates_cert_and_key_files(self, tmp_path):
        cert_path = str(tmp_path / "test.crt")
        key_path = str(tmp_path / "test.key")
        result = generate_self_signed_cert("localhost", cert_path, key_path)
        assert result is True
        assert Path(cert_path).exists()
        assert Path(key_path).exists()

    def test_cert_content_is_pem(self, tmp_path):
        cert_path = str(tmp_path / "test.crt")
        key_path = str(tmp_path / "test.key")
        generate_self_signed_cert("example.com", cert_path, key_path)
        cert_data = Path(cert_path).read_text()
        assert "BEGIN CERTIFICATE" in cert_data

    def test_key_content_is_pem(self, tmp_path):
        cert_path = str(tmp_path / "test.crt")
        key_path = str(tmp_path / "test.key")
        generate_self_signed_cert("example.com", cert_path, key_path)
        key_data = Path(key_path).read_text()
        assert "PRIVATE KEY" in key_data

    def test_custom_days_valid(self, tmp_path):
        cert_path = str(tmp_path / "test.crt")
        key_path = str(tmp_path / "test.key")
        result = generate_self_signed_cert("example.com", cert_path, key_path, days_valid=30)
        assert result is True

    def test_invalid_path_returns_false(self):
        result = generate_self_signed_cert(
            "example.com",
            "/nonexistent/deeply/nested/path/cert.pem",
            "/nonexistent/deeply/nested/path/key.pem",
        )
        assert result is False


# ---------------------------------------------------------------------------
# validate_certificate_files utility function
# ---------------------------------------------------------------------------

class TestValidateCertificateFilesUtility:
    def test_valid_cert_key_pair(self, tmp_path):
        cert_path = str(tmp_path / "cert.pem")
        key_path = str(tmp_path / "key.pem")
        generate_self_signed_cert("example.com", cert_path, key_path)
        is_valid, msg = validate_certificate_files(cert_path, key_path)
        assert is_valid is True

    def test_nonexistent_cert_returns_invalid(self, tmp_path):
        is_valid, msg = validate_certificate_files(
            str(tmp_path / "missing.pem"),
            str(tmp_path / "missing.key"),
        )
        assert is_valid is False
        assert "not found" in msg.lower() or "Certificate" in msg

    def test_invalid_cert_content_returns_invalid(self, tmp_path):
        cert_path = str(tmp_path / "bad.pem")
        key_path = str(tmp_path / "bad.key")
        Path(cert_path).write_text("not a real certificate")
        Path(key_path).write_text("not a real key")
        is_valid, msg = validate_certificate_files(cert_path, key_path)
        assert is_valid is False

    def test_mismatched_cert_and_key_returns_invalid(self, tmp_path):
        """Two separate self-signed certs whose keys don't match."""
        cert1 = str(tmp_path / "cert1.pem")
        key1 = str(tmp_path / "key1.pem")
        cert2 = str(tmp_path / "cert2.pem")
        key2 = str(tmp_path / "key2.pem")
        generate_self_signed_cert("host1.example.com", cert1, key1)
        generate_self_signed_cert("host2.example.com", cert2, key2)
        # Using cert1 with key2 should fail the match check
        is_valid, msg = validate_certificate_files(cert1, key2)
        assert is_valid is False


# ---------------------------------------------------------------------------
# _parse_certificate — with a real self-signed certificate
# ---------------------------------------------------------------------------

class TestParseCertificate:
    def _load_cert(self, tmp_path):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        cert_path = str(tmp_path / "cert.pem")
        key_path = str(tmp_path / "key.pem")
        generate_self_signed_cert("parse-test.example.com", cert_path, key_path)
        cert_data = Path(cert_path).read_bytes()
        return x509.load_pem_x509_certificate(cert_data)

    def test_parse_returns_certificate_info(self, tmp_path):
        checker = MTLSChecker()
        cert = self._load_cert(tmp_path)
        info = checker._parse_certificate(cert)
        assert isinstance(info, CertificateInfo)

    def test_parsed_subject_contains_hostname(self, tmp_path):
        checker = MTLSChecker()
        cert = self._load_cert(tmp_path)
        info = checker._parse_certificate(cert)
        assert "parse-test.example.com" in info.subject

    def test_parsed_is_self_signed(self, tmp_path):
        checker = MTLSChecker()
        cert = self._load_cert(tmp_path)
        info = checker._parse_certificate(cert)
        assert info.is_self_signed is True

    def test_parsed_key_size(self, tmp_path):
        checker = MTLSChecker()
        cert = self._load_cert(tmp_path)
        info = checker._parse_certificate(cert)
        assert info.key_size == 2048

    def test_parsed_san_contains_hostname(self, tmp_path):
        checker = MTLSChecker()
        cert = self._load_cert(tmp_path)
        info = checker._parse_certificate(cert)
        assert "parse-test.example.com" in info.san_dns_names


# ---------------------------------------------------------------------------
# _get_server_certificate_info — with mocked socket
# ---------------------------------------------------------------------------

class TestGetServerCertificateInfo:
    @pytest.mark.asyncio
    async def test_returns_none_on_ssl_error(self):
        checker = MTLSChecker(verify_ssl=False)
        with patch("socket.create_connection", side_effect=ssl.SSLError("cert error")):
            result = await checker._get_server_certificate_info("example.com", 443)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_timeout(self):
        checker = MTLSChecker(verify_ssl=False)
        with patch("socket.create_connection", side_effect=socket.timeout("timed out")):
            result = await checker._get_server_certificate_info("example.com", 443)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_general_exception(self):
        checker = MTLSChecker(verify_ssl=False)
        with patch("socket.create_connection", side_effect=Exception("unexpected")):
            result = await checker._get_server_certificate_info("example.com", 443)
        assert result is None


# ---------------------------------------------------------------------------
# _check_client_cert_requirement — with mocked socket
# ---------------------------------------------------------------------------

class TestCheckClientCertRequirement:
    @pytest.mark.asyncio
    async def test_returns_false_false_on_timeout(self):
        checker = MTLSChecker(verify_ssl=False)
        with patch("socket.create_connection", side_effect=socket.timeout("timed out")):
            requested, required = await checker._check_client_cert_requirement("example.com", 443)
        assert requested is False
        assert required is False

    @pytest.mark.asyncio
    async def test_returns_true_true_on_cert_required_error(self):
        checker = MTLSChecker(verify_ssl=False)
        ssl_err = ssl.SSLError("certificate required")
        with patch("socket.create_connection", side_effect=ssl_err):
            requested, required = await checker._check_client_cert_requirement("example.com", 443)
        assert requested is True
        assert required is True

    @pytest.mark.asyncio
    async def test_returns_false_false_on_general_exception(self):
        checker = MTLSChecker(verify_ssl=False)
        with patch("socket.create_connection", side_effect=Exception("unknown")):
            requested, required = await checker._check_client_cert_requirement("example.com", 443)
        assert requested is False
        assert required is False


# ---------------------------------------------------------------------------
# _perform_mtls_handshake — mocked socket
# ---------------------------------------------------------------------------

class TestPerformMtlsHandshake:
    @pytest.mark.asyncio
    async def test_returns_success_false_on_ssl_error(self, tmp_path):
        cert_path = str(tmp_path / "c.pem")
        key_path = str(tmp_path / "k.pem")
        generate_self_signed_cert("test.example.com", cert_path, key_path)
        checker = MTLSChecker(verify_ssl=False)
        with patch("socket.create_connection", side_effect=ssl.SSLError("bad cert")):
            result = await checker._perform_mtls_handshake(
                "example.com", 443, cert_path, key_path, None
            )
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_returns_success_false_on_timeout(self, tmp_path):
        cert_path = str(tmp_path / "c.pem")
        key_path = str(tmp_path / "k.pem")
        generate_self_signed_cert("test.example.com", cert_path, key_path)
        checker = MTLSChecker(verify_ssl=False)
        with patch("socket.create_connection", side_effect=socket.timeout("timed out")):
            result = await checker._perform_mtls_handshake(
                "example.com", 443, cert_path, key_path, None
            )
        assert result["success"] is False
        assert "timeout" in (result.get("error") or "").lower()
