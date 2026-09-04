"""
Extended tests for MTLSChecker — validation logic, metrics, no real TLS connections.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from offensive_ai.core.mtls_checker import MTLSChecker
from offensive_ai.models.mtls_result import CertificateInfo, MTLSResult


# ---------------------------------------------------------------------------
# __init__ validation
# ---------------------------------------------------------------------------

class TestMTLSCheckerInit:
    def test_default_init(self):
        checker = MTLSChecker()
        assert checker.timeout == 10
        assert checker.verify_ssl is True
        assert checker.max_retries == 3
        assert checker.retry_delay == 1.0

    def test_custom_valid_params(self):
        checker = MTLSChecker(timeout=30, max_retries=5, retry_delay=2.0, verify_ssl=False)
        assert checker.timeout == 30
        assert checker.max_retries == 5
        assert checker.retry_delay == 2.0
        assert checker.verify_ssl is False

    def test_timeout_too_low_raises(self):
        with pytest.raises(ValueError, match="Timeout"):
            MTLSChecker(timeout=0)

    def test_timeout_too_high_raises(self):
        with pytest.raises(ValueError, match="Timeout"):
            MTLSChecker(timeout=301)

    def test_timeout_boundary_low_valid(self):
        checker = MTLSChecker(timeout=1)
        assert checker.timeout == 1

    def test_timeout_boundary_high_valid(self):
        checker = MTLSChecker(timeout=300)
        assert checker.timeout == 300

    def test_max_retries_negative_raises(self):
        with pytest.raises(ValueError, match="Max retries"):
            MTLSChecker(max_retries=-1)

    def test_max_retries_too_high_raises(self):
        with pytest.raises(ValueError, match="Max retries"):
            MTLSChecker(max_retries=11)

    def test_max_retries_zero_valid(self):
        checker = MTLSChecker(max_retries=0)
        assert checker.max_retries == 0

    def test_max_retries_10_valid(self):
        checker = MTLSChecker(max_retries=10)
        assert checker.max_retries == 10

    def test_retry_delay_too_low_raises(self):
        with pytest.raises(ValueError, match="Retry delay"):
            MTLSChecker(retry_delay=0.05)

    def test_retry_delay_too_high_raises(self):
        with pytest.raises(ValueError, match="Retry delay"):
            MTLSChecker(retry_delay=10.1)

    def test_retry_delay_boundary_low_valid(self):
        checker = MTLSChecker(retry_delay=0.1)
        assert checker.retry_delay == 0.1

    def test_retry_delay_boundary_high_valid(self):
        checker = MTLSChecker(retry_delay=10.0)
        assert checker.retry_delay == 10.0

    def test_logging_disabled(self):
        checker = MTLSChecker(enable_logging=False)
        import logging
        assert checker.logger.level == logging.CRITICAL

    def test_timeout_float_raises(self):
        with pytest.raises(ValueError, match="Timeout"):
            MTLSChecker(timeout=10.5)  # Must be int


# ---------------------------------------------------------------------------
# _validate_target
# ---------------------------------------------------------------------------

class TestValidateTarget:
    def setup_method(self):
        self.checker = MTLSChecker()

    def test_valid_hostname(self):
        result = self.checker._validate_target("example.com")
        assert result == "example.com"

    def test_valid_subdomain(self):
        result = self.checker._validate_target("api.example.com")
        assert result == "api.example.com"

    def test_strips_leading_whitespace(self):
        result = self.checker._validate_target("  example.com  ")
        assert result == "example.com"

    def test_lowercases_target(self):
        result = self.checker._validate_target("Example.COM")
        assert result == "example.com"

    def test_valid_ip_address(self):
        result = self.checker._validate_target("192.168.1.1")
        assert result == "192.168.1.1"

    def test_valid_ipv6_address(self):
        result = self.checker._validate_target("::1")
        assert result == "::1"

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            self.checker._validate_target("")

    def test_none_raises(self):
        with pytest.raises((ValueError, AttributeError)):
            self.checker._validate_target(None)

    def test_hostname_too_long_raises(self):
        long_hostname = "a" * 254 + ".com"
        with pytest.raises(ValueError, match="too long"):
            self.checker._validate_target(long_hostname)

    def test_hostname_starting_with_dot_raises(self):
        with pytest.raises(ValueError):
            self.checker._validate_target(".example.com")

    def test_hostname_ending_with_dot_raises(self):
        with pytest.raises(ValueError):
            self.checker._validate_target("example.com.")

    def test_strips_https_prefix(self):
        result = self.checker._validate_target("https://example.com")
        assert "://" not in result

    def test_strips_http_prefix(self):
        result = self.checker._validate_target("http://example.com")
        assert "://" not in result


# ---------------------------------------------------------------------------
# _validate_port
# ---------------------------------------------------------------------------

class TestValidatePort:
    def setup_method(self):
        self.checker = MTLSChecker()

    def test_valid_port_443(self):
        assert self.checker._validate_port(443) == 443

    def test_valid_port_1(self):
        assert self.checker._validate_port(1) == 1

    def test_valid_port_65535(self):
        assert self.checker._validate_port(65535) == 65535

    def test_port_zero_raises(self):
        with pytest.raises(ValueError, match="Port"):
            self.checker._validate_port(0)

    def test_port_too_high_raises(self):
        with pytest.raises(ValueError, match="Port"):
            self.checker._validate_port(65536)

    def test_port_negative_raises(self):
        with pytest.raises(ValueError, match="Port"):
            self.checker._validate_port(-1)

    def test_port_string_raises(self):
        with pytest.raises(ValueError, match="Port"):
            self.checker._validate_port("443")


# ---------------------------------------------------------------------------
# get_metrics / _reset_metrics
# ---------------------------------------------------------------------------

class TestMetrics:
    def setup_method(self):
        self.checker = MTLSChecker()

    def test_initial_metrics_all_zero(self):
        metrics = self.checker.get_metrics()
        for key, value in metrics.items():
            assert value == 0 or value == 0.0, f"Expected 0 for {key}, got {value}"

    def test_metrics_returns_copy(self):
        metrics1 = self.checker.get_metrics()
        metrics2 = self.checker.get_metrics()
        assert metrics1 == metrics2
        # Modifying one should not affect the other
        metrics1["total_requests"] = 999
        assert self.checker.get_metrics()["total_requests"] == 0

    def test_reset_metrics_zeroes_all(self):
        # Manually increment metrics
        self.checker._metrics["total_requests"] = 5
        self.checker._metrics["successful_connections"] = 3
        
        # Reset
        self.checker._reset_metrics()
        
        metrics = self.checker.get_metrics()
        assert metrics["total_requests"] == 0
        assert metrics["successful_connections"] == 0

    def test_metrics_has_expected_keys(self):
        metrics = self.checker.get_metrics()
        expected_keys = [
            "total_requests", "successful_connections", "failed_connections",
            "mtls_supported", "client_cert_required", "handshake_failures",
            "certificate_errors", "network_errors", "timeout_errors", "total_time"
        ]
        for key in expected_keys:
            assert key in metrics, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# _validate_certificate_files
# ---------------------------------------------------------------------------

class TestValidateCertificateFiles:
    def setup_method(self):
        self.checker = MTLSChecker()

    def test_both_none_returns_none_none(self):
        cert, key = self.checker._validate_certificate_files(None, None)
        assert cert is None
        assert key is None

    def test_cert_without_key_raises(self):
        with pytest.raises(ValueError):
            self.checker._validate_certificate_files("/some/cert.pem", None)

    def test_key_without_cert_raises(self):
        with pytest.raises(ValueError):
            self.checker._validate_certificate_files(None, "/some/key.pem")

    def test_nonexistent_cert_file_raises(self):
        with pytest.raises(ValueError, match="not found"):
            self.checker._validate_certificate_files(
                "/nonexistent/cert.pem",
                "/nonexistent/key.pem"
            )


# ---------------------------------------------------------------------------
# check_mtls — with mocked network calls
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckMtlsMocked:
    async def test_check_mtls_returns_result_on_network_error(self):
        """check_mtls should return an error MTLSResult rather than raising."""
        checker = MTLSChecker(max_retries=0, retry_delay=0.1)

        with patch.object(
            checker, "_perform_mtls_check",
            AsyncMock(side_effect=ConnectionError("Connection refused"))
        ):
            result = await checker.check_mtls("nonexistent.local", port=443)

        assert isinstance(result, MTLSResult)
        assert result.supports_mtls is False
        assert result.error_message is not None
        assert "Connection" in result.error_message or "failed" in result.error_message.lower()

    async def test_check_mtls_updates_metrics_on_success(self):
        checker = MTLSChecker(max_retries=0)
        from datetime import datetime, timezone
        mock_result = MTLSResult(
            target="example.com",
            port=443,
            supports_mtls=True,
            requires_client_cert=False,
            server_cert_info=None,
            client_cert_requested=False,
            handshake_successful=True,
            error_message=None,
            cipher_suite="TLS_AES_256_GCM_SHA384",
            tls_version="TLSv1.3",
            verification_mode="default",
            ca_bundle_path=None,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        with patch.object(checker, "_perform_mtls_check", AsyncMock(return_value=mock_result)):
            await checker.check_mtls("example.com", port=443)

        metrics = checker.get_metrics()
        assert metrics["total_requests"] == 1
        assert metrics["successful_connections"] == 1

    async def test_check_mtls_invalid_target_returns_error_result(self):
        """Empty target should result in an error MTLSResult (not raise)."""
        checker = MTLSChecker()
        result = await checker.check_mtls("", port=443)
        assert isinstance(result, MTLSResult)
        assert result.supports_mtls is False
        assert result.error_message is not None

    async def test_check_mtls_invalid_port_returns_error_result(self):
        """Invalid port should result in an error MTLSResult (not raise)."""
        checker = MTLSChecker()
        result = await checker.check_mtls("example.com", port=99999)
        assert isinstance(result, MTLSResult)
        assert result.supports_mtls is False
        assert result.error_message is not None
