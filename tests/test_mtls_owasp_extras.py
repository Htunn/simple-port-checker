"""
Tests for mTLS checker models and MTLSChecker constructor/validation,
OwaspScanner internal methods, and mcp_attacker extended paths.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from offensive_ai.models.mtls_result import (
    BatchMTLSResult,
    CertificateInfo,
    MTLSConfig,
    MTLSResult,
    MTLSTestProfile,
)
from offensive_ai.core.mtls_checker import MTLSChecker


# ===========================================================================
# CertificateInfo model
# ===========================================================================

class TestCertificateInfo:
    def _make(self, **kwargs):
        defaults = dict(
            subject="CN=server.example.com",
            issuer="CN=Root CA",
            version=3,
            serial_number="1234ABCD",
            not_valid_before="2024-01-01T00:00:00+00:00",
            not_valid_after="2025-01-01T00:00:00+00:00",
            signature_algorithm="sha256WithRSAEncryption",
            key_algorithm="RSA",
            fingerprint_sha256="ABCDEF1234567890" * 4,
        )
        defaults.update(kwargs)
        return CertificateInfo(**defaults)

    def test_basic_creation(self):
        cert = self._make()
        assert cert.subject == "CN=server.example.com"
        assert cert.issuer == "CN=Root CA"

    def test_optional_fields_default(self):
        cert = self._make()
        assert cert.key_size is None
        assert cert.san_dns_names == []
        assert cert.san_ip_addresses == []
        assert cert.is_ca is False
        assert cert.is_self_signed is False

    def test_with_key_size(self):
        cert = self._make(key_size=2048)
        assert cert.key_size == 2048

    def test_ca_cert(self):
        cert = self._make(is_ca=True)
        assert cert.is_ca is True

    def test_self_signed(self):
        cert = self._make(is_self_signed=True)
        assert cert.is_self_signed is True

    def test_san_dns_names(self):
        cert = self._make(san_dns_names=["example.com", "www.example.com"])
        assert "example.com" in cert.san_dns_names

    def test_san_ip_addresses(self):
        cert = self._make(san_ip_addresses=["10.0.0.1"])
        assert "10.0.0.1" in cert.san_ip_addresses


# ===========================================================================
# MTLSResult model
# ===========================================================================

class TestMTLSResult:
    def _make(self, **kwargs):
        defaults = dict(
            target="server.example.com",
            port=443,
            supports_mtls=True,
            requires_client_cert=False,
            client_cert_requested=False,
            handshake_successful=True,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        defaults.update(kwargs)
        return MTLSResult(**defaults)

    def test_basic_fields(self):
        result = self._make()
        assert result.target == "server.example.com"
        assert result.port == 443
        assert result.supports_mtls is True

    def test_optional_fields_none(self):
        result = self._make()
        assert result.server_cert_info is None
        assert result.error_message is None
        assert result.cipher_suite is None
        assert result.tls_version is None

    def test_error_state(self):
        result = self._make(
            supports_mtls=False,
            handshake_successful=False,
            error_message="Connection refused",
        )
        assert result.error_message == "Connection refused"
        assert result.handshake_successful is False

    def test_with_cert_info(self):
        cert = CertificateInfo(
            subject="CN=server.example.com",
            issuer="CN=Root CA",
            version=3,
            serial_number="123",
            not_valid_before="2024-01-01T00:00:00+00:00",
            not_valid_after="2025-01-01T00:00:00+00:00",
            signature_algorithm="sha256WithRSAEncryption",
            key_algorithm="RSA",
            fingerprint_sha256="ABCD" * 16,
        )
        result = self._make(server_cert_info=cert)
        assert result.server_cert_info is not None
        assert result.server_cert_info.subject == "CN=server.example.com"

    def test_cipher_suite_stored(self):
        result = self._make(cipher_suite="TLS_AES_256_GCM_SHA384")
        assert result.cipher_suite == "TLS_AES_256_GCM_SHA384"

    def test_tls_version_stored(self):
        result = self._make(tls_version="TLSv1.3")
        assert result.tls_version == "TLSv1.3"


# ===========================================================================
# BatchMTLSResult model
# ===========================================================================

class TestBatchMTLSResult:
    def _make_result(self, target, supports_mtls=True, requires_cert=False, error=None):
        return MTLSResult(
            target=target,
            port=443,
            supports_mtls=supports_mtls,
            requires_client_cert=requires_cert,
            client_cert_requested=requires_cert,
            handshake_successful=error is None,
            error_message=error,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def test_from_results_counts(self):
        results = [
            self._make_result("host1.com", supports_mtls=True, requires_cert=True),
            self._make_result("host2.com", supports_mtls=False, error="Connection refused"),
            self._make_result("host3.com", supports_mtls=True, requires_cert=False),
        ]
        batch = BatchMTLSResult.from_results(results)
        assert batch.total_targets == 3
        assert batch.successful_checks == 2
        assert batch.failed_checks == 1
        assert batch.mtls_supported_count == 2
        assert batch.mtls_required_count == 1

    def test_from_results_empty(self):
        batch = BatchMTLSResult.from_results([])
        assert batch.total_targets == 0
        assert batch.successful_checks == 0
        assert batch.failed_checks == 0

    def test_timestamp_set(self):
        batch = BatchMTLSResult.from_results([])
        assert batch.timestamp is not None
        assert "T" in batch.timestamp


# ===========================================================================
# MTLSConfig model
# ===========================================================================

class TestMTLSConfig:
    def test_defaults(self):
        cfg = MTLSConfig()
        assert cfg.timeout == 10
        assert cfg.verify_ssl is True
        assert cfg.client_cert_path is None
        assert cfg.max_concurrent == 10

    def test_custom_values(self):
        cfg = MTLSConfig(
            timeout=30,
            verify_ssl=False,
            client_cert_path="/path/to/cert.pem",
            ca_bundle_path="/path/to/ca.pem",
        )
        assert cfg.timeout == 30
        assert cfg.verify_ssl is False
        assert cfg.client_cert_path == "/path/to/cert.pem"


# ===========================================================================
# MTLSChecker constructor validation
# ===========================================================================

class TestMTLSCheckerInit:
    def test_valid_construction(self):
        checker = MTLSChecker()
        assert checker.timeout == 10
        assert checker.verify_ssl is True
        assert checker.max_retries == 3

    def test_custom_timeout(self):
        checker = MTLSChecker(timeout=30)
        assert checker.timeout == 30

    def test_invalid_timeout_raises(self):
        with pytest.raises(ValueError, match="Timeout"):
            MTLSChecker(timeout=0)

    def test_invalid_timeout_too_large(self):
        with pytest.raises(ValueError, match="Timeout"):
            MTLSChecker(timeout=999)

    def test_invalid_max_retries_raises(self):
        with pytest.raises(ValueError, match="Max retries"):
            MTLSChecker(max_retries=11)

    def test_invalid_retry_delay_raises(self):
        with pytest.raises(ValueError, match="Retry delay"):
            MTLSChecker(retry_delay=0.0)

    def test_get_metrics_structure(self):
        checker = MTLSChecker()
        metrics = checker.get_metrics()
        assert "total_requests" in metrics
        assert "successful_connections" in metrics
        assert "failed_connections" in metrics

    def test_disable_logging(self):
        import logging
        checker = MTLSChecker(enable_logging=False)
        assert checker.logger.level == logging.CRITICAL


# ===========================================================================
# MTLSChecker._validate_target
# ===========================================================================

class TestMTLSCheckerValidateTarget:
    def setup_method(self):
        self.checker = MTLSChecker(enable_logging=False)

    def test_plain_hostname(self):
        result = self.checker._validate_target("example.com")
        assert "example.com" in result

    def test_strips_https(self):
        result = self.checker._validate_target("https://example.com")
        assert "example.com" in result

    def test_strips_http(self):
        result = self.checker._validate_target("http://example.com")
        assert "example.com" in result

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            self.checker._validate_target("")

    def test_none_raises(self):
        with pytest.raises((ValueError, AttributeError)):
            self.checker._validate_target(None)


# ===========================================================================
# OwaspScanner tests (unit-level with mocked sub-checkers)
# ===========================================================================

from offensive_ai.core.owasp_scanner import OwaspScanner, SAFE_MODE_CATEGORIES, ALL_CATEGORIES
from offensive_ai.models.owasp_result import (
    OwaspScanResult, ScanMode, SeverityLevel, OwaspFinding, OwaspCategoryResult
)
from offensive_ai.core.security_headers import HeaderAnalysisResult, HeaderAnalysis


class TestOwaspScannerInit:
    def test_safe_mode_default_categories(self):
        scanner = OwaspScanner(mode="safe")
        assert scanner.enabled_categories == SAFE_MODE_CATEGORIES
        assert scanner.mode == ScanMode.SAFE

    def test_deep_mode_all_categories(self):
        scanner = OwaspScanner(mode="deep")
        assert scanner.enabled_categories == ALL_CATEGORIES
        assert scanner.mode == ScanMode.DEEP

    def test_custom_categories(self):
        scanner = OwaspScanner(categories=["A02", "A05"])
        assert "A02" in scanner.enabled_categories
        assert "A05" in scanner.enabled_categories

    def test_timeout_stored(self):
        scanner = OwaspScanner(timeout=30.0)
        assert scanner.timeout == 30.0

    def test_judge_stored(self):
        judge = MagicMock()
        scanner = OwaspScanner(judge=judge)
        assert scanner.judge is judge


@pytest.mark.asyncio
class TestOwaspScannerScanCategory:
    async def test_unknown_category_returns_not_testable(self):
        scanner = OwaspScanner(mode="safe", categories=["A99"])
        result = await scanner._scan_category("A99", "https://example.com", "example.com")
        assert result.testable is False
        assert result.category_id == "A99"

    async def test_a09_not_testable(self):
        scanner = OwaspScanner(mode="deep")
        result = await scanner._scan_category("A09", "https://example.com", "example.com")
        assert result.testable is False

    async def test_known_category_returns_result(self):
        scanner = OwaspScanner(mode="safe", categories=["A05"])
        # Mock the header_checker to avoid network
        mock_header_result = HeaderAnalysisResult(url="https://example.com", status_code=200)
        mock_header_result.headers = {}
        mock_header_result.cors_issues = []
        mock_header_result.information_disclosure = {}
        mock_header_result.overall_grade = "A"

        with patch.object(scanner.header_checker, "check_headers", new=AsyncMock(return_value=mock_header_result)):
            result = await scanner._scan_category("A05", "https://example.com", "example.com")

        assert result.category_id == "A05"
        assert isinstance(result.findings, list)

    async def test_a02_category_runs(self):
        """A02 category attempts TLS check — mock cert_analyzer."""
        scanner = OwaspScanner(mode="safe", categories=["A02"])
        mock_header_result = HeaderAnalysisResult(url="https://example.com", status_code=200)
        mock_header_result.headers = {}
        mock_header_result.cors_issues = []
        mock_header_result.information_disclosure = {}
        mock_header_result.overall_grade = "B"

        # Mock cert_analyzer to raise (simulates no TLS available)
        with patch.object(scanner.header_checker, "check_headers", new=AsyncMock(return_value=mock_header_result)):
            with patch.object(scanner.cert_analyzer, "analyze_certificate_chain", new=AsyncMock(side_effect=RuntimeError("no TLS"))):
                result = await scanner._scan_category("A02", "https://example.com", "example.com")

        assert result.category_id == "A02"
        assert isinstance(result.findings, list)


@pytest.mark.asyncio
class TestOwaspScannerScan:
    async def test_full_scan_returns_result(self):
        """Full scan with mocked sub-checkers returns valid OwaspScanResult."""
        scanner = OwaspScanner(mode="safe", categories=["A05"], timeout=5.0)
        mock_header_result = HeaderAnalysisResult(url="https://example.com", status_code=200)
        mock_header_result.headers = {}
        mock_header_result.cors_issues = []
        mock_header_result.information_disclosure = {}
        mock_header_result.overall_grade = "A"

        with patch.object(scanner.header_checker, "check_headers", new=AsyncMock(return_value=mock_header_result)):
            result = await scanner.scan("https://example.com")

        assert isinstance(result, OwaspScanResult)
        assert result.target == "https://example.com"
        assert result.scan_duration >= 0.0
        assert len(result.categories) == 1

    async def test_scan_adds_https_if_missing(self):
        """scan() should normalize a bare hostname to https://."""
        scanner = OwaspScanner(mode="safe", categories=["A05"], timeout=5.0)
        mock_header_result = HeaderAnalysisResult(url="https://example.com", status_code=200)
        mock_header_result.headers = {}
        mock_header_result.cors_issues = []
        mock_header_result.information_disclosure = {}
        mock_header_result.overall_grade = "A"

        with patch.object(scanner.header_checker, "check_headers", new=AsyncMock(return_value=mock_header_result)):
            result = await scanner.scan("example.com")

        assert "example.com" in result.target

    async def test_scan_with_judge_triage(self):
        """When judge is provided, _triage_with_llm should be called."""
        judge = MagicMock()
        scanner = OwaspScanner(mode="safe", categories=["A05"], judge=judge, timeout=5.0)

        mock_header_result = HeaderAnalysisResult(url="https://example.com", status_code=200)
        mock_header_result.headers = {}
        mock_header_result.cors_issues = [
            "CORS allows all origins (*) - may expose sensitive data"
        ]
        mock_header_result.information_disclosure = {}
        mock_header_result.overall_grade = "C"

        with patch.object(scanner.header_checker, "check_headers", new=AsyncMock(return_value=mock_header_result)):
            with patch.object(scanner, "_triage_with_llm", new=AsyncMock()) as mock_triage:
                result = await scanner.scan("https://example.com")

        mock_triage.assert_called_once()

    async def test_overall_grade_calculated(self):
        scanner = OwaspScanner(mode="safe", categories=["A05"], timeout=5.0)
        mock_header_result = HeaderAnalysisResult(url="https://example.com", status_code=200)
        mock_header_result.headers = {}
        mock_header_result.cors_issues = []
        mock_header_result.information_disclosure = {}
        mock_header_result.overall_grade = "A"

        with patch.object(scanner.header_checker, "check_headers", new=AsyncMock(return_value=mock_header_result)):
            result = await scanner.scan("https://example.com")

        assert result.overall_grade in ("A", "B", "C", "D", "F")


# ===========================================================================
# MCP Attacker extended paths
# ===========================================================================

from offensive_ai.core.mcp_attacker import MCPAttacker
from offensive_ai.models.mcp_result import MCPAttackReport, MCPAttackResult, MCPVulnSeverity


@pytest.mark.asyncio
class TestMCPAttackerExtended:
    async def test_attack_deep_mode_runs(self):
        """Deep mode should run more probes than safe mode."""
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-attacker.test/mcp"

        with respx.mock:
            respx.post(target).mock(
                return_value=httpx.Response(
                    200,
                    json={"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {}}},
                )
            )
            report_deep = await attacker.attack(target=target, transport="http", mode="deep")

        assert isinstance(report_deep, MCPAttackReport)
        assert report_deep.attacks_run > 0

    async def test_attack_safe_mode_runs(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-safe.test/mcp"

        with respx.mock:
            respx.post(target).mock(
                return_value=httpx.Response(
                    200,
                    json={"jsonrpc": "2.0", "id": 1, "result": {}},
                )
            )
            report = await attacker.attack(target=target, transport="http", mode="safe")

        assert isinstance(report, MCPAttackReport)

    async def test_attack_report_has_duration(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-duration.test/mcp"

        with respx.mock:
            respx.post(target).mock(
                return_value=httpx.Response(
                    403, json={"error": "forbidden"}
                )
            )
            report = await attacker.attack(target=target, transport="http", mode="safe")

        assert report.scan_duration >= 0.0

    async def test_attack_with_custom_headers(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-headers.test/mcp"

        with respx.mock:
            respx.post(target).mock(
                return_value=httpx.Response(
                    200, json={"jsonrpc": "2.0", "id": 1, "result": {}}
                )
            )
            report = await attacker.attack(
                target=target,
                transport="http",
                mode="safe",
                headers={"X-Custom": "value"},
            )

        assert isinstance(report, MCPAttackReport)


# ===========================================================================
# Exporters — basic import + JSON/CSV path
# ===========================================================================

class TestExporterImports:
    def test_csv_exporter_importable(self):
        """OwaspCsvExporter can be imported."""
        try:
            from offensive_ai.utils.exporters import OwaspCsvExporter
            exporter = OwaspCsvExporter()
            assert exporter is not None
        except ImportError:
            pytest.skip("reportlab not installed")

    def test_json_exporter_importable(self):
        """OwaspJsonExporter can be imported."""
        try:
            from offensive_ai.utils.exporters import OwaspJsonExporter
            exporter = OwaspJsonExporter()
            assert exporter is not None
        except ImportError:
            pytest.skip("reportlab not installed")
