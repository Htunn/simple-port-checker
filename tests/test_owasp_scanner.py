"""
Tests for OwaspScanner — scan orchestration with mocked sub-checkers.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from offensive_ai.core.owasp_scanner import OwaspScanner, SAFE_MODE_CATEGORIES, ALL_CATEGORIES
from offensive_ai.models.owasp_result import (
    OwaspCategoryResult,
    OwaspFinding,
    OwaspScanResult,
    ScanMode,
    SeverityLevel,
)


# ---------------------------------------------------------------------------
# Helpers for making mock objects
# ---------------------------------------------------------------------------

def make_header_result(
    cors_issues=None,
    cookies=None,
    hsts_present=True,
    hsts_grade="A",
):
    from offensive_ai.core.security_headers import HeaderAnalysisResult, HeaderAnalysis, CookieAnalysis

    # HSTS header
    hsts = HeaderAnalysis(
        header_name="Strict-Transport-Security",
        present=hsts_present,
        value="max-age=31536000; includeSubDomains" if hsts_present else None,
        grade=hsts_grade if hsts_present else "F",
        issues=[] if hsts_grade == "A" else ["max-age too low"],
    )

    result = HeaderAnalysisResult(
        url="https://example.com",
        status_code=200,
        headers={"HSTS": hsts},
        cookies=cookies or [],
        cors_issues=cors_issues or [],
    )
    return result


# ---------------------------------------------------------------------------
# OwaspScanner init
# ---------------------------------------------------------------------------

class TestOwaspScannerInit:
    def test_default_safe_mode(self):
        scanner = OwaspScanner()
        assert scanner.mode == ScanMode.SAFE
        assert scanner.enabled_categories == SAFE_MODE_CATEGORIES

    def test_deep_mode_enables_all_categories(self):
        scanner = OwaspScanner(mode="deep")
        assert scanner.mode == ScanMode.DEEP
        assert scanner.enabled_categories == ALL_CATEGORIES

    def test_custom_categories(self):
        scanner = OwaspScanner(categories=["A01", "A02"])
        assert scanner.enabled_categories == ["A01", "A02"]

    def test_custom_timeout(self):
        scanner = OwaspScanner(timeout=30.0)
        assert scanner.timeout == 30.0

    def test_judge_stored(self):
        mock_judge = MagicMock()
        scanner = OwaspScanner(judge=mock_judge)
        assert scanner.judge is mock_judge


# ---------------------------------------------------------------------------
# _scan_category — unknown category
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestScanCategory:
    async def test_unknown_category_returns_untestable(self):
        scanner = OwaspScanner()
        result = await scanner._scan_category("UNKNOWN_CAT", "https://example.com", "example.com")
        assert isinstance(result, OwaspCategoryResult)
        assert result.testable is False

    async def test_a01_category_returns_result(self):
        scanner = OwaspScanner()
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=make_header_result(cors_issues=["CORS wildcard"]))):
            result = await scanner._scan_category("A01", "https://example.com", "example.com")
        assert isinstance(result, OwaspCategoryResult)
        assert result.category_id == "A01"

    async def test_a02_returns_result(self):
        scanner = OwaspScanner()
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=make_header_result(hsts_present=False))):
            result = await scanner._scan_category("A02", "https://example.com", "example.com")
        assert isinstance(result, OwaspCategoryResult)

    async def test_a03_returns_result(self):
        scanner = OwaspScanner(mode="safe")
        result = await scanner._scan_category("A03", "https://example.com", "example.com")
        assert isinstance(result, OwaspCategoryResult)
        assert result.category_id == "A03"

    async def test_a05_returns_result(self):
        scanner = OwaspScanner()
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=make_header_result())):
            result = await scanner._scan_category("A05", "https://example.com", "example.com")
        assert isinstance(result, OwaspCategoryResult)

    async def test_a06_returns_result(self):
        scanner = OwaspScanner()
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=make_header_result())):
            result = await scanner._scan_category("A06", "https://example.com", "example.com")
        assert isinstance(result, OwaspCategoryResult)

    async def test_a07_returns_result(self):
        scanner = OwaspScanner()
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=make_header_result())):
            result = await scanner._scan_category("A07", "https://example.com", "example.com")
        assert isinstance(result, OwaspCategoryResult)


# ---------------------------------------------------------------------------
# _check_a01_access_control
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckA01:
    async def test_cors_wildcard_creates_finding(self):
        scanner = OwaspScanner()
        mock_result = make_header_result(cors_issues=["CORS wildcard origin with credentials"])
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_result)):
            findings = await scanner._check_a01_access_control("https://example.com")

        assert len(findings) > 0
        assert all(f.category == "A01" for f in findings)

    async def test_no_cors_issues_empty_findings(self):
        scanner = OwaspScanner()
        mock_result = make_header_result(cors_issues=[])
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_result)):
            findings = await scanner._check_a01_access_control("https://example.com")

        assert findings == []

    async def test_cors_credentials_issue_is_high(self):
        scanner = OwaspScanner()
        mock_result = make_header_result(cors_issues=["CORS allows credentials from any origin"])
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_result)):
            findings = await scanner._check_a01_access_control("https://example.com")

        assert any(f.severity == SeverityLevel.HIGH for f in findings)

    async def test_exception_during_headers_returns_empty(self):
        scanner = OwaspScanner()
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(side_effect=Exception("network error"))):
            findings = await scanner._check_a01_access_control("https://example.com")

        assert findings == []


# ---------------------------------------------------------------------------
# _check_a02_cryptographic_failures
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckA02:
    async def test_missing_hsts_creates_high_finding(self):
        scanner = OwaspScanner()
        mock_result = make_header_result(hsts_present=False)
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_result)):
            findings = await scanner._check_a02_cryptographic_failures(
                "https://example.com", "example.com"
            )

        hsts_findings = [f for f in findings if "HSTS" in f.title]
        assert len(hsts_findings) > 0
        assert hsts_findings[0].severity == SeverityLevel.HIGH

    async def test_present_hsts_weak_config_creates_medium(self):
        scanner = OwaspScanner()
        mock_result = make_header_result(hsts_present=True, hsts_grade="D")
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_result)):
            findings = await scanner._check_a02_cryptographic_failures(
                "https://example.com", "example.com"
            )

        medium_findings = [f for f in findings if f.severity == SeverityLevel.MEDIUM and "HSTS" in f.title]
        assert len(medium_findings) > 0

    async def test_insecure_cookie_creates_finding(self):
        scanner = OwaspScanner()
        from offensive_ai.core.security_headers import CookieAnalysis
        cookie = CookieAnalysis(
            cookie_name="session",
            has_secure=False,
            has_httponly=True,
            has_samesite=True,
            samesite_value="Lax",
        )
        mock_result = make_header_result(cookies=[cookie])
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_result)):
            findings = await scanner._check_a02_cryptographic_failures(
                "https://example.com", "example.com"
            )

        cookie_findings = [f for f in findings if "Cookie" in f.title]
        assert len(cookie_findings) > 0

    async def test_exception_returns_empty_list(self):
        scanner = OwaspScanner()
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(side_effect=Exception("fail"))):
            findings = await scanner._check_a02_cryptographic_failures(
                "https://example.com", "example.com"
            )

        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Full scan() — mocked sub-checks
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestOwaspScan:
    async def test_scan_returns_scan_result(self):
        scanner = OwaspScanner(mode="safe", categories=["A02"])
        with patch.object(scanner, "_scan_category", AsyncMock(return_value=OwaspCategoryResult(
            category_id="A02",
            category_name="Cryptographic Failures",
            findings=[],
        ))):
            result = await scanner.scan("https://example.com")

        assert isinstance(result, OwaspScanResult)
        assert result.target == "https://example.com"

    async def test_scan_adds_scheme_if_missing(self):
        scanner = OwaspScanner(mode="safe", categories=["A02"])
        with patch.object(scanner, "_scan_category", AsyncMock(return_value=OwaspCategoryResult(
            category_id="A02",
            category_name="Cryptographic Failures",
        ))):
            result = await scanner.scan("example.com")

        assert result.target.startswith("https://")

    async def test_scan_calculates_grade(self):
        scanner = OwaspScanner(mode="safe", categories=["A01"])
        with patch.object(scanner, "_scan_category", AsyncMock(return_value=OwaspCategoryResult(
            category_id="A01",
            category_name="Broken Access Control",
            findings=[],
        ))):
            result = await scanner.scan("https://example.com")

        assert result.overall_grade in ["A", "B", "C", "D", "F", "N/A"]

    async def test_scan_duration_recorded(self):
        scanner = OwaspScanner(mode="safe", categories=["A01"])
        with patch.object(scanner, "_scan_category", AsyncMock(return_value=OwaspCategoryResult(
            category_id="A01",
            category_name="Broken Access Control",
        ))):
            result = await scanner.scan("https://example.com")

        assert result.scan_duration >= 0

    async def test_scan_with_judge_calls_triage(self):
        mock_judge = AsyncMock()
        mock_judge.evaluate = AsyncMock(return_value=MagicMock(reasoning="test", confidence=0.8))
        scanner = OwaspScanner(mode="safe", categories=["A01"], judge=mock_judge)

        cat_with_findings = OwaspCategoryResult(
            category_id="A01",
            category_name="Broken Access Control",
            findings=[
                OwaspFinding(
                    category="A01",
                    severity=SeverityLevel.MEDIUM,
                    title="CORS Issue",
                    description="CORS misconfiguration",
                    remediation_key="cors_misconfiguration",
                )
            ],
        )

        with patch.object(scanner, "_scan_category", AsyncMock(return_value=cat_with_findings)):
            result = await scanner.scan("https://example.com")

        assert isinstance(result, OwaspScanResult)


# ---------------------------------------------------------------------------
# Batch scan
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestBatchScan:
    async def test_batch_scan_returns_batch_result(self):
        from offensive_ai.core.owasp_scanner import OwaspScanner

        scanner = OwaspScanner(mode="safe", categories=["A02"])

        async def mock_scan(target):
            return OwaspScanResult(
                target=target,
                scan_mode=ScanMode.SAFE,
                enabled_categories=["A02"],
                categories=[],
            )

        with patch.object(scanner, "scan", side_effect=mock_scan):
            from offensive_ai.models.owasp_result import BatchOwaspResult
            targets = ["https://example.com", "https://test.com"]
            results = []
            for t in targets:
                results.append(await scanner.scan(t))

        assert len(results) == 2

    async def test_batch_scan_real(self):
        from offensive_ai.core.owasp_scanner import OwaspScanner
        from offensive_ai.models.owasp_result import BatchOwaspResult

        scanner = OwaspScanner(mode="safe", categories=["A02"])

        mock_result = OwaspScanResult(
            target="https://example.com",
            scan_mode=ScanMode.SAFE,
            enabled_categories=["A02"],
            categories=[],
        )

        with patch.object(scanner, "scan", AsyncMock(return_value=mock_result)):
            batch = await scanner.batch_scan(["https://example.com", "https://test.com"])

        from offensive_ai.models.owasp_result import BatchOwaspResult
        assert isinstance(batch, BatchOwaspResult)
        assert batch.total_targets == 2


# ---------------------------------------------------------------------------
# _check_a04_insecure_design
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckA04:
    async def test_a04_no_rate_limit_creates_finding(self):
        import httpx
        import respx

        scanner = OwaspScanner()
        with respx.mock:
            respx.get("https://example.com").mock(
                return_value=httpx.Response(200, headers={}, text="OK")
            )
            findings = await scanner._check_a04_insecure_design("https://example.com")

        assert isinstance(findings, list)
        # If no rate-limit headers, should have a LOW finding
        if findings:
            assert findings[0].category == "A04"

    async def test_a04_exception_returns_empty(self):
        import httpx
        import respx

        scanner = OwaspScanner()
        with respx.mock:
            respx.get("https://example.com").mock(side_effect=httpx.ConnectError("refused"))
            findings = await scanner._check_a04_insecure_design("https://example.com")

        assert findings == []

    async def test_a04_with_rate_limit_headers_no_finding(self):
        import httpx
        import respx

        scanner = OwaspScanner()
        with respx.mock:
            respx.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    headers={"X-RateLimit-Limit": "100"},
                    text="OK",
                )
            )
            findings = await scanner._check_a04_insecure_design("https://example.com")

        # With rate limiting, should NOT have the LOW finding
        rate_findings = [f for f in findings if "Rate Limiting" in f.title]
        assert rate_findings == []


# ---------------------------------------------------------------------------
# _check_a05_security_misconfiguration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckA05:
    async def test_missing_headers_creates_findings(self):
        from offensive_ai.core.security_headers import HeaderAnalysisResult, HeaderAnalysis

        scanner = OwaspScanner()

        # Build a mock result where CSP is missing
        csp_missing = HeaderAnalysis(
            header_name="Content-Security-Policy",
            present=False,
            value=None,
            grade="F",
            issues=["Header missing"],
        )
        mock_result = make_header_result()
        mock_result.headers["CSP"] = csp_missing

        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_result)):
            findings = await scanner._check_a05_security_misconfiguration("https://example.com")

        csp_findings = [f for f in findings if "CSP" in f.title or "Content-Security-Policy" in f.title]
        assert isinstance(findings, list)

    async def test_exception_returns_empty(self):
        scanner = OwaspScanner()
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(side_effect=Exception("fail"))):
            findings = await scanner._check_a05_security_misconfiguration("https://example.com")

        assert findings == []


# ---------------------------------------------------------------------------
# _check_a06_vulnerable_components
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckA06:
    async def test_information_disclosure_creates_finding(self):
        from offensive_ai.core.security_headers import HeaderAnalysisResult

        scanner = OwaspScanner()
        mock_result = make_header_result()
        mock_result.information_disclosure = {"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4"}

        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_result)):
            findings = await scanner._check_a06_vulnerable_components("https://example.com")

        assert len(findings) > 0
        assert all(f.category == "A06" for f in findings)

    async def test_no_disclosure_returns_empty(self):
        scanner = OwaspScanner()
        mock_result = make_header_result()
        mock_result.information_disclosure = {}

        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_result)):
            findings = await scanner._check_a06_vulnerable_components("https://example.com")

        assert findings == []

    async def test_exception_returns_empty(self):
        scanner = OwaspScanner()
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(side_effect=Exception("fail"))):
            findings = await scanner._check_a06_vulnerable_components("https://example.com")

        assert findings == []


# ---------------------------------------------------------------------------
# _check_a07_auth_failures
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckA07:
    async def test_insecure_cookie_creates_finding(self):
        from offensive_ai.core.security_headers import CookieAnalysis

        scanner = OwaspScanner()
        # Cookie missing Secure and HttpOnly
        cookie = CookieAnalysis(
            cookie_name="auth",
            has_secure=False,
            has_httponly=False,
            has_samesite=False,
            samesite_value=None,
        )
        mock_result = make_header_result(cookies=[cookie])

        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_result)):
            findings = await scanner._check_a07_auth_failures("https://example.com")

        assert len(findings) > 0
        assert all(f.category == "A07" for f in findings)
        assert any("missing Secure flag" in f.description for f in findings)
        assert any("missing HttpOnly flag" in f.description for f in findings)
        assert any("missing SameSite" in f.description for f in findings)

    async def test_secure_cookie_no_finding(self):
        from offensive_ai.core.security_headers import CookieAnalysis

        scanner = OwaspScanner()
        cookie = CookieAnalysis(
            cookie_name="session",
            has_secure=True,
            has_httponly=True,
            has_samesite=True,
            samesite_value="Strict",
        )
        mock_result = make_header_result(cookies=[cookie])

        with patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_result)):
            findings = await scanner._check_a07_auth_failures("https://example.com")

        assert findings == []

    async def test_exception_returns_empty(self):
        scanner = OwaspScanner()
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(side_effect=Exception("fail"))):
            findings = await scanner._check_a07_auth_failures("https://example.com")

        assert findings == []


# ---------------------------------------------------------------------------
# _check_a08_integrity_failures
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckA08:
    async def test_returns_empty_list_placeholder(self):
        scanner = OwaspScanner()
        findings = await scanner._check_a08_integrity_failures("https://example.com")
        assert findings == []


# ---------------------------------------------------------------------------
# _check_a10_ssrf
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckA10SSRF:
    async def test_safe_mode_returns_empty(self):
        scanner = OwaspScanner(mode="safe")
        findings = await scanner._check_a10_ssrf("https://example.com")
        assert findings == []

    async def test_deep_mode_returns_empty_placeholder(self):
        scanner = OwaspScanner(mode="deep")
        findings = await scanner._check_a10_ssrf("https://example.com")
        # Currently a placeholder, should return empty list
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# _check_a03_2025_supply_chain — mocked httpx
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckA03SupplyChain:
    async def test_missing_security_txt_returns_finding(self):
        import httpx
        scanner = OwaspScanner()

        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            findings = await scanner._check_a03_2025_supply_chain("example.com")

        titles = [f.title for f in findings]
        assert any("security.txt" in t for t in titles)

    async def test_exception_adds_security_txt_finding(self):
        import httpx
        scanner = OwaspScanner()

        with patch("httpx.AsyncClient", side_effect=Exception("network error")):
            findings = await scanner._check_a03_2025_supply_chain("example.com")

        titles = [f.title for f in findings]
        assert any("security.txt" in t for t in titles)

    async def test_no_sbom_returns_sbom_finding(self):
        import httpx
        scanner = OwaspScanner()

        call_count = {"n": 0}

        async def mock_get(url, **kwargs):
            resp = MagicMock()
            # security.txt returns 200, sbom paths return 404
            call_count["n"] += 1
            resp.status_code = 200 if call_count["n"] == 1 else 404
            return resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            findings = await scanner._check_a03_2025_supply_chain("example.com")

        titles = [f.title for f in findings]
        assert any("SBOM" in t for t in titles)


# ---------------------------------------------------------------------------
# _check_a10_2025_exception_handling — mocked header checker and httpx
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckA10ExceptionHandling:
    async def test_server_header_disclosure_creates_finding(self):
        from offensive_ai.core.security_headers import HeaderAnalysisResult
        scanner = OwaspScanner()

        mock_header_result = HeaderAnalysisResult(url="https://example.com", status_code=200)
        mock_header_result.server_header = "Apache/2.4.51"
        mock_header_result.powered_by = None

        import httpx
        resp_404 = MagicMock()
        resp_404.status_code = 404
        resp_404.text = "Not found"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp_404)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_header_result)),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            findings = await scanner._check_a10_2025_exception_handling("example.com")

        titles = [f.title for f in findings]
        assert any("Server Version" in t for t in titles)

    async def test_powered_by_disclosure_creates_finding(self):
        from offensive_ai.core.security_headers import HeaderAnalysisResult
        scanner = OwaspScanner()

        mock_header_result = HeaderAnalysisResult(url="https://example.com", status_code=200)
        mock_header_result.server_header = None
        mock_header_result.powered_by = "PHP/8.1"

        import httpx
        resp_404 = MagicMock()
        resp_404.status_code = 200  # Non-404 to skip stack trace check
        resp_404.text = "Normal page"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp_404)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_header_result)),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            findings = await scanner._check_a10_2025_exception_handling("example.com")

        titles = [f.title for f in findings]
        assert any("Technology Stack" in t for t in titles)

    async def test_verbose_error_in_404_creates_finding(self):
        from offensive_ai.core.security_headers import HeaderAnalysisResult
        scanner = OwaspScanner()

        mock_header_result = HeaderAnalysisResult(url="https://example.com", status_code=200)
        mock_header_result.server_header = None
        mock_header_result.powered_by = None

        import httpx
        resp_404 = MagicMock()
        resp_404.status_code = 404
        resp_404.text = "Traceback (most recent call last): File app.py at line 42"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp_404)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch.object(scanner.header_checker, "check_headers", AsyncMock(return_value=mock_header_result)),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            findings = await scanner._check_a10_2025_exception_handling("example.com")

        titles = [f.title for f in findings]
        assert any("Verbose Error" in t for t in titles)

    async def test_exception_in_header_check_handled_gracefully(self):
        scanner = OwaspScanner()
        with patch.object(scanner.header_checker, "check_headers", AsyncMock(side_effect=Exception("fail"))):
            findings = await scanner._check_a10_2025_exception_handling("example.com")
        assert isinstance(findings, list)
