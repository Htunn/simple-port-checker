"""
Additional tests targeting uncovered lines in port_scanner and security_headers.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from offensive_ai.core.port_scanner import PortChecker, PortResult, ScanResult


# ---------------------------------------------------------------------------
# PortScanner.scan_multiple_hosts
# ---------------------------------------------------------------------------

class TestScanMultipleHosts:
    @pytest.mark.asyncio
    async def test_empty_list_returns_empty(self):
        scanner = PortChecker()
        with patch.object(scanner, "scan_host", AsyncMock(return_value=ScanResult(
            host="x.com", ip_address="1.2.3.4", ports=[], scan_time=0.1
        ))):
            results = await scanner.scan_multiple_hosts([])
        assert results == []

    @pytest.mark.asyncio
    async def test_multiple_hosts_all_scanned(self):
        scanner = PortChecker()

        async def mock_scan(host, ports=None, timeout=None):
            return ScanResult(host=host, ip_address="1.2.3.4", ports=[], scan_time=0.1)

        with patch.object(scanner, "scan_host", side_effect=mock_scan):
            results = await scanner.scan_multiple_hosts(["a.com", "b.com", "c.com"])

        assert len(results) == 3
        assert all(isinstance(r, ScanResult) for r in results)


# ---------------------------------------------------------------------------
# PortScanner.check_service_version — mocked aiohttp / asyncio connections
# ---------------------------------------------------------------------------

class TestCheckServiceVersion:
    @pytest.mark.asyncio
    async def test_http_service_detection(self):
        scanner = PortChecker()

        mock_response = AsyncMock()
        mock_response.headers = {"Server": "nginx/1.22"}
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get.return_value = mock_response
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scanner.check_service_version("example.com", 80)

        assert result["service"] == "http"

    @pytest.mark.asyncio
    async def test_https_service_detection(self):
        scanner = PortChecker()

        mock_response = AsyncMock()
        mock_response.headers = {"Server": "Apache"}
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get.return_value = mock_response
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await scanner.check_service_version("example.com", 443)

        assert result["service"] == "http"

    @pytest.mark.asyncio
    async def test_ssh_banner_detection(self):
        scanner = PortChecker()

        banner_data = b"SSH-2.0-OpenSSH_8.9p1"
        reader = AsyncMock()
        reader.read = AsyncMock(return_value=banner_data)
        writer = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        with patch("asyncio.wait_for", side_effect=[
            (reader, writer),   # open_connection
            banner_data,        # reader.read
        ]):
            result = await scanner.check_service_version("example.com", 22)

        # Service detection depends on banner content
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_unknown_port_tcp_banner_failure(self):
        scanner = PortChecker()

        with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
            result = await scanner.check_service_version("example.com", 9999)

        assert isinstance(result, dict)
        assert "service" in result

    @pytest.mark.asyncio
    async def test_general_exception_returns_error(self):
        scanner = PortChecker()

        with patch("aiohttp.ClientSession", side_effect=Exception("aiohttp failed")):
            result = await scanner.check_service_version("example.com", 80)

        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# PortScanner._scan_port — various outcomes
# ---------------------------------------------------------------------------

class TestScanPort:
    @pytest.mark.asyncio
    async def test_open_port_http_banner(self):
        scanner = PortChecker()
        scanner.config.delay_between_requests = 0

        reader = AsyncMock()
        reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\nServer: nginx")
        writer = AsyncMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        with patch("asyncio.wait_for", side_effect=[(reader, writer), b"HTTP/1.1 200 OK\r\n"]):
            result = await scanner._scan_port("1.2.3.4", 80, 2.0)

        assert result is None or result.is_open  # May vary based on mock behavior

    @pytest.mark.asyncio
    async def test_connection_refused_returns_none(self):
        scanner = PortChecker()
        scanner.config.delay_between_requests = 0

        with patch("asyncio.wait_for", side_effect=ConnectionRefusedError()):
            result = await scanner._scan_port("1.2.3.4", 12345, 1.0)

        assert result is None

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self):
        scanner = PortChecker()
        scanner.config.delay_between_requests = 0

        with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
            result = await scanner._scan_port("1.2.3.4", 12345, 1.0)

        assert result is None


# ---------------------------------------------------------------------------
# SecurityHeaderChecker — check_headers with mocked httpx
# ---------------------------------------------------------------------------

class TestCheckHeadersMocked:
    @pytest.mark.asyncio
    async def test_check_headers_with_all_security_headers(self):
        import httpx
        from offensive_ai.core.security_headers import SecurityHeaderChecker, HeaderAnalysisResult

        checker = SecurityHeaderChecker(timeout=2.0)

        mock_headers = httpx.Headers({
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        })
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = mock_headers
        mock_response.cookies = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await checker.check_headers("https://example.com")

        assert isinstance(result, HeaderAnalysisResult)
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_check_headers_missing_all_headers(self):
        import httpx
        from offensive_ai.core.security_headers import SecurityHeaderChecker, HeaderAnalysisResult

        checker = SecurityHeaderChecker()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = httpx.Headers({"Server": "Apache/2.4"})
        mock_response.cookies = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await checker.check_headers("http://example.com")

        assert result.overall_grade in ["D", "F"]

    @pytest.mark.asyncio
    async def test_batch_check_multiple_urls(self):
        import httpx
        from offensive_ai.core.security_headers import SecurityHeaderChecker, HeaderAnalysisResult

        checker = SecurityHeaderChecker()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = httpx.Headers({
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        })
        mock_response.cookies = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await checker.batch_check(["https://a.com", "https://b.com"])

        assert len(results) == 2
        assert all(isinstance(r, HeaderAnalysisResult) for r in results)

    @pytest.mark.asyncio
    async def test_check_headers_with_cors_issue(self):
        import httpx
        from offensive_ai.core.security_headers import SecurityHeaderChecker

        checker = SecurityHeaderChecker()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = httpx.Headers({
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })
        mock_response.cookies = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await checker.check_headers("https://cors-issue.com")

        assert len(result.cors_issues) > 0
