"""Tests for port scanner functionality."""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, Mock

from simple_port_checker.core.port_scanner import PortChecker, ScanConfig
from simple_port_checker.models.scan_result import PortResult, ScanResult


class TestPortChecker:
    """Test cases for PortChecker class."""

    def test_scan_config_defaults(self):
        """Test ScanConfig default values."""
        config = ScanConfig()
        assert config.timeout == 3.0
        assert config.concurrent_limit == 100
        assert config.delay_between_requests == 0.01
        assert config.resolve_hostnames is True

    def test_port_checker_initialization(self):
        """Test PortChecker initialization."""
        checker = PortChecker()
        assert checker.config is not None
        assert checker.throttler is not None

        # Test with custom config
        config = ScanConfig(timeout=5.0, concurrent_limit=50)
        checker = PortChecker(config)
        assert checker.config.timeout == 5.0
        assert checker.config.concurrent_limit == 50

    @pytest.mark.asyncio
    async def test_scan_host_success(self):
        """Test successful host scanning."""
        checker = PortChecker()

        # Mock socket resolution
        with patch("socket.gethostbyname", return_value="93.184.216.34"):
            # Mock open_connection to simulate open port
            async def mock_open_connection(host, port):
                reader = AsyncMock()
                writer = AsyncMock()
                reader.read.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n"
                return reader, writer

            with patch("asyncio.open_connection", side_effect=mock_open_connection):
                result = await checker.scan_host("example.com", [80])

                assert isinstance(result, ScanResult)
                assert result.host == "example.com"
                assert result.ip_address == "93.184.216.34"
                assert len(result.ports) == 1
                assert result.ports[0].port == 80
                assert result.ports[0].is_open is True

    @pytest.mark.asyncio
    async def test_scan_host_dns_failure(self):
        """Test scanning with DNS resolution failure."""
        checker = PortChecker()

        # Mock socket resolution failure
        with patch(
            "socket.gethostbyname", side_effect=OSError("Name resolution failed")
        ):
            result = await checker.scan_host("nonexistent.example", [80])

            assert result.host == "nonexistent.example"
            assert result.ip_address is None
            assert result.error is not None
            assert "Failed to resolve hostname" in result.error

    @pytest.mark.asyncio
    async def test_scan_port_timeout(self):
        """Test port scanning with timeout."""
        checker = PortChecker()

        # Mock timeout
        with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError()):
            result = await checker._scan_port("127.0.0.1", 12345, 1.0)
            assert result is None

    @pytest.mark.asyncio
    async def test_scan_port_connection_refused(self):
        """Test port scanning with connection refused."""
        checker = PortChecker()

        # Mock connection refused
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError()):
            result = await checker._scan_port("127.0.0.1", 12345, 1.0)
            assert result is None

    @pytest.mark.asyncio
    async def test_scan_multiple_hosts(self):
        """Test scanning multiple hosts."""
        checker = PortChecker()
        hosts = ["example.com", "google.com"]

        with patch.object(checker, "scan_host") as mock_scan:
            mock_scan.return_value = ScanResult(
                host="test", ip_address="1.2.3.4", ports=[], scan_time=1.0
            )

            results = await checker.scan_multiple_hosts(hosts, [80])

            assert len(results) == 2
            assert all(isinstance(r, ScanResult) for r in results)
            assert mock_scan.call_count == 2

    @pytest.mark.asyncio
    async def test_check_service_version_http(self):
        """Test HTTP service version detection."""
        checker = PortChecker()

        # Mock the entire HTTP detection method
        with patch.object(checker, "check_service_version") as mock_method:
            mock_method.return_value = {
                "service": "http",
                "version": "Apache/2.4.41",
                "banner": "Apache/2.4.41",
                "headers": {"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4.0"},
            }

            result = await checker.check_service_version("example.com", 80, "http")

            assert result["service"] == "http"
            assert "Apache/2.4.41" in result["version"]
            assert result["headers"]["Server"] == "Apache/2.4.41"

    @pytest.mark.asyncio
    async def test_check_service_version_tcp_banner(self):
        """Test TCP banner grabbing for non-HTTP services."""
        checker = PortChecker()

        # Mock TCP connection with SSH banner
        async def mock_open_connection(host, port):
            reader = AsyncMock()
            writer = AsyncMock()
            reader.read.return_value = b"SSH-2.0-OpenSSH_8.0\r\n"
            return reader, writer

        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            result = await checker.check_service_version("example.com", 22, "ssh")

            assert result["service"] == "ssh"
            assert "SSH-2.0-OpenSSH_8.0" in result["banner"]
            assert "SSH-2.0-OpenSSH_8.0" in result["version"]


class TestPortResult:
    """Test cases for PortResult model."""

    def test_port_result_creation(self):
        """Test PortResult creation and attributes."""
        result = PortResult(
            port=80,
            is_open=True,
            service="http",
            banner="HTTP/1.1 200 OK",
            response_time=0.5,
        )

        assert result.port == 80
        assert result.is_open is True
        assert result.service == "http"
        assert result.banner == "HTTP/1.1 200 OK"
        assert result.response_time == 0.5
        assert result.error is None

    def test_port_result_to_dict(self):
        """Test PortResult to_dict conversion."""
        result = PortResult(port=443, is_open=True, service="https")
        result_dict = result.to_dict()

        assert result_dict["port"] == 443
        assert result_dict["is_open"] is True
        assert result_dict["service"] == "https"
        assert "banner" in result_dict
        assert "error" in result_dict


class TestScanResult:
    """Test cases for ScanResult model."""

    def test_scan_result_creation(self):
        """Test ScanResult creation."""
        ports = [
            PortResult(port=80, is_open=True, service="http"),
            PortResult(port=443, is_open=True, service="https"),
            PortResult(port=22, is_open=False, service="ssh"),
        ]

        result = ScanResult(
            host="example.com", ip_address="93.184.216.34", ports=ports, scan_time=2.5
        )

        assert result.host == "example.com"
        assert result.ip_address == "93.184.216.34"
        assert len(result.ports) == 3
        assert result.scan_time == 2.5
        assert result.timestamp is not None

    def test_scan_result_properties(self):
        """Test ScanResult computed properties."""
        ports = [
            PortResult(port=80, is_open=True, service="http"),
            PortResult(port=443, is_open=True, service="https"),
            PortResult(port=22, is_open=False, service="ssh"),
            PortResult(
                port=21, is_open=False, service="ftp", error="Connection refused"
            ),
        ]

        result = ScanResult(
            host="example.com", ip_address="93.184.216.34", ports=ports, scan_time=2.5
        )

        assert len(result.open_ports) == 2
        assert len(result.closed_ports) == 1
        assert len(result.error_ports) == 1

        assert result.open_ports[0].port == 80
        assert result.open_ports[1].port == 443
        assert result.closed_ports[0].port == 22
        assert result.error_ports[0].port == 21

    def test_scan_result_to_dict(self):
        """Test ScanResult to_dict conversion."""
        ports = [PortResult(port=80, is_open=True, service="http")]
        result = ScanResult(
            host="example.com", ip_address="93.184.216.34", ports=ports, scan_time=1.0
        )

        result_dict = result.to_dict()

        assert result_dict["host"] == "example.com"
        assert result_dict["ip_address"] == "93.184.216.34"
        assert len(result_dict["ports"]) == 1
        assert result_dict["scan_time"] == 1.0
        assert "summary" in result_dict
        assert result_dict["summary"]["total_ports"] == 1
        assert result_dict["summary"]["open_ports"] == 1

    def test_scan_result_json_serialization(self):
        """Test ScanResult JSON serialization."""
        ports = [PortResult(port=80, is_open=True, service="http")]
        result = ScanResult(
            host="example.com", ip_address="93.184.216.34", ports=ports, scan_time=1.0
        )

        json_str = result.to_json()
        assert isinstance(json_str, str)
        assert "example.com" in json_str
        assert "93.184.216.34" in json_str
