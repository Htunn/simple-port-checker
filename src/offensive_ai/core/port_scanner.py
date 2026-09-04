"""
Port Scanner module for checking open ports on target hosts.

This module provides asynchronous port scanning capabilities with configurable
concurrency limits and timeout settings.
"""

import asyncio
import socket
import time
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

import aiohttp
from asyncio_throttle import Throttler

from ..models.scan_result import ScanResult, PortResult
from ..utils.common_ports import COMMON_PORTS, get_service_name


@dataclass
class ScanConfig:
    """Configuration for port scanning."""

    timeout: float = 3.0
    concurrent_limit: int = 100
    delay_between_requests: float = 0.01
    resolve_hostnames: bool = True


class PortChecker:
    """Asynchronous port scanner for checking open ports."""

    def __init__(self, config: Optional[ScanConfig] = None):
        """Initialize the port checker with optional configuration."""
        self.config = config or ScanConfig()
        self.throttler = Throttler(rate_limit=self.config.concurrent_limit)

    async def scan_host(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        timeout: Optional[float] = None,
    ) -> ScanResult:
        """
        Scan a single host for open ports.

        Args:
            host: Target hostname or IP address
            ports: List of ports to scan (defaults to common ports)
            timeout: Connection timeout in seconds

        Returns:
            ScanResult object containing scan results
        """
        if ports is None:
            ports = list(COMMON_PORTS.keys())

        scan_timeout = timeout or self.config.timeout
        start_time = time.time()

        # Resolve hostname to IP
        try:
            ip_address = socket.gethostbyname(host)
        except (socket.gaierror, OSError) as e:
            return ScanResult(
                host=host,
                ip_address=None,
                ports=[],
                scan_time=time.time() - start_time,
                error=f"Failed to resolve hostname: {host} - {str(e)}",
            )

        # Scan ports concurrently
        tasks = []
        async with asyncio.TaskGroup() as group:
            for port in ports:
                task = group.create_task(
                    self._scan_port(ip_address, port, scan_timeout)
                )
                tasks.append(task)

        # Collect results
        port_results = []
        for i, task in enumerate(tasks):
            try:
                result = task.result()
                if result:
                    port_results.append(result)
            except Exception as e:
                # Create a failed result for this port
                port_results.append(
                    PortResult(
                        port=ports[i],
                        is_open=False,
                        service=get_service_name(ports[i]),
                        banner="",
                        error=str(e),
                    )
                )

        return ScanResult(
            host=host,
            ip_address=ip_address,
            ports=port_results,
            scan_time=time.time() - start_time,
        )

    async def scan_multiple_hosts(
        self,
        hosts: List[str],
        ports: Optional[List[int]] = None,
        timeout: Optional[float] = None,
    ) -> List[ScanResult]:
        """
        Scan multiple hosts for open ports.

        Args:
            hosts: List of target hostnames or IP addresses
            ports: List of ports to scan
            timeout: Connection timeout in seconds

        Returns:
            List of ScanResult objects
        """
        tasks = []
        async with asyncio.TaskGroup() as group:
            for host in hosts:
                task = group.create_task(self.scan_host(host, ports, timeout))
                tasks.append(task)

        return [task.result() for task in tasks]

    async def _scan_port(
        self, ip: str, port: int, timeout: float
    ) -> Optional[PortResult]:
        """
        Scan a single port on a target IP.

        Args:
            ip: Target IP address
            port: Port number to scan
            timeout: Connection timeout

        Returns:
            PortResult if successful, None if failed
        """
        async with self.throttler:
            try:
                # Add small delay between requests
                await asyncio.sleep(self.config.delay_between_requests)

                # Attempt TCP connection
                future = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(future, timeout=timeout)

                # Try to grab banner
                banner = ""
                try:
                    # Send a basic HTTP request for web services
                    if port in [80, 8080, 8000, 8008]:
                        writer.write(
                            b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"
                        )
                        await writer.drain()
                    elif port == 443 or port == 8443:
                        # For HTTPS, just try to read initial data
                        pass
                    elif port == 22:
                        # SSH banner
                        pass
                    elif port == 21:
                        # FTP banner
                        pass

                    # Try to read banner (with short timeout)
                    try:
                        data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                        banner = data.decode("utf-8", errors="ignore").strip()
                    except (asyncio.TimeoutError, UnicodeDecodeError):
                        pass

                except Exception:
                    pass
                finally:
                    writer.close()
                    await writer.wait_closed()

                return PortResult(
                    port=port,
                    is_open=True,
                    service=get_service_name(port),
                    banner=banner[:200],  # Limit banner length
                )

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception as e:
                return PortResult(
                    port=port,
                    is_open=False,
                    service=get_service_name(port),
                    banner="",
                    error=str(e),
                )

    async def check_service_version(
        self, host: str, port: int, service: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Attempt to identify service version for a specific port.

        Args:
            host: Target hostname or IP
            port: Port number
            service: Known service name

        Returns:
            Dictionary with service information
        """
        result = {"service": service, "version": "unknown", "banner": "", "headers": {}}

        try:
            if port in [80, 8080, 8000, 8008, 443, 8443]:
                # HTTP/HTTPS service detection
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as session:
                    scheme = "https" if port in [443, 8443] else "http"
                    url = f"{scheme}://{host}:{port}/"

                    try:
                        async with session.get(url) as response:
                            result["headers"] = dict(response.headers)
                            result["service"] = "http"

                            # Extract server information
                            server = response.headers.get("Server", "")
                            if server:
                                result["version"] = server
                                result["banner"] = server

                    except Exception:
                        pass
            else:
                # TCP banner grabbing for other services
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=5.0
                    )

                    # Read initial banner
                    banner_data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                    banner = banner_data.decode("utf-8", errors="ignore").strip()
                    result["banner"] = banner

                    # Parse common service banners
                    if "SSH" in banner:
                        result["service"] = "ssh"
                        result["version"] = banner
                    elif "FTP" in banner:
                        result["service"] = "ftp"
                        result["version"] = banner
                    elif "SMTP" in banner:
                        result["service"] = "smtp"
                        result["version"] = banner

                    writer.close()
                    await writer.wait_closed()

                except Exception:
                    pass

        except Exception as e:
            result["error"] = str(e)

        return result
