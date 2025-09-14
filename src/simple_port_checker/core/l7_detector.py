"""
L7 Protection Detection module for identifying WAF, CDN, and other L7 services.

This module provides functionality to detect various L7 protection services
by analyzing HTTP headers, response patterns, and other indicators.
"""

import asyncio
import re
import time
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse

import aiohttp
import dns.resolver

from ..models.l7_result import L7Result, L7Detection, L7Protection
from ..utils.l7_signatures import L7_SIGNATURES, get_signature_patterns


class L7Detector:
    """Detector for L7 protection services like WAF, CDN, etc."""

    def __init__(self, timeout: float = 10.0, user_agent: Optional[str] = None):
        """
        Initialize the L7 detector.

        Args:
            timeout: Request timeout in seconds
            user_agent: Custom User-Agent string
        """
        self.timeout = timeout
        self.user_agent = user_agent or "SimplePortChecker/1.0 (Security Scanner)"
        self.signatures = L7_SIGNATURES

    async def detect(self, host: str, port: int = None, path: str = "/") -> L7Result:
        """
        Detect L7 protection services for a given host.

        Args:
            host: Target hostname
            port: Optional port (defaults to 80/443 based on scheme)
            path: URL path to test

        Returns:
            L7Result with detection results
        """
        start_time = time.time()

        # Determine URL
        if port:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}{path}"
        else:
            # Try HTTPS first, fall back to HTTP
            url = f"https://{host}{path}"

        detections = []
        response_headers = {}
        status_code = None
        error = None

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={"User-Agent": self.user_agent},
            ) as session:

                # Try HTTPS first
                try:
                    async with session.get(url) as response:
                        status_code = response.status
                        response_headers = dict(response.headers)

                        # Analyze response for L7 protection indicators
                        detections = await self._analyze_response(
                            response, response_headers, host
                        )

                except aiohttp.ClientConnectorError:
                    # If HTTPS fails and no port specified, try HTTP
                    if not port:
                        url = f"http://{host}{path}"
                        try:
                            async with session.get(url) as response:
                                status_code = response.status
                                response_headers = dict(response.headers)
                                detections = await self._analyze_response(
                                    response, response_headers, host
                                )
                        except Exception as e:
                            error = f"HTTP request failed: {str(e)}"
                    else:
                        error = f"Connection failed to {url}"

        except Exception as e:
            error = f"Request failed: {str(e)}"

        # Additional DNS-based detection
        if not error:
            dns_detections = await self._dns_detection(host)
            detections.extend(dns_detections)

        # Remove duplicates and sort by confidence
        unique_detections = self._deduplicate_detections(detections)
        unique_detections.sort(key=lambda d: d.confidence, reverse=True)

        return L7Result(
            host=host,
            url=url,
            detections=unique_detections,
            response_headers=response_headers,
            response_time=time.time() - start_time,
            status_code=status_code,
            error=error,
        )

    async def detect_multiple(
        self, hosts: List[str], port: int = None, path: str = "/"
    ) -> List[L7Result]:
        """
        Detect L7 protection for multiple hosts.

        Args:
            hosts: List of hostnames
            port: Optional port number
            path: URL path to test

        Returns:
            List of L7Result objects
        """
        tasks = []
        async with asyncio.TaskGroup() as group:
            for host in hosts:
                task = group.create_task(self.detect(host, port, path))
                tasks.append(task)

        return [task.result() for task in tasks]

    async def _analyze_response(
        self, response: aiohttp.ClientResponse, headers: Dict[str, str], host: str
    ) -> List[L7Detection]:
        """
        Analyze HTTP response for L7 protection indicators.

        Args:
            response: aiohttp response object
            headers: Response headers dictionary
            host: Target hostname

        Returns:
            List of L7Detection objects
        """
        detections = []

        # Check headers against signatures
        for protection_type, signatures in self.signatures.items():
            confidence = 0.0
            indicators = []

            # Check header patterns
            for header_name, patterns in signatures.get("headers", {}).items():
                header_value = headers.get(header_name, "").lower()
                if header_value:
                    for pattern in patterns:
                        if re.search(pattern.lower(), header_value):
                            confidence += 0.3
                            indicators.append(f"Header {header_name}: {header_value}")

            # Check server header specifically
            server_header = headers.get("Server", "").lower()
            if server_header:
                for pattern in signatures.get("server", []):
                    if re.search(pattern.lower(), server_header):
                        confidence += 0.4
                        indicators.append(f"Server header: {server_header}")

            # Check response body patterns
            try:
                body_text = await response.text()
                for pattern in signatures.get("body", []):
                    if re.search(pattern, body_text, re.IGNORECASE):
                        confidence += 0.2
                        indicators.append(f"Body pattern: {pattern}")
            except Exception:
                pass  # Ignore body analysis errors

            # Check status code patterns
            status_patterns = signatures.get("status_codes", [])
            if response.status in status_patterns:
                confidence += 0.1
                indicators.append(f"Status code: {response.status}")

            # Create detection if confidence is above threshold
            if confidence > 0.2 and indicators:
                # Cap confidence at 1.0
                confidence = min(confidence, 1.0)

                detection = L7Detection(
                    service=protection_type,
                    confidence=confidence,
                    indicators=indicators,
                    details={"method": "http_analysis"},
                )
                detections.append(detection)

        return detections

    async def _dns_detection(self, host: str) -> List[L7Detection]:
        """
        Perform DNS-based L7 protection detection.

        Args:
            host: Target hostname

        Returns:
            List of L7Detection objects from DNS analysis
        """
        detections = []

        try:
            # Check CNAME records for CDN/WAF indicators
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5

            try:
                cname_answers = resolver.resolve(host, "CNAME")
                for cname in cname_answers:
                    cname_str = str(cname.target).lower()

                    # Check CNAME against known patterns
                    if "cloudflare" in cname_str:
                        detections.append(
                            L7Detection(
                                service=L7Protection.CLOUDFLARE,
                                confidence=0.8,
                                indicators=[f"CNAME: {cname_str}"],
                                details={"method": "dns_cname"},
                            )
                        )
                    elif "fastly" in cname_str:
                        detections.append(
                            L7Detection(
                                service=L7Protection.FASTLY,
                                confidence=0.8,
                                indicators=[f"CNAME: {cname_str}"],
                                details={"method": "dns_cname"},
                            )
                        )
                    elif "akamai" in cname_str or "edgekey" in cname_str:
                        detections.append(
                            L7Detection(
                                service=L7Protection.AKAMAI,
                                confidence=0.8,
                                indicators=[f"CNAME: {cname_str}"],
                                details={"method": "dns_cname"},
                            )
                        )
                    elif "awsdns" in cname_str or "amazonaws" in cname_str:
                        detections.append(
                            L7Detection(
                                service=L7Protection.AWS_WAF,
                                confidence=0.6,
                                indicators=[f"CNAME: {cname_str}"],
                                details={"method": "dns_cname"},
                            )
                        )
                    elif "azurefd.net" in cname_str:
                        detections.append(
                            L7Detection(
                                service=L7Protection.AZURE_FRONT_DOOR,
                                confidence=0.9,
                                indicators=[f"CNAME: {cname_str}"],
                                details={"method": "dns_cname"},
                            )
                        )

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass  # No CNAME records

            # Check A records for known IP ranges
            try:
                a_answers = resolver.resolve(host, "A")
                for a_record in a_answers:
                    ip_str = str(a_record)

                    # Check against known Cloudflare IP ranges
                    if self._is_cloudflare_ip(ip_str):
                        detections.append(
                            L7Detection(
                                service=L7Protection.CLOUDFLARE,
                                confidence=0.7,
                                indicators=[f"Cloudflare IP: {ip_str}"],
                                details={"method": "dns_ip_range"},
                            )
                        )

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass  # No A records

        except Exception:
            pass  # Ignore DNS errors

        return detections

    def _is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP address belongs to Cloudflare."""
        # Simplified check for Cloudflare IP ranges
        # In production, you'd want a more comprehensive list
        cloudflare_ranges = [
            "103.21.244.",
            "103.22.200.",
            "103.31.4.",
            "104.16.",
            "104.17.",
            "104.18.",
            "104.19.",
            "104.20.",
            "104.21.",
            "104.22.",
            "104.23.",
            "104.24.",
            "104.25.",
            "104.26.",
            "104.27.",
            "104.28.",
            "108.162.192.",
            "131.0.72.",
            "141.101.64.",
            "162.158.",
            "172.64.",
            "173.245.48.",
            "188.114.96.",
            "190.93.240.",
            "197.234.240.",
            "198.41.128.",
        ]

        return any(ip.startswith(prefix) for prefix in cloudflare_ranges)

    def _deduplicate_detections(
        self, detections: List[L7Detection]
    ) -> List[L7Detection]:
        """Remove duplicate detections, keeping the one with highest confidence."""
        seen_services = {}

        for detection in detections:
            service = detection.service
            if (
                service not in seen_services
                or detection.confidence > seen_services[service].confidence
            ):
                seen_services[service] = detection

        return list(seen_services.values())

    async def test_waf_bypass(self, host: str, port: int = None) -> Dict[str, Any]:
        """
        Test for WAF presence using common bypass techniques.

        Args:
            host: Target hostname
            port: Optional port number

        Returns:
            Dictionary with WAF test results
        """
        results = {
            "waf_detected": False,
            "blocked_requests": [],
            "successful_requests": [],
            "detection_methods": [],
        }

        # Common WAF detection payloads
        test_payloads = [
            "/?test=<script>alert('xss')</script>",
            "/?test=' OR '1'='1",
            "/?test=../../../etc/passwd",
            "/?test=<img src=x onerror=alert(1)>",
            "/?test=UNION SELECT 1,2,3--",
        ]

        base_url = f"http://{host}" if port == 80 else f"https://{host}"
        if port and port not in [80, 443]:
            base_url += f":{port}"

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as session:

                for payload in test_payloads:
                    try:
                        url = base_url + payload
                        async with session.get(url) as response:

                            # Check for WAF indicators
                            if response.status in [403, 406, 429, 503]:
                                results["blocked_requests"].append(
                                    {
                                        "payload": payload,
                                        "status": response.status,
                                        "headers": dict(response.headers),
                                    }
                                )
                                results["waf_detected"] = True
                            else:
                                results["successful_requests"].append(
                                    {"payload": payload, "status": response.status}
                                )

                    except Exception as e:
                        results["blocked_requests"].append(
                            {"payload": payload, "error": str(e)}
                        )

        except Exception as e:
            results["error"] = str(e)

        return results
