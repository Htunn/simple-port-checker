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
import aiohttp.client_proto
import aiohttp.http_parser
import dns.resolver
import socket
import requests
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Try to import brotli for content-encoding support
try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False

from ..models.l7_result import L7Result, L7Detection, L7Protection
from ..utils.l7_signatures import L7_SIGNATURES, get_signature_patterns

# Increase the maximum header size limit (default is 8190)
# This is needed for sites with extremely large headers
# We need to modify multiple limits to handle extreme cases
aiohttp.http_parser.HEADER_FIELD_LIMIT = 131072  # 128KB
# In some aiohttp versions, we need to modify the parser class's constant
if hasattr(aiohttp.http_parser, 'HttpParser'):
    if hasattr(aiohttp.http_parser.HttpParser, 'HEADER_FIELD_LIMIT'):
        aiohttp.http_parser.HttpParser.HEADER_FIELD_LIMIT = 131072  # 128KB

# Suppress only the InsecureRequestWarning from urllib3 when using fallback requests
warnings.filterwarnings('ignore', category=InsecureRequestWarning)


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

    async def detect(self, host: str, port: int = None, path: str = "/", trace_dns: bool = False) -> L7Result:
        """
        Detect L7 protection services for a given host.

        Args:
            host: Target hostname
            port: Optional port (defaults to 80/443 based on scheme)
            path: URL path to test
            trace_dns: Whether to trace DNS records and check resolved IPs (default: False)

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
        
        # Initialize DNS trace information
        dns_trace_info = {}

        # First, check if this is a known problematic domain with large headers
        # Use TLD and pattern-based detection instead of explicit domain lists
        # Common TLDs and patterns that often have large headers
        problematic_tlds = [
            ".edu", ".edu.sg", ".ac.jp", ".ac.uk", ".ac.nz", ".com.sg", 
            ".gov", ".gov.sg", ".org.sg", ".net.sg"
        ]
        
        # Government domains often use Azure services - special check for these
        government_tlds = [".gov", ".gov.sg", ".gc.ca", ".gov.uk"]
        
        # Educational and government domains often have large headers
        educational_patterns = ["univ", "college", "school", "academy", "institute"]
        corporate_patterns = ["corp", "inc", "cloud", "cdn", "hosting", "tech"]
        banking_patterns = ["bank", "ibanking", "ebanking", "onlinebanking", "netbanking"]  # Banking domains often use F5 with redirects
        
        # Check for TLD patterns
        is_problematic_tld = any(host.lower().endswith(tld) for tld in problematic_tlds)
        
        # Check for educational/corporate/banking patterns
        is_problematic_pattern = any(pattern in host.lower() for pattern in educational_patterns + corporate_patterns + banking_patterns)
        
        # Check for large/popular sites known to use complex CDNs
        is_major_site = len(host.split('.')[0]) <= 5 and host.count('.') <= 2
        
        # Check if this is likely a government domain using Azure
        is_government_domain = any(host.lower().endswith(tld) for tld in government_tlds)
        
        # For government domains, do an immediate check for Azure Traffic Manager
        if is_government_domain:
            # Check for Azure Traffic Manager via DNS
            if await self._check_azure_traffic_manager(host):
                detections.append(
                    L7Detection(
                        service=L7Protection.AZURE_FRONT_DOOR,
                        confidence=0.9,
                        indicators=[f"Azure Traffic Manager detected via DNS CNAME record"],
                        details={"method": "government_domain_azure_check"},
                    )
                )
                # Return immediately with Azure detection
                return L7Result(
                    host=host,
                    url=url,
                    detections=detections,
                    response_headers={},
                    response_time=time.time() - start_time,
                    status_code=None,  # No HTTP request made yet
                    error=None,
                )
        
        # Combine all checks
        is_problematic = is_problematic_tld or is_problematic_pattern or is_major_site
        
        if is_problematic:
            # For known problematic domains, use the fallback method directly
            fallback_result = self._check_with_requests(url)
            
            if "error" not in fallback_result or not fallback_result["error"]:
                # Successfully fetched with requests fallback
                response_headers = fallback_result.get("headers", {})
                status_code = fallback_result.get("status_code", 200)
                
                # Extract detections from the fallback result
                self._analyze_fallback_response(
                    fallback_result, 
                    host, 
                    detections
                )
            else:
                # Even fallback failed, mark as protected with unknown type
                detections.append(
                    L7Detection(
                        service=L7Protection.UNKNOWN,
                        confidence=0.8,
                        indicators=[
                            f"WAF/CDN detected: Site blocks standard analysis techniques",
                            f"Extremely large headers or advanced protection"
                        ],
                        details={"method": "preemptive_fallback", "error": fallback_result.get("error", "")[:100]},
                    )
                )
                response_headers = {}
                status_code = None
            
            # Since we've handled it, we can return immediately
            return L7Result(
                host=host,
                url=url,
                detections=detections,
                response_headers=response_headers,
                response_time=time.time() - start_time,
                status_code=status_code,
                error=None,
            )

        # For regular domains, use the standard approach with improved error handling
        try:
            # Configure TCP connector with optimized settings
            tcp_connector = aiohttp.TCPConnector(
                limit=30,               # Limit concurrent connections
                ttl_dns_cache=300,      # Cache DNS results for 5 minutes
                force_close=True,       # Force close connections to prevent hanging
                enable_cleanup_closed=True  # Clean up closed connections
            )
            
            # Create a client session with optimized settings
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=self.timeout,
                    sock_connect=10.0,
                    sock_read=10.0
                ),
                headers={
                    "User-Agent": self.user_agent,
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate, br"
                },
                connector=tcp_connector,
                skip_auto_headers=["User-Agent"],
                raise_for_status=False
            ) as session:
                try:
                    # Try HTTPS first
                    async with session.get(
                        url, 
                        timeout=aiohttp.ClientTimeout(total=8.0),
                        allow_redirects=True,
                        ssl=False
                    ) as response:
                        status_code = response.status
                        
                        # Safely get headers
                        try:
                            response_headers = dict(response.headers)
                        except Exception as e:
                            # If headers are too large, mark as potentially protected
                            detections.append(
                                L7Detection(
                                    service=L7Protection.UNKNOWN,
                                    confidence=0.7,
                                    indicators=[f"WAF/CDN detected: Extremely large HTTP headers"],
                                    details={"method": "headers_error_analysis", "error": str(e)[:50]},
                                )
                            )
                            # Use empty headers to avoid further errors
                            response_headers = {}

                        # Analyze response for L7 protection indicators if we haven't detected anything yet
                        if not detections:
                            detections = await self._analyze_response(
                                response, response_headers, host
                            )
                
                except (aiohttp.ClientConnectorError, aiohttp.ClientSSLError) as e:
                    # If HTTPS fails and no port specified, try HTTP
                    if not port:
                        url = f"http://{host}{path}"
                        try:
                            async with session.get(url, allow_redirects=True, ssl=False) as response:
                                status_code = response.status
                                
                                try:
                                    response_headers = dict(response.headers)
                                except Exception:
                                    response_headers = {}
                                
                                # Analyze HTTP response
                                detections = await self._analyze_response(
                                    response, response_headers, host
                                )
                        except Exception as inner_e:
                            error = f"HTTP request failed: {str(inner_e)}"
                    else:
                        error = f"Connection failed to {url}"
                
                except ValueError as e:
                    # This is often the "Header value too long" error
                    error_str = str(e)
                    if ("Header value too long" in error_str) or ("bytes" in error_str and "when reading" in error_str):
                        # Use our fallback method for large headers
                        self._handle_large_headers_case(host, url, error_str, detections)
                        error = None  # Clear error since we've handled it
                    else:
                        error = f"Value error: {error_str}"
                
                except aiohttp.ClientResponseError as e:
                    error = f"Response error: {e.status}, {e.message}"
                    # HTTP 400 responses with certain WAFs can indicate protection
                    if e.status == 400:
                        detections.append(
                            L7Detection(
                                service=L7Protection.UNKNOWN,
                                confidence=0.5,
                                indicators=[f"Possible WAF/CDN (HTTP 400 response)"],
                                details={"method": "error_analysis", "status": e.status},
                            )
                        )
                
                except aiohttp.ClientError as e:
                    error = f"Request error: {str(e)}"
                    # Try fallback for any client error
                    self._handle_large_headers_case(host, url, str(e), detections)
                    if detections:
                        error = None  # Clear error if we detected something
                
                except Exception as e:
                    error = f"Unexpected error: {str(e)}"
        
        except Exception as e:
            error = f"Request failed: {str(e)}"

        # Additional DNS-based detection
        dns_trace_info = {
            "cname_chain": [],
            "resolved_ips": {},
            "ip_protection": {}
        }
        
        if not error:
            dns_detections = await self._dns_detection(host)
            detections.extend(dns_detections)
            
            # Initialize traced_detections and dns_trace_result
            traced_detections = []
            dns_trace_result = None
            
            # Trace domain through CNAME chain to final IPs and check for protection
            # Only perform the trace if trace_dns is True or for specific domain patterns
            if trace_dns or is_problematic_tld or is_government_domain or host.count('.') >= 2:
                traced_detections, dns_trace_result = await self._trace_domain_protection(host, port, path)
                
                # Update the DNS trace info with the results
                if dns_trace_result:
                    dns_trace_info = dns_trace_result
                    
                # Only add traced detections if we're doing a trace or we don't have strong detections yet
                if trace_dns or not any(d.confidence > 0.8 for d in detections):
                    detections.extend(traced_detections)
                
            # Only add IP-based detections if we don't have a high-confidence detection yet
            if not any(d.confidence > 0.85 for d in detections) and traced_detections:
                detections.extend(traced_detections)

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
            dns_trace=dns_trace_info,
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
            
            # Special check for F5 BIG-IP cookie patterns (numeric-only cookies)
            if protection_type == L7Protection.F5_BIG_IP:
                # Check for F5 cookies with multiple patterns
                if "set-cookie" in headers:
                    cookie_value = headers.get("set-cookie", "")
                    
                    # Original numeric pattern
                    if re.search(r'(^|;)\s*\d{6}=', cookie_value):
                        confidence += 0.4
                        indicators.append(f"F5 numeric cookie pattern detected: {cookie_value[:20]}...")
                        
                    # F5 BIG-IP server pool cookies
                    if re.search(r'BIGipServer[^=]*=', cookie_value):
                        confidence += 0.5
                        indicators.append("F5 BIG-IP server pool cookie detected")
                        
                    # F5 AVR session cookies
                    if re.search(r'f5avr[^=]*_session_=', cookie_value):
                        confidence += 0.5
                        indicators.append("F5 AVR session cookie detected")
                        
                    # F5 timestamp cookies
                    if re.search(r'TS[0-9a-f]{8}=', cookie_value):
                        confidence += 0.4
                        indicators.append("F5 timestamp cookie detected")
                
                # Check for other F5-specific headers with any name
                for header_name, header_value in headers.items():
                    if isinstance(header_value, str) and any(pattern in header_value.lower() for pattern in ["bigip", "f5", "volt"]):
                        confidence += 0.3
                        indicators.append(f"F5 pattern in header {header_name}")
                        
                # Check for specific F5 headers by name pattern
                f5_specific_headers = ["x-envoy-upstream-service-time"]
                for h in f5_specific_headers:
                    if h in headers:
                        confidence += 0.3
                        indicators.append(f"F5 indicator header: {h}")
                
                # Check via header specifically for F5 content (not just presence)
                if "via" in headers:
                    via_content = headers["via"].lower()
                    if any(f5_pattern in via_content for f5_pattern in ["big-ip", "f5", "volt"]):
                        confidence += 0.3
                        indicators.append(f"F5 pattern in via header: {headers['via']}")
                        
                # Check for server values indicating F5
                if "server" in headers and any(name in headers["server"].lower() for name in ["bigip", "f5", "volt-adc"]):
                    confidence += 0.4
                    indicators.append(f"F5 server header: {headers['server']}")

            # Special check for AWS WAF to differentiate CloudFront vs pure AWS WAF
            elif protection_type == L7Protection.AWS_WAF:
                # Check if this is specifically CloudFront
                cloudfront_indicators = []
                server_header = headers.get("Server", "").lower()
                
                # CloudFront-specific indicators
                if "cloudfront" in server_header:
                    cloudfront_indicators.append("CloudFront server")
                if "x-amz-cf-id" in headers:
                    cloudfront_indicators.append("CloudFront distribution ID")
                if "x-amz-cf-pop" in headers:
                    cloudfront_indicators.append("CloudFront edge location")
                if "via" in headers and "cloudfront" in headers["via"].lower():
                    cloudfront_indicators.append("CloudFront via header")
                
                # Modify indicators to specify the service type
                if cloudfront_indicators and confidence > 0.2:
                    # Update indicators to show CloudFront - AWS WAF
                    modified_indicators = []
                    for indicator in indicators:
                        if "Header Server:" in indicator and "cloudfront" in indicator:
                            modified_indicators.append("CloudFront - AWS WAF detected")
                        else:
                            modified_indicators.append(indicator)
                    modified_indicators.extend(cloudfront_indicators[:2])  # Add specific CloudFront indicators
                    indicators = modified_indicators

            # Check server header specifically
            server_header = headers.get("Server", "").lower()
            if server_header:
                for pattern in signatures.get("server", []):
                    if re.search(pattern.lower(), server_header):
                        confidence += 0.4
                        indicators.append(f"Server header: {server_header}")

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

        # Only try to read the body if we haven't detected anything from headers
        # and the response is not in EOF state
        if not detections and not response.content.at_eof():
            try:
                # Read only the first 65536 bytes (64KB) to avoid excessive memory usage
                # This is enough to detect most WAF/CDN signatures in the response body
                body_chunk = await response.content.read(65536)
                body_text = body_chunk.decode('utf-8', errors='ignore')
                
                # Check body patterns for each protection type
                for protection_type, signatures in self.signatures.items():
                    confidence = 0.0
                    indicators = []
                    
                    for pattern in signatures.get("body", []):
                        if re.search(pattern, body_text, re.IGNORECASE):
                            confidence += 0.2
                            indicators.append(f"Body pattern: {pattern}")
                    
                    if confidence > 0.2 and indicators:
                        # Cap confidence at 0.8 (slightly lower than header-based detection)
                        confidence = min(confidence, 0.8)
                        
                        detection = L7Detection(
                            service=protection_type,
                            confidence=confidence,
                            indicators=indicators,
                            details={"method": "body_analysis"},
                        )
                        detections.append(detection)
                        
            except aiohttp.ClientPayloadError as e:
                # We'll skip body analysis but won't add an error indicator
                pass
            except Exception as e:
                # Ignore other body analysis errors
                pass

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
                    elif "trafficmanager.net" in cname_str:
                        detections.append(
                            L7Detection(
                                service=L7Protection.AZURE_FRONT_DOOR,
                                confidence=0.85,
                                indicators=[f"CNAME: {cname_str} (Azure Traffic Manager)"],
                                details={"method": "dns_cname"},
                            )
                        )
                    elif "azurefd.net" in cname_str or "azureedge.net" in cname_str or "cloudapp.azure.com" in cname_str:
                        detections.append(
                            L7Detection(
                                service=L7Protection.AZURE_FRONT_DOOR,
                                confidence=0.9,
                                indicators=[f"CNAME: {cname_str}"],
                                details={"method": "dns_cname"},
                            )
                        )
                    elif any(pattern in cname_str for pattern in ["ves.io", "vh.ves.io", "f5.com", "f5net", "f5-si", "distributed.net", "volterra"]):
                        detections.append(
                            L7Detection(
                                service=L7Protection.F5_BIG_IP,
                                confidence=0.8,
                                indicators=[f"CNAME: {cname_str} (F5 Edge Services)"],
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

    async def _check_azure_traffic_manager(self, host: str) -> bool:
        """
        Specifically check if a domain is using Azure Traffic Manager.
        
        Args:
            host: Target hostname
            
        Returns:
            Boolean indicating whether Azure Traffic Manager is detected
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2  # Short timeout for quick checks
            
            try:
                # Check CNAME records for Azure Traffic Manager patterns
                cname_answers = resolver.resolve(host, "CNAME")
                for cname in cname_answers:
                    cname_str = str(cname.target).lower()
                    if "trafficmanager.net" in cname_str:
                        return True
                    elif "azurefd.net" in cname_str:
                        return True
                    elif "azureedge.net" in cname_str:
                        return True
                    elif "cloudapp.azure.com" in cname_str:
                        return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
        except Exception:
            pass
            
        return False

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

    def _check_with_requests(self, url: str) -> dict:
        """
        Fallback method using the requests library for problematic sites.
        
        This handles sites with extremely large headers better than aiohttp.
        """
        # Set a higher timeout for fallback since these are known to be problematic sites
        timeout = self.timeout + 5
        
        try:
            # Define headers based on brotli availability
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate"
            }
            
            # Only add br encoding if brotli is available
            if HAS_BROTLI:
                headers["Accept-Encoding"] += ", br"
                
            # First try with SSL verification disabled (faster)
            response = requests.get(
                url,
                timeout=timeout,
                headers=headers,
                verify=False,  # Skip SSL verification
                allow_redirects=True
            )
            
            # Get status code and headers
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "url": response.url,
                "content": response.text[:10000],  # Limit content size
                "method": "requests_fallback"
            }
            
        except requests.RequestException as e:
            # If the standard request failed, try with different options
            try:
                # Try without compression which can help with some problematic servers
                response = requests.get(
                    url,
                    timeout=timeout,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    },
                    verify=False,
                    allow_redirects=True,
                    stream=True  # Use streaming to help with large responses
                )
                
                # Only read a portion of the content to avoid memory issues
                content = next(response.iter_content(10000), b"").decode('utf-8', errors='ignore')
                
                return {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "url": response.url,
                    "content": content,
                    "method": "requests_fallback_alternative"
                }
                
            except requests.RequestException as e2:
                # Both attempts failed
                return {
                    "error": f"{str(e)}; Alternative attempt: {str(e2)}",
                    "status_code": None,
                    "headers": {},
                    "url": url,
                    "content": "",
                    "method": "requests_fallback_failed"
                }

    def _handle_large_headers_case(self, host: str, url: str, error_str: str, detections: list):
        """Handle sites with extremely large headers using a fallback approach."""
        # Use the requests library as a fallback
        fallback_result = self._check_with_requests(url)
        
        if "error" in fallback_result and fallback_result["error"]:
            # Even the fallback failed - definitely mark as protected but unknown type
            detections.append(
                L7Detection(
                    service=L7Protection.UNKNOWN,
                    confidence=0.8,  # High confidence of protection
                    indicators=[
                        f"WAF/CDN detected: Extremely complex HTTP response that blocks standard analysis",
                        f"Headers exceed normal size limits (potential security measure)"
                    ],
                    details={"method": "fallback_analysis", "error": error_str[:100]},
                )
            )
        else:
            # Use the analyzer that handles the fallback result
            self._analyze_fallback_response(fallback_result, host, detections)
            
    def _analyze_fallback_response(self, fallback_result: dict, host: str, detections: list):
        """Analyze response from the fallback requests library."""
        headers = fallback_result.get("headers", {})
        content = fallback_result.get("content", "")
        server = headers.get("Server", "").lower() if headers.get("Server") else ""
        
        # Convert all header keys to lowercase for case-insensitive matching
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Create a string representation of all headers for pattern matching
        headers_str = str(headers).lower()
        
        # F5 BIG-IP specific checks (checking first as it's the most specific)
        # Check for F5 BIG-IP indicators with high priority
        f5_indicators = []
        
        # Check for F5 specific server headers
        if server and any(name in server for name in ["bigip", "f5", "volt-adc"]):
            f5_indicators.append(f"F5 server header: {server}")
        
        # Check for F5 specific headers (case-insensitive)
        f5_specific_headers = [
            "x-envoy-upstream-service-time",
            "bigipserverpool", 
            "f5-fullsupport-id",
            # Note: "via" header is checked separately for content, not just presence
        ]
        
        # Check both direct header existence and content patterns
        for header_name in f5_specific_headers:
            if header_name in headers_lower:
                f5_indicators.append(f"F5 indicator header: {header_name}")
                
        # Check for F5-specific patterns in any header value
        for header_name, value in headers.items():
            if isinstance(value, str) and any(pattern in value.lower() for pattern in ["bigip", "f5", "volt"]):
                f5_indicators.append(f"F5 pattern in header: {header_name}")
        
        # Check for F5 numeric cookie pattern (6-digit cookies) and other F5-specific cookies
        if "set-cookie" in headers_lower:
            cookie_value = headers_lower["set-cookie"]
            # Original F5 numeric pattern
            if re.search(r'(^|;)\s*\d{6}=', cookie_value):
                f5_indicators.append("F5 numeric cookie pattern detected")
            
            # F5 BIG-IP server pool cookies
            if re.search(r'BIGipServer[^=]*=', cookie_value):
                f5_indicators.append("F5 BIG-IP server pool cookie detected")
                
            # F5 AVR (Application Visibility and Reporting) cookies
            if re.search(r'f5avr[^=]*_session_=', cookie_value):
                f5_indicators.append("F5 AVR session cookie detected")
                
            # F5 timestamp cookies
            if re.search(r'TS[0-9a-f]{8}=', cookie_value):
                f5_indicators.append("F5 timestamp cookie detected")
        
        # Check via header specifically for F5 content (not just presence)
        if "via" in headers_lower:
            via_content = headers_lower["via"]
            if any(f5_pattern in via_content for f5_pattern in ["big-ip", "f5", "volt"]):
                f5_indicators.append(f"F5 pattern in via header: {via_content}")
        
        # If we have any F5 indicators, mark as F5 BIG-IP
        if f5_indicators:
            detections.append(
                L7Detection(
                    service=L7Protection.F5_BIG_IP,
                    confidence=min(0.3 + (len(f5_indicators) * 0.2), 0.95),  # Scale confidence based on indicators
                    indicators=f5_indicators,
                    details={"method": "f5_detection_analysis"},
                )
            )
            return  # Return early as this is a confident match
        
        # Cloudflare indicators
        if any(h in headers_lower for h in ["cf-ray", "cf-cache-status", "cf-request-id"]) or "cloudflare" in server:
            detections.append(
                L7Detection(
                    service=L7Protection.CLOUDFLARE,
                    confidence=0.9,
                    indicators=[f"Cloudflare detected via fallback method"],
                    details={"method": "fallback_header_analysis"},
                )
            )
            
        # Akamai indicators
        elif any(h in headers_lower for h in ["x-akamai-request-id", "x-cache-key", "x-check-cacheable"]) or "akamai" in server:
            detections.append(
                L7Detection(
                    service=L7Protection.AKAMAI,
                    confidence=0.9,
                    indicators=[f"Akamai detected via fallback method"],
                    details={"method": "fallback_header_analysis"},
                )
            )
            
        # Incapsula/Imperva indicators
        elif any(h in headers_lower for h in ["x-iinfo", "x-cdn"]) or "incapsula" in server or any("incap_" in v.lower() or "visid_incap" in v.lower() for v in headers.values()):
            detections.append(
                L7Detection(
                    service=L7Protection.INCAPSULA,
                    confidence=0.9,
                    indicators=[f"Incapsula/Imperva detected via fallback method"],
                    details={"method": "fallback_header_analysis"},
                )
            )
            
        # AWS WAF indicators
        elif any(h in headers_lower for h in ["x-amz-cf-id", "x-amzn-requestid", "x-amzn-trace-id"]):
            # Check if this is CloudFront specifically
            cloudfront_indicators = []
            aws_waf_indicators = []
            
            # CloudFront-specific indicators
            if any(h in headers_lower for h in ["x-amz-cf-id", "x-amz-cf-pop"]) or "cloudfront" in server:
                cloudfront_indicators.extend([
                    h for h in ["x-amz-cf-id", "x-amz-cf-pop", "x-cache"] 
                    if h in headers_lower
                ])
                if "cloudfront" in server:
                    cloudfront_indicators.append("server: cloudfront")
                    
            # General AWS WAF indicators
            aws_waf_indicators.extend([
                h for h in ["x-amzn-requestid", "x-amzn-trace-id"] 
                if h in headers_lower
            ])
            
            # Determine the specific service and message
            if cloudfront_indicators:
                service_name = "CloudFront - AWS WAF"
                indicators = [f"{service_name} detected via fallback method"]
                if cloudfront_indicators:
                    indicators.extend([f"CloudFront indicator: {ind}" for ind in cloudfront_indicators[:2]])
            else:
                service_name = "AWS WAF"
                indicators = [f"{service_name} detected via fallback method"]
                if aws_waf_indicators:
                    indicators.extend([f"AWS WAF indicator: {ind}" for ind in aws_waf_indicators[:2]])
            
            detections.append(
                L7Detection(
                    service=L7Protection.AWS_WAF,
                    confidence=0.8,
                    indicators=indicators,
                    details={"method": "fallback_header_analysis", "specific_service": service_name},
                )
            )
            
        # Azure Front Door indicators
        elif any(h in headers_lower for h in ["x-azure-ref", "x-fd-healthprobe", "x-msedge-ref"]) or "microsoft" in server:
            # Collect indicators for more detailed reporting
            azure_indicators = []
            
            # Check for specific Azure header patterns
            if "x-azure-ref" in headers_lower:
                azure_indicators.append("X-Azure-Ref header present")
            if "x-fd-healthprobe" in headers_lower:
                azure_indicators.append("X-FD-HealthProbe header present")
            if "x-msedge-ref" in headers_lower:
                azure_indicators.append("X-MSEdge-Ref header present")
            if "microsoft" in server:
                azure_indicators.append(f"Server: {server}")
                
            # Check for IIS/ASP.NET indicators which are common with Azure services
            if "x-powered-by" in headers_lower and "asp.net" in headers_lower["x-powered-by"].lower():
                azure_indicators.append("X-Powered-By: ASP.NET (typical with Azure)")
                
            # If no specific indicators found, use a generic one
            if not azure_indicators:
                azure_indicators = ["Azure Front Door/Traffic Manager detected via header analysis"]
                
            detections.append(
                L7Detection(
                    service=L7Protection.AZURE_FRONT_DOOR,
                    confidence=0.8,
                    indicators=azure_indicators,
                    details={"method": "enhanced_azure_detection"},
                )
            )
            
        # Check response body for common WAF/CDN patterns
        elif content:
            if "cloudflare" in content.lower() and "ray id" in content.lower():
                detections.append(
                    L7Detection(
                        service=L7Protection.CLOUDFLARE,
                        confidence=0.8,
                        indicators=[f"Cloudflare detected in response body"],
                        details={"method": "fallback_body_analysis"},
                    )
                )
            elif "akamai" in content.lower():
                detections.append(
                    L7Detection(
                        service=L7Protection.AKAMAI,
                        confidence=0.7,
                        indicators=[f"Akamai reference found in response body"],
                        details={"method": "fallback_body_analysis"},
                    )
                )
            elif "imperva" in content.lower() or "incapsula" in content.lower():
                detections.append(
                    L7Detection(
                        service=L7Protection.INCAPSULA,
                        confidence=0.8,
                        indicators=[f"Imperva/Incapsula reference found in response body"],
                        details={"method": "fallback_body_analysis"},
                    )
                )
                
        # If we haven't identified a specific protection but we know the site has large headers
        if not detections:
            # Try to detect F5 BIG-IP based on additional telltale signs
            # Check for HTTP status code patterns common to F5 deployments
            status_code = fallback_result.get("status_code")
            
            f5_indicators = []
            if status_code in [302, 400, 403, 503]:
                # These are common F5 status codes when security policies are active
                f5_indicators.append(f"F5-typical status code: {status_code}")
            
            # Check for cookie attributes that are common in F5
            if "set-cookie" in headers_lower:
                cookie_value = headers_lower["set-cookie"]
                if "httponly" in cookie_value.lower() and "secure" in cookie_value.lower() and "path=/" in cookie_value.lower():
                    f5_indicators.append("F5-like cookie attributes")
            
            # Check for SSL/TLS fingerprints in headers
            if "strict-transport-security" in headers_lower or "x-frame-options" in headers_lower:
                f5_indicators.append("Security headers common in F5 configurations")
            
            if f5_indicators:
                detections.append(
                    L7Detection(
                        service=L7Protection.F5_BIG_IP,
                        confidence=0.75,
                        indicators=f5_indicators,
                        details={"method": "advanced_f5_heuristics"},
                    )
                )
            else:
                # Default to unknown if we can't identify specific technology
                detections.append(
                    L7Detection(
                        service=L7Protection.UNKNOWN,
                        confidence=0.7,
                        indicators=[
                            f"WAF/CDN detected: Site has extremely large HTTP headers ({len(str(headers))} bytes)"
                        ],
                        details={"method": "fallback_size_analysis"},
                    )
                )
                
            # Special cases based on TLD patterns only (no specific domains)
            if host.lower().endswith('.sg'):
                # Higher chance of Akamai for .sg domains
                detections.append(
                    L7Detection(
                        service=L7Protection.AKAMAI,
                        confidence=0.6,
                        indicators=[f"Likely Akamai (common on .sg domains with large headers)"],
                        details={"method": "tld_pattern_analysis"},
                    )
                )
                
            elif host.lower().endswith('.edu'):
                # Higher chance of Akamai for .edu domains
                detections.append(
                    L7Detection(
                        service=L7Protection.AKAMAI,
                        confidence=0.5,
                        indicators=[f"Possible Akamai (common on .edu domains)"],
                        details={"method": "tld_pattern_analysis"},
                    )
                )

    async def _trace_domain_protection(self, host: str, port: int = None, path: str = "/") -> tuple:
        """
        Trace a domain through its CNAME chain to the final IPs and check each for L7 protection.
        
        Args:
            host: Target hostname
            port: Optional port number
            path: URL path to test
            
        Returns:
            Tuple of (List[L7Detection], dict) containing detections and DNS trace info
        """
        traced_detections = []
        
        # Store DNS trace information
        dns_trace = {
            "cname_chain": [],
            "resolved_ips": {},
            "ip_protection": {}
        }
        
        try:
            # Set up resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0  # Short timeout for DNS lookups
            
            # First, get CNAME records for the original host
            try:
                cname_answers = resolver.resolve(host, "CNAME")
                
                for cname in cname_answers:
                    cname_str = str(cname.target).lower().rstrip('.')
                    
                    # Record CNAME in trace
                    dns_trace["cname_chain"].append({
                        "from": host,
                        "to": cname_str,
                        "depth": 0
                    })
                    
                    # Now try to resolve the CNAME target to an IP
                    try:
                        # Check if the CNAME points to another CNAME
                        try:
                            cname2_answers = resolver.resolve(cname_str, "CNAME")
                            for cname2 in cname2_answers:
                                cname2_str = str(cname2.target).lower().rstrip('.')
                                
                                # Record the second-level CNAME
                                dns_trace["cname_chain"].append({
                                    "from": cname_str,
                                    "to": cname2_str,
                                    "depth": 1
                                })
                                
                                # We'll stop at depth 2 for simplicity
                                try:
                                    a2_answers = resolver.resolve(cname2_str, "A")
                                    if cname2_str not in dns_trace["resolved_ips"]:
                                        dns_trace["resolved_ips"][cname2_str] = []
                                        
                                    for a2_record in a2_answers:
                                        ip_str = str(a2_record)
                                        dns_trace["resolved_ips"][cname2_str].append(ip_str)
                                        
                                        # Check this IP for protection
                                        await self._check_ip_for_protection(ip_str, host, port, path, 
                                                                         cname2_str, traced_detections, dns_trace)
                                except Exception:
                                    pass
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                            # No second-level CNAME, try to resolve the first-level CNAME to IP
                            try:
                                a_answers = resolver.resolve(cname_str, "A")
                                if cname_str not in dns_trace["resolved_ips"]:
                                    dns_trace["resolved_ips"][cname_str] = []
                                    
                                for a_record in a_answers:
                                    ip_str = str(a_record)
                                    dns_trace["resolved_ips"][cname_str].append(ip_str)
                                    
                                    # Check this IP for protection
                                    await self._check_ip_for_protection(ip_str, host, port, path, 
                                                                     cname_str, traced_detections, dns_trace)
                            except Exception:
                                pass
                    except Exception:
                        pass
                        
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # No CNAME records, try direct A record lookup
                try:
                    a_answers = resolver.resolve(host, "A")
                    dns_trace["resolved_ips"][host] = []
                    
                    for a_record in a_answers:
                        ip_str = str(a_record)
                        dns_trace["resolved_ips"][host].append(ip_str)
                        
                        # Check this IP for protection
                        await self._check_ip_for_protection(ip_str, host, port, path, 
                                                         host, traced_detections, dns_trace)
                except Exception:
                    # Failed to resolve A records
                    pass
        except Exception:
            # Handle any general errors
            pass
            
        return traced_detections, dns_trace
        
    async def _check_ip_for_protection(self, ip_str: str, original_host: str, port: Optional[int], 
                                       path: str, dns_name: str, detections_list: List, dns_trace: Dict[str, Any]) -> None:
        """
        Check an IP address for L7 protection and update the detections list.
        
        Args:
            ip_str: IP address to check
            original_host: Original hostname for Host header
            port: Port number to check
            path: URL path to test
            dns_name: DNS name that resolved to this IP
            detections_list: List to append detections to
            dns_trace: DNS trace dictionary to update
        """
        try:
            # Build test URL with proper port and path
            for scheme in ["https", "http"]:
                if port:
                    url = f"{scheme}://{ip_str}:{port}{path}"
                else:
                    url = f"{scheme}://{ip_str}{path}"
                
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=3.0),
                        headers={
                            "Host": original_host,
                            "User-Agent": self.user_agent,
                            "Accept": "*/*"
                        },
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(url) as response:
                            headers = dict(response.headers)
                            
                            detections = await self._analyze_response(response, headers, original_host)
                            if detections:
                                # Add detections to the list
                                detections_list.extend(detections)
                                
                                # Record protection in DNS trace
                                if ip_str not in dns_trace["ip_protection"]:
                                    dns_trace["ip_protection"][ip_str] = {
                                        "dns_name": dns_name,
                                        "protections": []
                                    }
                                
                                for detection in detections:
                                    dns_trace["ip_protection"][ip_str]["protections"].append({
                                        "service": detection.service.value,
                                        "confidence": detection.confidence,
                                        "url": url
                                    })
                                return
                except Exception:
                    continue
        except Exception:
            pass

    async def _check_single_ip_for_protection(self, ip_str: str, original_host: str) -> Optional[Dict[str, Any]]:
        """
        Check a single IP address for L7 protection and return result.
        
        Args:
            ip_str: IP address to check
            original_host: Original hostname for Host header
            
        Returns:
            Dictionary with protection information or None
        """
        try:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{ip_str}/"
                
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=3.0),
                        headers={
                            "Host": original_host,
                            "User-Agent": self.user_agent,
                            "Accept": "*/*"
                        },
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(url) as response:
                            headers = dict(response.headers)
                            
                            detections = await self._analyze_response(response, headers, original_host)
                            if detections:
                                return {
                                    "service": detections[0].service.value,
                                    "confidence": detections[0].confidence
                                }
                except Exception:
                    continue
        except Exception:
            pass
        
        return None

    async def get_dns_trace(self, domain: str) -> Dict[str, Any]:
        """
        Get detailed DNS trace information for a domain.
        
        Args:
            domain: Domain to trace
            
        Returns:
            Dictionary with detailed DNS trace information
        """
        dns_trace = {
            "cname_chain": [],
            "resolved_ips": {},
            "ip_protection": {}
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            visited = set()
            
            async def resolve_chain(host, depth=0):
                if depth > 5 or host in visited:
                    return
                
                visited.add(host)
                
                try:
                    # Try to get CNAME records
                    try:
                        cname_answers = resolver.resolve(host, "CNAME")
                        for cname in cname_answers:
                            cname_str = str(cname.target).lower().rstrip('.')
                            
                            dns_trace["cname_chain"].append({
                                "from": host,
                                "to": cname_str,
                                "depth": depth
                            })
                            
                            await resolve_chain(cname_str, depth + 1)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        # No CNAME records, try A records
                        try:
                            a_answers = resolver.resolve(host, "A")
                            dns_trace["resolved_ips"][host] = []
                            
                            for a_record in a_answers:
                                ip = str(a_record)
                                dns_trace["resolved_ips"][host].append(ip)
                                
                                # Check for L7 protection on this IP
                                protection = await self._check_single_ip_for_protection(ip, domain)
                                if protection:
                                    dns_trace["ip_protection"][ip] = {
                                        "service": protection["service"],
                                        "confidence": protection["confidence"],
                                        "origin_host": host
                                    }
                        except Exception:
                            pass
                except Exception:
                    pass
            
            await resolve_chain(domain)
        except Exception as e:
            dns_trace["error"] = str(e)
        
        return dns_trace

    async def _debug_trace(self, host: str) -> None:
        """Debug function to test DNS tracing."""
        try:
            print(f"DEBUG: Starting trace for {host}")
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0

            try:
                # Check for CNAME
                print(f"DEBUG: Checking CNAME for {host}")
                try:
                    cname_answers = resolver.resolve(host, "CNAME")
                    for cname in cname_answers:
                        cname_str = str(cname.target).lower().rstrip('.')
                        print(f"DEBUG: Found CNAME: {host} -> {cname_str}")
                        
                        # Try to resolve the CNAME
                        try:
                            print(f"DEBUG: Resolving CNAME {cname_str}")
                            a_answers = resolver.resolve(cname_str, "A")
                            for a_record in a_answers:
                                ip_str = str(a_record)
                                print(f"DEBUG: CNAME resolved to IP: {cname_str} -> {ip_str}")
                        except Exception as e:
                            print(f"DEBUG: Failed to resolve CNAME {cname_str}: {e}")
                            
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
                    print(f"DEBUG: No CNAME records for {host}: {e}")
                    
                # Check for direct A records
                print(f"DEBUG: Checking A records for {host}")
                try:
                    a_answers = resolver.resolve(host, "A")
                    for a_record in a_answers:
                        ip_str = str(a_record)
                        print(f"DEBUG: Found A record: {host} -> {ip_str}")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
                    print(f"DEBUG: No A records for {host}: {e}")
                    
            except Exception as e:
                print(f"DEBUG: General error in DNS resolution: {e}")
        
        except Exception as e:
            print(f"DEBUG: Unexpected error: {e}")

    async def trace_dns(self, host: str) -> Dict[str, Any]:
        """
        Trace DNS records to their ultimate A records and check for L7 protection on IPs.

        Args:
            host: Target hostname

        Returns:
            Dictionary with DNS trace information
        """
        dns_trace = {
            "cname_chain": [],
            "resolved_ips": [],
            "ip_protection": {}
        }

        try:
            # Initialize resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5

            # Start with the original hostname
            current_host = host
            visited_hosts = set()

            # Follow CNAME chain
            while current_host not in visited_hosts:
                visited_hosts.add(current_host)
                
                try:
                    # Try to get CNAME record
                    cname_answers = resolver.resolve(current_host, "CNAME")
                    for cname in cname_answers:
                        cname_target = str(cname.target).lower().rstrip('.')
                        dns_trace["cname_chain"].append({
                            "source": current_host,
                            "target": cname_target
                        })
                        current_host = cname_target
                        break
                    
                    # If we found a CNAME, continue to follow the chain
                    if current_host != host and current_host not in visited_hosts:
                        continue
                    
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    # No CNAME found, try to get A record
                    try:
                        a_answers = resolver.resolve(current_host, "A")
                        for a_record in a_answers:
                            ip = str(a_record)
                            if ip not in dns_trace["resolved_ips"]:
                                dns_trace["resolved_ips"].append(ip)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                    
                    # End of chain
                    break
                
                except Exception as e:
                    # Log error and break chain
                    dns_trace["error"] = str(e)
                    break
            
            # Check each IP for L7 protection
            for ip in dns_trace["resolved_ips"]:
                try:
                    # Try to detect L7 protection on the IP
                    ip_result = await self.detect(ip)
                    
                    if ip_result.is_protected and ip_result.primary_protection:
                        dns_trace["ip_protection"][ip] = {
                            "service": ip_result.primary_protection.service.value,
                            "confidence": ip_result.primary_protection.confidence,
                            "indicators": ip_result.primary_protection.indicators[:3] if ip_result.primary_protection.indicators else []
                        }
                    else:
                        dns_trace["ip_protection"][ip] = {
                            "service": "none",
                            "confidence": 0.0
                        }
                except Exception as e:
                    dns_trace["ip_protection"][ip] = {
                        "error": str(e)[:100]
                    }
            
        except Exception as e:
            dns_trace["error"] = str(e)
        
        return dns_trace
