"""
L7 Protection Service Signatures for detection.

This module contains signature patterns for detecting various L7 protection
services like WAF, CDN, and other security solutions.
"""

from typing import Dict, List, Any
from ..models.l7_result import L7Protection

# L7 Protection Service Signatures
L7_SIGNATURES: Dict[L7Protection, Dict[str, Any]] = {
    L7Protection.CLOUDFLARE: {
        "headers": {
            "CF-Ray": [r".*"],
            "CF-Cache-Status": [r".*"],
            "CF-Request-ID": [r".*"],
            "Server": [r"cloudflare"],
            "CF-Connecting-IP": [r".*"],
            "CF-Visitor": [r".*"],
            "CF-IPCountry": [r".*"],
            "Set-Cookie": [r"__cfduid", r"cf_clearance"],
        },
        "server": [r"cloudflare"],
        "body": [
            r"Attention Required! \| Cloudflare",
            r"Please enable cookies\.",
            r"Ray ID: [a-f0-9]+",
            r"cloudflare",
            r"CF-RAY",
        ],
        "status_codes": [403, 503, 520, 521, 522, 523, 524, 525, 526, 527, 530],
        "description": "Cloudflare CDN and DDoS Protection",
    },
    L7Protection.AWS_WAF: {
        "headers": {
            "X-Amzn-RequestId": [r".*"],
            "X-Amzn-Trace-Id": [r".*"],
            "X-Cache": [r".*cloudfront.*"],
            "Via": [r".*CloudFront.*"],
            "X-Amz-Cf-Id": [r".*"],
            "X-Amz-Cf-Pop": [r".*"],
            "Server": [r"CloudFront", r"AmazonS3"],
        },
        "server": [r"CloudFront", r"AmazonS3"],
        "body": [
            r"The request could not be satisfied",
            r"CloudFront",
            r"Bad request\. We can't connect to the server for this app or website",
            r"Request blocked\. We can't connect to the server for this app or website",
            r"<title>ERROR: The request could not be satisfied</title>",
        ],
        "status_codes": [403, 503],
        "description": "Amazon Web Services WAF and CloudFront",
    },
    L7Protection.AZURE_WAF: {
        "headers": {
            "X-Azure-Ref": [r".*"],
            "X-Cache": [r".*AZURE.*"],
            "X-Served-By": [r".*azure.*"],
            "X-Msedge-Ref": [r".*"],
            "Server": [r"Microsoft-.*", r"AzureWebSites"],
        },
        "server": [r"Microsoft-.*", r"AzureWebSites"],
        "body": [
            r"Microsoft Azure",
            r"Request blocked by the security policy",
            r"The page cannot be displayed because an internal server error has occurred",
            r"<title>Microsoft Azure Application Gateway",
        ],
        "status_codes": [403, 503],
        "description": "Microsoft Azure Web Application Firewall",
    },
    L7Protection.AZURE_FRONT_DOOR: {
        "headers": {
            "X-Azure-Ref": [r".*"],
            "X-FD-HealthProbe": [r".*"],
            "X-Azure-FDID": [r".*"],
            "X-Cache": [r".*"],
            "X-Azure-DebugInfo": [r".*"],
            "X-MSEdge-Ref": [r".*"],
            "X-Powered-By": [r"ASP.NET"],
            "Server": [r"Microsoft-IIS.*", r"Microsoft-Azure.*", r"Azure.*"]
        },
        "cname": [r".*\.azurefd\.net", r".*\.trafficmanager\.net", r".*\.cloudapp\.azure\.com", 
                r".*\.azureedge\.net", r".*\.azure-api\.net"],
        "dns": [r".*\.z\d+\.azurefd\.net", r".*\.trafficmanager\.net", r".*\.cloudapp\.azure\.com"],
        "body": [
            r"Azure Front Door",
            r"Our services aren't available right now",
            r"We're working hard to restore all services as soon as possible",
            r"Microsoft Azure",
            r"Azure Traffic Manager",
            r"App Service"
        ],
        "status_codes": [403, 404, 503],
        "description": "Microsoft Azure Front Door and Traffic Manager",
    },
    L7Protection.F5_BIG_IP: {
        "headers": {
            "X-WA-Info": [r".*"],
            "BigipServerPool": [r".*"],
            "F5-FullSupport-Id": [r".*"],
            "Set-Cookie": [r"BIGipServer", r"F5_fullSupport", r"LastMRH_Session", r"[0-9]{6}=", r"BIGipServer.*=", r"f5avr.*_session_", r"TS[0-9a-f]{8}="],
            "Server": [r"BigIP", r"F5", r"BIG-IP", r"volt-adc", r"^BigIP$", r"^F5$"],
            "X-envoy-upstream-service-time": [r".*"],
            "Via": [r".*BIG-IP.*", r".*F5.*", r".*Volt.*"],
            "X-F5-Auth-Token": [r".*"],
            "X-F5": [r".*"],
            "X-Cnection": [r"close"]
        },
        "server": [r"BigIP", r"F5", r"BIG-IP", r"volt-adc", r"f5server", r"^BigIP$", r"^F5$"],
        "body": [
            r"The requested URL was rejected\. Please consult with your administrator",
            r"Your support ID is",
            r"BIG-IP",
            r"F5 Networks",
            r"Application Security Manager",
            r"Request Rejected",
            r"HTTP Error 404\. The requested resource is not found\.",
            r"Modified by F5",
            r"Volt ADC",
            r"Volterra",
            r"Access policy denied",
            r"Access to this page is denied by access policy",
            r"SERVERID=",
            r"<title>Error</title>\s*<p>The requested URL was rejected",
            r"The requested URL was rejected",
            r"This request was blocked by the security rules",
        ],
        "status_codes": [302, 400, 403, 404, 503],
        "description": "F5 BIG-IP Application Security Manager",
    },
    L7Protection.AKAMAI: {
        "headers": {
            "X-Akamai-Request-ID": [r".*"],
            "X-Cache": [r".*akamai.*"],
            "X-Cache-Key": [r".*"],
            "X-Check-Cacheable": [r".*"],
            "Akamai-GRN": [r".*"],
            "Server": [r"AkamaiGHost"],
        },
        "server": [r"AkamaiGHost"],
        "body": [
            r"Access Denied",
            r"Reference #[0-9a-f\.]+",
            r"Incident ID",
            r"akamai",
            r"kona site defender",
        ],
        "status_codes": [403],
        "description": "Akamai Web Application Protector",
    },
    L7Protection.IMPERVA: {
        "headers": {
            "X-Iinfo": [r".*"],
            "X-CDN": [r"Incapsula"],
            "Set-Cookie": [r"incap_ses", r"visid_incap"],
            "X-Sucuri-ID": [r".*"],
            "X-Sucuri-Cache": [r".*"],
        },
        "server": [],
        "body": [
            r"Request unsuccessful\. Incapsula incident ID",
            r"Incident ID",
            r"incapsula",
            r"imperva",
            r"Access Denied - Sucuri Website Firewall",
        ],
        "status_codes": [403, 406],
        "description": "Imperva Incapsula WAF",
    },
    L7Protection.SUCURI: {
        "headers": {
            "X-Sucuri-ID": [r".*"],
            "X-Sucuri-Cache": [r".*"],
            "Server": [r"Sucuri.*"],
        },
        "server": [r"Sucuri.*"],
        "body": [
            r"Access Denied - Sucuri Website Firewall",
            r"sucuri\.net",
            r"Questions\? security@sucuri\.net",
            r"Sucuri WebSite Firewall - Access Denied",
            r"Your access to this site has been limited",
        ],
        "status_codes": [403],
        "description": "Sucuri Website Firewall",
    },
    L7Protection.FASTLY: {
        "headers": {
            "X-Served-By": [r"cache-.*fastly"],
            "X-Cache": [r".*fastly.*"],
            "X-Cache-Hits": [r".*"],
            "Fastly-Debug-Digest": [r".*"],
            "Via": [r".*Fastly.*"],
        },
        "server": [],
        "body": [r"Fastly error: unknown domain", r"Request blocked", r"fastly"],
        "status_codes": [403, 503],
        "description": "Fastly Edge Security",
    },
    L7Protection.KEYCDN: {
        "headers": {
            "Server": [r"keycdn-engine"],
            "X-Edge-Location": [r".*"],
            "X-Cache": [r".*keycdn.*"],
        },
        "server": [r"keycdn-engine"],
        "body": [r"KeyCDN", r"Request blocked by KeyCDN"],
        "status_codes": [403],
        "description": "KeyCDN Security",
    },
    L7Protection.MAXCDN: {
        "headers": {
            "Server": [r"NetDNA-cache"],
            "X-HW": [r".*"],
            "X-Cache": [r".*maxcdn.*"],
        },
        "server": [r"NetDNA-cache"],
        "body": [r"MaxCDN", r"Request blocked"],
        "status_codes": [403],
        "description": "MaxCDN Security",
    },
    L7Protection.INCAPSULA: {
        "headers": {
            "X-CDN": [r"Incapsula"],
            "Set-Cookie": [r"incap_ses", r"visid_incap"],
        },
        "server": [],
        "body": [
            r"Request unsuccessful\. Incapsula incident ID",
            r"Incident ID: [0-9]+",
            r"incapsula",
        ],
        "status_codes": [403],
        "description": "Imperva Incapsula (legacy detection)",
    },
    L7Protection.BARRACUDA: {
        "headers": {
            "X-Barracuda-Url": [r".*"],
            "barra": [r".*"],
        },
        "server": [],
        "body": [
            r"Barracuda",
            r"You have been blocked by the Barracuda Web Application Firewall",
            r"BWAF",
        ],
        "status_codes": [403],
        "description": "Barracuda Web Application Firewall",
    },
    L7Protection.FORTINET: {
        "headers": {
            "X-Frame-Options": [r".*fortinet.*"],
        },
        "server": [],
        "body": [
            r"FortiGate",
            r"Fortinet",
            r"Access to this web site is blocked",
            r"Web Page Blocked",
        ],
        "status_codes": [403],
        "description": "Fortinet FortiGate WAF",
    },
    L7Protection.CITRIX: {
        "headers": {
            "X-Citrix-Application": [r".*"],
            "Cneonction": [r".*"],  # Common Citrix typo
            "nnCoection": [r".*"],  # Another Citrix signature
        },
        "server": [],
        "body": [r"Citrix", r"NetScaler", r"Access denied by Citrix"],
        "status_codes": [403],
        "description": "Citrix NetScaler",
    },
    L7Protection.RADWARE: {
        "headers": {
            "X-Sec-Policy": [r".*radware.*"],
        },
        "server": [],
        "body": [
            r"Radware",
            r"AppWall",
            r"Unauthorized Activity Has Been Detected",
            r"blocked by website protection from Radware",
        ],
        "status_codes": [403],
        "description": "Radware AppWall",
    },
}


def get_signature_patterns(protection: L7Protection) -> Dict[str, Any]:
    """
    Get signature patterns for a specific L7 protection service.

    Args:
        protection: L7Protection enum value

    Returns:
        Dictionary containing signature patterns
    """
    return L7_SIGNATURES.get(protection, {})


def get_all_header_patterns() -> Dict[str, List[str]]:
    """
    Get all header patterns from all L7 protection signatures.

    Returns:
        Dictionary mapping header names to lists of patterns
    """
    all_headers = {}

    for signatures in L7_SIGNATURES.values():
        headers = signatures.get("headers", {})
        for header_name, patterns in headers.items():
            if header_name not in all_headers:
                all_headers[header_name] = []
            all_headers[header_name].extend(patterns)

    # Remove duplicates
    for header_name in all_headers:
        all_headers[header_name] = list(set(all_headers[header_name]))

    return all_headers


def get_protection_by_header(header_name: str, header_value: str) -> List[L7Protection]:
    """
    Get possible L7 protections based on a specific header.

    Args:
        header_name: HTTP header name
        header_value: HTTP header value

    Returns:
        List of possible L7Protection services
    """
    import re

    matches = []

    for protection, signatures in L7_SIGNATURES.items():
        headers = signatures.get("headers", {})
        patterns = headers.get(header_name, [])

        for pattern in patterns:
            if re.search(pattern.lower(), header_value.lower()):
                matches.append(protection)
                break

    return matches


def get_critical_headers() -> List[str]:
    """
    Get list of HTTP headers that are most indicative of L7 protection.

    Returns:
        List of critical header names
    """
    critical_headers = [
        "CF-Ray",  # Cloudflare
        "X-Amzn-RequestId",  # AWS
        "X-Azure-Ref",  # Azure
        "X-WA-Info",  # F5
        "X-Akamai-Request-ID",  # Akamai
        "X-Iinfo",  # Imperva
        "X-Sucuri-ID",  # Sucuri
        "X-Served-By",  # Various CDNs
        "X-Cache",  # Various CDNs
        "Via",  # Proxy/CDN indicators
        "Server",  # Server identification
    ]

    return critical_headers


def estimate_protection_confidence(
    headers: Dict[str, str], body: str, status_code: int
) -> Dict[L7Protection, float]:
    """
    Estimate confidence levels for L7 protection detection.

    Args:
        headers: HTTP response headers
        body: HTTP response body
        status_code: HTTP status code

    Returns:
        Dictionary mapping L7Protection to confidence scores (0.0-1.0)
    """
    import re

    confidence_scores = {}

    for protection, signatures in L7_SIGNATURES.items():
        score = 0.0

        # Check headers
        for header_name, patterns in signatures.get("headers", {}).items():
            header_value = headers.get(header_name, "").lower()
            if header_value:
                for pattern in patterns:
                    if re.search(pattern.lower(), header_value):
                        score += 0.3
                        break

        # Check server header
        server_header = headers.get("Server", "").lower()
        for pattern in signatures.get("server", []):
            if re.search(pattern.lower(), server_header):
                score += 0.4
                break

        # Check body patterns
        for pattern in signatures.get("body", []):
            if re.search(pattern, body, re.IGNORECASE):
                score += 0.2
                break

        # Check status codes
        if status_code in signatures.get("status_codes", []):
            score += 0.1

        # Cap at 1.0
        confidence_scores[protection] = min(score, 1.0)

    return confidence_scores
