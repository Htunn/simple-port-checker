"""
Data models for L7 protection detection results.

This module defines the data structures used to represent L7 protection detection results.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from enum import Enum
import json


class L7Protection(Enum):
    """Enumeration of supported L7 protection services."""

    UNKNOWN = "unknown"
    AWS_WAF = "aws_waf"
    AZURE_WAF = "azure_waf"
    AZURE_FRONT_DOOR = "azure_front_door"
    F5_BIG_IP = "f5_big_ip"
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    SUCURI = "sucuri"
    FASTLY = "fastly"
    KEYCDN = "keycdn"
    MAXCDN = "maxcdn"
    INCAPSULA = "incapsula"
    BARRACUDA = "barracuda"
    FORTINET = "fortinet"
    CITRIX = "citrix"
    RADWARE = "radware"


@dataclass
class L7Detection:
    """Represents a single L7 protection detection."""

    service: L7Protection
    confidence: float  # 0.0 to 1.0
    indicators: List[str]  # What indicated this service
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}

    def get_display_name(self) -> str:
        """Get the display name for this service, considering specific details."""
        # Check if there's a custom service name in details
        if self.details and "service_name" in self.details:
            return self.details["service_name"]
        
        # For AWS WAF, check for CloudFront indicators
        if self.service == L7Protection.AWS_WAF:
            cloudfront_indicators = [
                "cloudfront", "x-amz-cf-", "via.*cloudfront", 
                "server: cloudfront", "x-cache.*cloudfront"
            ]
            indicators_text = " ".join(self.indicators).lower()
            if any(indicator in indicators_text for indicator in cloudfront_indicators):
                return "CloudFront - AWS WAF"
            else:
                return "AWS WAF"
        
        # Default to the enum value
        return self.service.value


@dataclass
class L7Result:
    """Represents the complete L7 protection detection result."""

    host: str
    url: str
    detections: List[L7Detection]
    response_headers: Dict[str, str]
    response_time: float
    status_code: Optional[int] = None
    error: Optional[str] = None
    timestamp: Optional[str] = None
    dns_trace: Optional[Dict[str, Any]] = None  # Information about DNS chain and resolved IPs

    def __post_init__(self):
        """Set timestamp if not provided."""
        if self.timestamp is None:
            from datetime import datetime, timezone

            self.timestamp = datetime.now(timezone.utc).isoformat()
        
        if self.dns_trace is None:
            self.dns_trace = {}

    @property
    def primary_protection(self) -> Optional[L7Detection]:
        """Get the protection service with highest confidence."""
        if not self.detections:
            return None
        return max(self.detections, key=lambda d: d.confidence)

    @property
    def is_protected(self) -> bool:
        """Check if any L7 protection was detected."""
        return len(self.detections) > 0 and any(
            d.service != L7Protection.UNKNOWN for d in self.detections
        )

    def get_protection_by_service(self, service: L7Protection) -> Optional[L7Detection]:
        """Get detection result for a specific service."""
        for detection in self.detections:
            if detection.service == service:
                return detection
        return None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "host": self.host,
            "url": self.url,
            "detections": [
                {
                    "service": detection.get_display_name(),
                    "confidence": detection.confidence,
                    "indicators": detection.indicators,
                    "details": detection.details,
                }
                for detection in self.detections
            ],
            "response_headers": self.response_headers,
            "response_time": self.response_time,
            "status_code": self.status_code,
            "error": self.error,
            "timestamp": self.timestamp,
            "dns_trace": self.dns_trace,
            "summary": {
                "is_protected": self.is_protected,
                "primary_protection": (
                    self.primary_protection.get_display_name()
                    if self.primary_protection
                    else None
                ),
                "confidence": (
                    self.primary_protection.confidence
                    if self.primary_protection
                    else 0.0
                ),
                "total_detections": len(self.detections),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save_to_file(self, filename: str) -> None:
        """Save results to JSON file."""
        with open(filename, "w") as f:
            f.write(self.to_json())


@dataclass
class BatchL7Result:
    """Represents results from L7 detection on multiple hosts."""

    results: List[L7Result]
    total_scan_time: float
    timestamp: Optional[str] = None

    def __post_init__(self):
        """Set timestamp if not provided."""
        if self.timestamp is None:
            from datetime import datetime, timezone

            self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def protected_hosts(self) -> List[L7Result]:
        """Get list of hosts with L7 protection detected."""
        return [result for result in self.results if result.is_protected]

    @property
    def unprotected_hosts(self) -> List[L7Result]:
        """Get list of hosts without L7 protection."""
        return [
            result
            for result in self.results
            if not result.is_protected and not result.error
        ]

    @property
    def failed_checks(self) -> List[L7Result]:
        """Get list of failed L7 checks."""
        return [result for result in self.results if result.error]

    def get_protection_summary(self) -> Dict[str, int]:
        """Get summary of protection services detected."""
        summary = {}
        for result in self.protected_hosts:
            if result.primary_protection:
                service = result.primary_protection.get_display_name()
                summary[service] = summary.get(service, 0) + 1
        return summary

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "results": [result.to_dict() for result in self.results],
            "total_scan_time": self.total_scan_time,
            "timestamp": self.timestamp,
            "summary": {
                "total_hosts": len(self.results),
                "protected_hosts": len(self.protected_hosts),
                "unprotected_hosts": len(self.unprotected_hosts),
                "failed_checks": len(self.failed_checks),
                "protection_services": self.get_protection_summary(),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save_to_file(self, filename: str) -> None:
        """Save results to JSON file."""
        with open(filename, "w") as f:
            f.write(self.to_json())
