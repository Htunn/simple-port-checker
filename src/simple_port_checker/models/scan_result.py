"""
Data models for port scanning results.

This module defines the data structures used to represent port scan results.
"""

from dataclasses import dataclass
from typing import List, Optional
import json


@dataclass
class PortResult:
    """Represents the result of scanning a single port."""

    port: int
    is_open: bool
    service: str = "unknown"
    banner: str = ""
    error: Optional[str] = None
    response_time: Optional[float] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "port": self.port,
            "is_open": self.is_open,
            "service": self.service,
            "banner": self.banner,
            "error": self.error,
            "response_time": self.response_time,
        }


@dataclass
class ScanResult:
    """Represents the complete scan result for a host."""

    host: str
    ip_address: Optional[str]
    ports: List[PortResult]
    scan_time: float
    error: Optional[str] = None
    timestamp: Optional[str] = None

    def __post_init__(self):
        """Set timestamp if not provided."""
        if self.timestamp is None:
            from datetime import datetime, timezone

            self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def open_ports(self) -> List[PortResult]:
        """Get list of open ports only."""
        return [port for port in self.ports if port.is_open]

    @property
    def closed_ports(self) -> List[PortResult]:
        """Get list of closed ports only."""
        return [port for port in self.ports if not port.is_open and not port.error]

    @property
    def error_ports(self) -> List[PortResult]:
        """Get list of ports with errors."""
        return [port for port in self.ports if port.error]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "host": self.host,
            "ip_address": self.ip_address,
            "ports": [port.to_dict() for port in self.ports],
            "scan_time": self.scan_time,
            "error": self.error,
            "timestamp": self.timestamp,
            "summary": {
                "total_ports": len(self.ports),
                "open_ports": len(self.open_ports),
                "closed_ports": len(self.closed_ports),
                "error_ports": len(self.error_ports),
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
class BatchScanResult:
    """Represents results from scanning multiple hosts."""

    results: List[ScanResult]
    total_scan_time: float
    timestamp: Optional[str] = None

    def __post_init__(self):
        """Set timestamp if not provided."""
        if self.timestamp is None:
            from datetime import datetime

            self.timestamp = datetime.utcnow().isoformat()

    @property
    def successful_scans(self) -> List[ScanResult]:
        """Get list of successful scans (no errors)."""
        return [result for result in self.results if not result.error]

    @property
    def failed_scans(self) -> List[ScanResult]:
        """Get list of failed scans."""
        return [result for result in self.results if result.error]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "results": [result.to_dict() for result in self.results],
            "total_scan_time": self.total_scan_time,
            "timestamp": self.timestamp,
            "summary": {
                "total_hosts": len(self.results),
                "successful_scans": len(self.successful_scans),
                "failed_scans": len(self.failed_scans),
                "total_open_ports": sum(
                    len(r.open_ports) for r in self.successful_scans
                ),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save_to_file(self, filename: str) -> None:
        """Save results to JSON file."""
        with open(filename, "w") as f:
            f.write(self.to_json())
