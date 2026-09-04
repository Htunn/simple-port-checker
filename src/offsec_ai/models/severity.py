"""Shared vulnerability severity enum used across all scan result models."""

from __future__ import annotations

from enum import Enum


class VulnSeverity(str, Enum):
    """Canonical severity level for all protocol-specific vulnerability findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
