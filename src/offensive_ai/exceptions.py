"""
offensive-ai exception hierarchy.

All package-level exceptions inherit from ``OffensiveAIError`` so callers can
catch the base class for broad handling or a specific subtype for precise
error recovery.

Usage::

    from offensive_ai.exceptions import OffensiveAIError, AuthorizationRequired, ScanError

    try:
        result = await scanner.scan(target)
    except TargetUnreachableError as exc:
        log.warning("host down: %s", exc)
    except ScanError as exc:
        log.error("scan failed: %s", exc)
"""

from __future__ import annotations


class OffensiveAIError(Exception):
    """Base exception for all offensive-ai errors."""


class ScanError(OffensiveAIError):
    """Raised when a scan operation encounters an unexpected error."""


class ConfigError(OffensiveAIError):
    """Raised for invalid or missing configuration (bad values, missing keys)."""


class NetworkError(OffensiveAIError):
    """Raised for network-layer failures: DNS resolution, connection refused, timeout."""


class TargetUnreachableError(NetworkError):
    """Raised when the target host cannot be reached after all retries."""


class AuthorizationRequired(OffensiveAIError):
    """
    Raised when an active attack is attempted without explicit authorization.

    Consolidates the individual ``AuthorizationRequired`` classes previously
    defined in ``mcp_attacker`` and ``openclaw_attacker``.

    Args:
        module: Human-readable name of the attack module requesting authorization.
    """

    def __init__(self, module: str = "offensive-ai attack module") -> None:
        super().__init__(
            f"{module} requires explicit authorization. "
            "Pass authorized=True only when you have written permission to test the target."
        )
        self.module = module
