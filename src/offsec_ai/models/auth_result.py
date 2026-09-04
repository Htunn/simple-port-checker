"""Auth protocol (OIDC / OAuth 2.0 / SAML) security scan and attack result models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .severity import VulnSeverity
from .vulnerability import BaseVulnerability

# Backward-compatible alias
AuthVulnSeverity = VulnSeverity


class AuthProtocol(str, Enum):
    OIDC = "oidc"
    OAUTH2 = "oauth2"
    SAML = "saml"
    UNKNOWN = "unknown"


class AuthProviderInfo(BaseModel):
    """Fingerprint of the detected auth provider."""

    name: str = ""
    version: str = ""
    issuer: str = ""
    # Discovered endpoint URLs keyed by role
    endpoints: dict[str, str] = Field(default_factory=dict)
    # e.g. ["authorization_code", "implicit", "client_credentials"]
    supported_flows: list[str] = Field(default_factory=list)
    # e.g. ["RS256", "ES256", "none"]
    supported_algorithms: list[str] = Field(default_factory=list)
    pkce_supported: bool = False
    pkce_required: bool = False
    implicit_flow_enabled: bool = False
    state_required: bool = False
    # Raw discovery document or metadata dict
    raw: dict[str, Any] = Field(default_factory=dict)


class AuthVulnerability(BaseVulnerability):
    """A security vulnerability found on an auth endpoint."""

    affected_component: str = ""          # e.g. "/.well-known/openid-configuration"


class AuthScanResult(BaseModel):
    """Complete result of an auth protocol security scan."""

    target: str
    protocol: AuthProtocol = AuthProtocol.UNKNOWN
    provider_info: AuthProviderInfo = Field(default_factory=AuthProviderInfo)
    vulnerabilities: list[AuthVulnerability] = Field(default_factory=list)
    cve_matches: list[AuthVulnerability] = Field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error: str | None = None

    @property
    def critical_vulns(self) -> list[AuthVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == AuthVulnSeverity.CRITICAL]

    @property
    def all_vulns(self) -> list[AuthVulnerability]:
        return self.vulnerabilities + self.cve_matches


# ---------------------------------------------------------------------------
# Attack result models
# ---------------------------------------------------------------------------

class AuthAttackResult(BaseModel):
    """Result of a single auth attack probe."""

    attack_id: str
    target: str
    payload: str = ""                     # Truncated representation of what was sent
    response: str = ""                    # Truncated response body / status
    triggered: bool = False
    severity: AuthVulnSeverity = AuthVulnSeverity.INFO
    title: str = ""
    evidence: str = ""


class AuthAttackReport(BaseModel):
    """Aggregated report from an AuthAttacker run."""

    target: str
    authorized: bool = True
    protocol: AuthProtocol = AuthProtocol.UNKNOWN
    attacks_run: int = 0
    attacks_triggered: int = 0
    results: list[AuthAttackResult] = Field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def triggered_results(self) -> list[AuthAttackResult]:
        return [r for r in self.results if r.triggered]
