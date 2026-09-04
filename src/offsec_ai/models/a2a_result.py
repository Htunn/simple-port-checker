"""A2A (Agent-to-Agent) protocol security scan result models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .severity import VulnSeverity
from .vulnerability import BaseVulnerability

# Backward-compatible alias
A2AVulnSeverity = VulnSeverity


class A2ASkill(BaseModel):
    """A skill advertised by an A2A agent in its Agent Card."""
    id: str
    name: str = ""
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    input_modes: list[str] = Field(default_factory=list)
    output_modes: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)
    # Security-relevant flags
    has_dangerous_keywords: bool = False
    dangerous_keywords_found: list[str] = Field(default_factory=list)


class A2ACapabilities(BaseModel):
    """Capabilities block from an Agent Card."""
    streaming: bool = False
    push_notifications: bool = False
    extended_agent_card: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)


class A2AAgentCard(BaseModel):
    """Parsed Agent Card discovered at /.well-known/agent-card.json."""
    name: str = ""
    description: str = ""
    version: str = ""
    provider_organization: str = ""
    provider_url: str = ""
    documentation_url: str = ""
    icon_url: str = ""
    supported_interfaces: list[dict[str, Any]] = Field(default_factory=list)
    security_schemes: dict[str, Any] = Field(default_factory=dict)
    security: list[dict[str, Any]] = Field(default_factory=list)
    capabilities: A2ACapabilities = Field(default_factory=A2ACapabilities)
    skills: list[A2ASkill] = Field(default_factory=list)
    default_input_modes: list[str] = Field(default_factory=list)
    default_output_modes: list[str] = Field(default_factory=list)
    is_signed: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)


class A2AServerInfo(BaseModel):
    """Fingerprint / discovery info for the A2A agent."""
    protocol_version: str = ""
    supported_bindings: list[str] = Field(default_factory=list)
    endpoint_url: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class A2AAuthPosture(BaseModel):
    """Authentication posture of the A2A agent."""
    requires_auth: bool = False
    scheme_names: list[str] = Field(default_factory=list)
    auth_type: str = ""         # "bearer", "oauth2", "oidc", "apiKey", "none"
    unauthenticated_access: bool = False
    auth_bypass_possible: bool = False
    notes: str = ""


class A2AVulnerability(BaseVulnerability):
    """A security vulnerability found on an A2A endpoint."""
    affected_component: str = ""


class A2AScanResult(BaseModel):
    """Full security scan result for a single A2A agent endpoint."""
    target: str
    agent_card: A2AAgentCard = Field(default_factory=A2AAgentCard)
    server_info: A2AServerInfo = Field(default_factory=A2AServerInfo)
    auth_posture: A2AAuthPosture = Field(default_factory=A2AAuthPosture)
    vulnerabilities: list[A2AVulnerability] = Field(default_factory=list)
    cve_matches: list[A2AVulnerability] = Field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None

    @property
    def critical_vulns(self) -> list[A2AVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == A2AVulnSeverity.CRITICAL]

    @property
    def high_vulns(self) -> list[A2AVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == A2AVulnSeverity.HIGH]

    @property
    def has_critical(self) -> bool:
        return bool(self.critical_vulns)

    @property
    def all_vulns(self) -> list[A2AVulnerability]:
        return self.vulnerabilities + self.cve_matches

    model_config = {"populate_by_name": True}


class A2AAttackResult(BaseModel):
    """Result of a single attack probe against an A2A endpoint."""
    attack_id: str
    target: str
    attack_type: str = ""       # "auth_bypass", "ssrf", "message_injection", "task_enum", "jsonrpc"
    payload: str = ""
    response: str = ""
    triggered: bool = False
    severity: A2AVulnSeverity = A2AVulnSeverity.INFO
    title: str = ""
    description: str = ""
    evidence: str = ""
    error: str = ""


class A2AAttackReport(BaseModel):
    """Aggregated results from an authorized A2A attack session."""
    target: str
    authorized: bool = True
    attacks_run: int = 0
    attacks_triggered: int = 0
    results: list[A2AAttackResult] = Field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    authorization_note: str = (
        "This attack was performed under explicit authorization. "
        "Unauthorized use of this tool is illegal."
    )

    @property
    def successful_attacks(self) -> list[A2AAttackResult]:
        return [r for r in self.results if r.triggered]
