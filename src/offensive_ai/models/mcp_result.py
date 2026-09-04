"""MCP (Model Context Protocol) security scan result models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .severity import VulnSeverity
from .vulnerability import BaseVulnerability

# Backward-compatible alias
MCPVulnSeverity = VulnSeverity


class MCPTransport(str, Enum):
    HTTP = "http"
    SSE = "sse"
    STDIO = "stdio"


class MCPTool(BaseModel):
    """A tool advertised by the MCP server."""
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    # Security-relevant flags
    has_dangerous_keywords: bool = False
    dangerous_keywords_found: list[str] = Field(default_factory=list)


class MCPResource(BaseModel):
    """A resource (file/data source) exposed by the MCP server."""
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str = ""


class MCPPrompt(BaseModel):
    """A prompt template exposed by the MCP server."""
    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = Field(default_factory=list)


class MCPServerInfo(BaseModel):
    """Fingerprint of the MCP server returned during initialization."""
    name: str = ""
    version: str = ""
    protocol_version: str = ""
    capabilities: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)


class MCPVulnerability(BaseVulnerability):
    """A security vulnerability found on an MCP endpoint."""
    affected_component: str = ""   # e.g. tool name, resource URI


class MCPAuthPosture(BaseModel):
    """Authentication posture of the MCP server."""
    requires_auth: bool = False
    auth_type: str = ""          # "bearer", "basic", "oauth2", "none"
    unauthenticated_access: bool = False
    auth_bypass_possible: bool = False
    notes: str = ""


class MCPScanResult(BaseModel):
    """Full security scan result for a single MCP endpoint."""
    target: str
    transport: MCPTransport = MCPTransport.HTTP
    server_info: MCPServerInfo = Field(default_factory=MCPServerInfo)
    tools: list[MCPTool] = Field(default_factory=list)
    resources: list[MCPResource] = Field(default_factory=list)
    prompts: list[MCPPrompt] = Field(default_factory=list)
    auth_posture: MCPAuthPosture = Field(default_factory=MCPAuthPosture)
    vulnerabilities: list[MCPVulnerability] = Field(default_factory=list)
    cve_matches: list[MCPVulnerability] = Field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None

    @property
    def critical_vulns(self) -> list[MCPVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == MCPVulnSeverity.CRITICAL]

    @property
    def high_vulns(self) -> list[MCPVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == MCPVulnSeverity.HIGH]

    @property
    def has_critical(self) -> bool:
        return bool(self.critical_vulns)

    @property
    def all_vulns(self) -> list[MCPVulnerability]:
        return self.vulnerabilities + self.cve_matches

    model_config = {"populate_by_name": True}


class MCPAttackResult(BaseModel):
    """Result of a single attack probe against an MCP endpoint."""
    attack_id: str
    target: str
    tool_name: str = ""
    resource_uri: str = ""
    payload: str = ""
    response: str = ""
    triggered: bool = False
    severity: MCPVulnSeverity = MCPVulnSeverity.INFO
    title: str = ""
    description: str = ""
    evidence: str = ""


class MCPAttackReport(BaseModel):
    """Aggregated results from an authorized MCP attack session."""
    target: str
    authorized: bool = True
    transport: MCPTransport = MCPTransport.HTTP
    attacks_run: int = 0
    attacks_triggered: int = 0
    results: list[MCPAttackResult] = Field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    authorization_note: str = (
        "This attack was performed under explicit authorization. "
        "Unauthorized use of this tool is illegal."
    )

    @property
    def triggered_results(self) -> list[MCPAttackResult]:
        return [r for r in self.results if r.triggered]
