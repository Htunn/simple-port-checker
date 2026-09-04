"""Postman collection-driven API security scan/attack result models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .severity import VulnSeverity
from .vulnerability import BaseVulnerability

# Backward-compatible alias
PostmanVulnSeverity = VulnSeverity


class PostmanAuthInfo(BaseModel):
    """Parsed auth block from a Postman request."""
    type: str = "noauth"          # "noauth", "bearer", "basic", "apikey", "oauth2", ...
    raw: dict[str, Any] = Field(default_factory=dict)


class PostmanEndpoint(BaseModel):
    """A single flattened request extracted from a Postman collection."""
    name: str = ""
    folder_path: str = ""          # e.g. "Users > Create"
    method: str = "GET"
    url: str = ""                  # resolved URL (variables substituted where possible)
    raw_url: str = ""              # original {{var}} form
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    path_params: list[str] = Field(default_factory=list)   # ":id" style segments detected in raw_url
    body: str = ""
    body_mode: str = ""            # raw / urlencoded / formdata / graphql / none
    auth: PostmanAuthInfo = Field(default_factory=PostmanAuthInfo)
    description: str = ""
    unresolved_variables: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class PostmanEndpointResult(BaseModel):
    """Baseline probe result for one endpoint (passive scan)."""
    endpoint: PostmanEndpoint
    status_code: int | None = None
    response_snippet: str = ""
    response_headers: dict[str, str] = Field(default_factory=dict)
    error: str = ""
    duration: float = 0.0


class PostmanVulnerability(BaseVulnerability):
    """A security finding on a Postman-collection-derived endpoint."""
    endpoint: str = ""              # "METHOD url" label
    owasp_api_category: str = ""    # e.g. "API1:2023 Broken Object Level Authorization"


class PostmanScanResult(BaseModel):
    """Full passive scan result for a Postman collection."""
    collection_name: str = ""
    target_override: str = ""
    endpoints_total: int = 0
    endpoints_tested: int = 0
    endpoint_results: list[PostmanEndpointResult] = Field(default_factory=list)
    vulnerabilities: list[PostmanVulnerability] = Field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None

    @property
    def critical_vulns(self) -> list[PostmanVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == PostmanVulnSeverity.CRITICAL]

    @property
    def high_vulns(self) -> list[PostmanVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == PostmanVulnSeverity.HIGH]

    @property
    def has_critical(self) -> bool:
        return bool(self.critical_vulns)

    model_config = {"populate_by_name": True}


class PostmanAttackResult(BaseModel):
    """Result of a single attack probe against a Postman-derived endpoint."""
    attack_id: str
    endpoint: str = ""
    attack_type: str = ""       # "auth_bypass", "bola", "mass_assignment", "injection", "ssrf"
    payload: str = ""
    response: str = ""
    triggered: bool = False
    severity: PostmanVulnSeverity = PostmanVulnSeverity.INFO
    title: str = ""
    description: str = ""
    evidence: str = ""
    error: str = ""
    llm_confidence: float | None = None
    llm_reasoning: str = ""


class PostmanAttackReport(BaseModel):
    """Aggregated results from an authorized Postman-collection attack session."""
    collection_name: str = ""
    target_override: str = ""
    authorized: bool = True
    attacks_run: int = 0
    attacks_triggered: int = 0
    results: list[PostmanAttackResult] = Field(default_factory=list)
    exploit_chain_summary: str = ""   # LLM-synthesized narrative linking exploitable endpoints
    scan_duration: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    authorization_note: str = (
        "This attack was performed under explicit authorization. "
        "Unauthorized use of this tool is illegal."
    )

    @property
    def successful_attacks(self) -> list[PostmanAttackResult]:
        return [r for r in self.results if r.triggered]
