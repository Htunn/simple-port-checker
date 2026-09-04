"""Kubernetes security scan and attack result models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .severity import VulnSeverity
from .vulnerability import BaseVulnerability

# Backward-compatible alias
K8sVulnSeverity = VulnSeverity


class K8sComponent(str, Enum):
    API_SERVER = "api_server"
    KUBELET = "kubelet"
    ETCD = "etcd"
    SCHEDULER = "scheduler"
    CONTROLLER_MANAGER = "controller_manager"
    KUBE_PROXY = "kube_proxy"
    CADVISOR = "cadvisor"
    DASHBOARD = "dashboard"


class K8sExposedComponent(BaseModel):
    """A Kubernetes component found accessible on the network."""
    component: K8sComponent
    port: int
    accessible: bool = False
    version: str = ""
    anonymous_access: bool = False
    tls: bool = False
    evidence: str = ""


class K8sServerInfo(BaseModel):
    """Kubernetes cluster version and component fingerprint."""
    version: str = ""
    git_version: str = ""
    platform: str = ""
    go_version: str = ""
    build_date: str = ""
    components_found: list[K8sComponent] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class K8sVulnerability(BaseVulnerability):
    """A single Kubernetes security finding."""
    owasp_id: str                     # K01–K10
    component: K8sComponent | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class K8sScanResult(BaseModel):
    """Full result of a Kubernetes cluster security scan."""
    target: str
    ports: list[int] = Field(default_factory=list)
    scan_duration: float = 0.0
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    error: str = ""

    # Discovery
    is_kubernetes: bool = False
    server_info: K8sServerInfo = Field(default_factory=K8sServerInfo)
    exposed_components: list[K8sExposedComponent] = Field(default_factory=list)

    # Findings
    vulnerabilities: list[K8sVulnerability] = Field(default_factory=list)
    cve_matches: list[str] = Field(default_factory=list)

    @property
    def critical_vulns(self) -> list[K8sVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == K8sVulnSeverity.CRITICAL]

    @property
    def high_vulns(self) -> list[K8sVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == K8sVulnSeverity.HIGH]

    @property
    def owasp_coverage(self) -> list[str]:
        """Return the distinct OWASP K8s Top 10 IDs found in vulnerabilities."""
        return sorted({v.owasp_id for v in self.vulnerabilities})


# ---------------------------------------------------------------------------
# Attack report models
# ---------------------------------------------------------------------------

class K8sAttackResult(BaseModel):
    """Result of a single Kubernetes attack probe."""
    attack_id: str
    owasp_id: str
    description: str
    severity: K8sVulnSeverity
    succeeded: bool = False
    payload_sent: str = ""
    response_snippet: str = ""
    evidence: str = ""
    error: str = ""


class K8sAttackReport(BaseModel):
    """Full report from a Kubernetes authorized red-team attack session."""
    target: str
    authorized: bool = True
    attack_duration: float = 0.0
    attacked_at: datetime = Field(default_factory=datetime.utcnow)
    mode: str = "safe"

    scan_result: K8sScanResult | None = None
    attack_results: list[K8sAttackResult] = Field(default_factory=list)

    @property
    def successful_attacks(self) -> list[K8sAttackResult]:
        return [r for r in self.attack_results if r.succeeded]

    @property
    def critical_successes(self) -> list[K8sAttackResult]:
        return [
            r for r in self.attack_results
            if r.succeeded and r.severity == K8sVulnSeverity.CRITICAL
        ]
