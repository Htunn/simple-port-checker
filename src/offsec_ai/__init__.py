"""
offsec-ai — Offensive-security toolkit for authorized red-team engagements.

Capabilities:
- Port scanning with banner grabbing (async, configurable concurrency)
- L7/WAF/CDN detection with DNS tracing
- mTLS (Mutual TLS) authentication checking
- SSL/TLS certificate chain analysis and validation
- Hybrid identity / Azure AD / ADFS detection
- OWASP Top 10 2021/2025 web vulnerability scanning
- AI/LLM OWASP Top 10 2025 black-box endpoint probing
- MCP (Model Context Protocol) endpoint security scanning and CVE matching
- MCP endpoint active attack module (requires explicit authorization)
- Kubernetes cluster black-box security scanner (OWASP K8s Top 10 2025)
- Kubernetes attacker module for authorized red-team engagements
- OpenClaw personal AI gateway security scanner and attacker
- Kubernetes cluster black-box security scanner (OWASP K8s Top 10 2025)
- Kubernetes attacker module for authorized red-team engagements
- OIDC / OAuth 2.0 / SAML endpoint security scanner and CVE matching
- OIDC / OAuth 2.0 / SAML active attack module (requires explicit authorization)
- Security header analysis and grading
- Multi-format reporting (PDF, JSON, CSV)
- Rich CLI interface with progress bars
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("offsec-ai")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "unknown"

__author__ = "Johny htunn"
__email__ = "htunnthuthu.linux@gmail.com"
__license__ = "MIT"

from .core.port_scanner import PortChecker
from .core.l7_detector import L7Detector, L7Protection
from .core.mtls_checker import MTLSChecker
from .core.cert_analyzer import CertificateAnalyzer
from .core.hybrid_identity_checker import HybridIdentityChecker, HybridIdentityResult
from .core.owasp_scanner import OwaspScanner
from .core.security_headers import SecurityHeaderChecker
from .core.ai_owasp_scanner import LLMOwaspScanner
from .core.mcp_scanner import MCPScanner
from .core.mcp_attacker import MCPAttacker
from .core.a2a_scanner import A2AScanner
from .core.a2a_attacker import A2AAttacker
from .core.postman_scanner import PostmanScanner
from .core.postman_attacker import PostmanAttacker
from .core.llm_judge import LLMJudge
from .exceptions import (
    AuthorizationRequired,
    ConfigError,
    NetworkError,
    OffsecError,
    ScanError,
    TargetUnreachableError,
)
from .config import OffsecConfig, get_config, reset_config
from .log_config import (
    configure_logging,
    new_correlation_id,
    get_correlation_id,
    audit_log,
)
from .models.scan_result import ScanResult, PortResult
from .models.l7_result import L7Result
from .models.mtls_result import MTLSResult, CertificateInfo
from .models.owasp_result import OwaspScanResult, OwaspFinding, OwaspCategoryResult, SeverityLevel
from .models.ai_owasp_result import LLMScanResult, LLMFinding, LLMCategoryResult, LLMSeverity
from .models.mcp_result import (
    MCPScanResult,
    MCPTool,
    MCPResource,
    MCPVulnerability,
    MCPAttackReport,
    MCPAttackResult,
    MCPTransport,
)
from .models.a2a_result import (
    A2AScanResult,
    A2AAgentCard,
    A2ASkill,
    A2AVulnerability,
    A2AAttackReport,
    A2AAttackResult,
    A2AVulnSeverity,
)
from .models.postman_result import (
    PostmanScanResult,
    PostmanEndpoint,
    PostmanVulnerability,
    PostmanAttackReport,
    PostmanAttackResult,
    PostmanVulnSeverity,
)
from .core.k8s_scanner import K8sScanner
from .core.k8s_attacker import K8sAttacker
from .core.auth_scanner import AuthScanner
from .core.auth_attacker import AuthAttacker
from .models.auth_result import (
    AuthScanResult,
    AuthAttackReport,
    AuthAttackResult,
    AuthVulnerability,
    AuthProtocol,
    AuthVulnSeverity,
)
from .models.k8s_result import (
    K8sScanResult,
    K8sAttackReport,
    K8sAttackResult,
    K8sVulnerability,
    K8sVulnSeverity,
    K8sComponent,
    K8sExposedComponent,
    K8sServerInfo,
)

__all__ = [
    # Original scanners
    "PortChecker",
    "L7Detector",
    "L7Protection",
    "MTLSChecker",
    "CertificateAnalyzer",
    "HybridIdentityChecker",
    "HybridIdentityResult",
    "OwaspScanner",
    "SecurityHeaderChecker",
    # New AI/LLM scanners
    "LLMOwaspScanner",
    "LLMJudge",
    # New MCP modules
    "MCPScanner",
    "MCPAttacker",
    # A2A (Agent-to-Agent) modules
    "A2AScanner",
    "A2AAttacker",
    # Postman collection-driven API modules
    "PostmanScanner",
    "PostmanAttacker",
    # Exceptions
    "OffsecError",
    "ScanError",
    "ConfigError",
    "NetworkError",
    "TargetUnreachableError",
    "AuthorizationRequired",
    # Configuration
    "OffsecConfig",
    "get_config",
    "reset_config",
    # Logging utilities
    "configure_logging",
    "new_correlation_id",
    "get_correlation_id",
    "audit_log",
    # Original result models
    "ScanResult",
    "PortResult",
    "L7Result",
    "MTLSResult",
    "CertificateInfo",
    "OwaspScanResult",
    "OwaspFinding",
    "OwaspCategoryResult",
    "SeverityLevel",
    # New AI OWASP result models
    "LLMScanResult",
    "LLMFinding",
    "LLMCategoryResult",
    "LLMSeverity",
    # New MCP result models
    "MCPScanResult",
    "MCPTool",
    "MCPResource",
    "MCPVulnerability",
    "MCPAttackReport",
    "MCPAttackResult",
    "MCPTransport",
    # A2A result models
    "A2AScanResult",
    "A2AAgentCard",
    "A2ASkill",
    "A2AVulnerability",
    "A2AAttackReport",
    "A2AAttackResult",
    "A2AVulnSeverity",
    # Postman collection result models
    "PostmanScanResult",
    "PostmanEndpoint",
    "PostmanVulnerability",
    "PostmanAttackReport",
    "PostmanAttackResult",
    "PostmanVulnSeverity",
    # Kubernetes modules
    "K8sScanner",
    "K8sAttacker",
    # Kubernetes result models
    "K8sScanResult",
    "K8sAttackReport",
    "K8sAttackResult",
    "K8sVulnerability",
    "K8sVulnSeverity",
    "K8sComponent",
    "K8sExposedComponent",
    "K8sServerInfo",
    # Auth (OIDC / OAuth2 / SAML) modules
    "AuthScanner",
    "AuthAttacker",
    # Auth result models
    "AuthScanResult",
    "AuthAttackReport",
    "AuthAttackResult",
    "AuthVulnerability",
    "AuthProtocol",
    "AuthVulnSeverity",
]
