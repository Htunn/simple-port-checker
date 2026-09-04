"""
OpenClaw personal AI assistant CVE and misconfiguration database.

Sources:
- OpenClaw security documentation (https://docs.openclaw.ai/gateway/security)
- OpenClaw exposure runbook (https://docs.openclaw.ai/gateway/security/exposure-runbook)
- OpenClaw sandboxing docs (https://docs.openclaw.ai/gateway/sandboxing)
- OpenClaw configuration reference (https://docs.openclaw.ai/gateway/configuration)
- Common misconfiguration patterns in self-hosted AI gateway deployments

This database is used by OpenClawScanner to match discovered configurations
against known CVEs and misconfigurations. All entries are for defensive/
detection purposes only.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OpenClawCVEEntry:
    vuln_id: str
    cve_id: str | None
    severity: str          # critical / high / medium / low / info
    title: str
    description: str
    affected_versions: list[str] = field(default_factory=list)  # version prefixes
    check_path: str = ""   # HTTP path used to detect this issue
    remediation: str = ""
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Known CVEs, advisories, and common misconfigurations for OpenClaw
# ---------------------------------------------------------------------------
OPENCLAW_CVE_DB: list[OpenClawCVEEntry] = [
    OpenClawCVEEntry(
        vuln_id="OCL-ADV-001",
        cve_id=None,
        severity="critical",
        title="Unauthenticated OpenClaw Gateway API Exposure",
        description=(
            "The OpenClaw Gateway REST API is accessible without authentication. "
            "An unauthenticated attacker can enumerate sessions, retrieve message "
            "history, send messages on behalf of the gateway owner, and control "
            "channel connections. The /api/v1/ endpoint tree is fully accessible."
        ),
        check_path="/api/v1/status",
        remediation=(
            "Enable gateway authentication in ~/.openclaw/openclaw.json under "
            "'gateway.auth'. Bind the gateway to 127.0.0.1 for local-only access. "
            "Use a reverse proxy with authentication before public exposure. "
            "Follow the Gateway exposure runbook: "
            "https://docs.openclaw.ai/gateway/security/exposure-runbook"
        ),
        references=[
            "https://docs.openclaw.ai/gateway/security",
            "https://docs.openclaw.ai/gateway/security/exposure-runbook",
            "https://docs.openclaw.ai/gateway/configuration",
        ],
    ),
    OpenClawCVEEntry(
        vuln_id="OCL-ADV-002",
        cve_id=None,
        severity="high",
        title="Open DM Policy Without Allowlist (Prompt Injection via DM)",
        description=(
            "The OpenClaw gateway is configured with dmPolicy='open' combined with "
            "a wildcard '*' in the channel allowFrom list. This allows any user on "
            "the connected messaging channel (Telegram/WhatsApp/Discord/Slack/etc.) "
            "to send DMs that are processed by the AI agent. Untrusted DM input "
            "can be used for prompt injection attacks against the agent."
        ),
        check_path="/api/v1/config",
        remediation=(
            "Use the default dmPolicy='pairing' which requires sender approval via "
            "'openclaw pairing approve <channel> <code>'. Audit allowFrom lists to "
            "remove wildcards. Run 'openclaw doctor' to surface risky DM policies."
        ),
        references=[
            "https://docs.openclaw.ai/gateway/security",
            "https://github.com/openclaw/openclaw/blob/main/SECURITY.md",
        ],
    ),
    OpenClawCVEEntry(
        vuln_id="OCL-ADV-003",
        cve_id=None,
        severity="high",
        title="Agent Running Outside Sandbox Mode (Unrestricted Tool Access)",
        description=(
            "The OpenClaw gateway is running multi-agent or channel sessions "
            "without sandbox mode enabled. Non-main sessions have full tool access "
            "including browser, canvas, file system, and process execution. "
            "Malicious actors who can interact with the agent via any connected "
            "channel can execute arbitrary commands on the host."
        ),
        check_path="/api/v1/sessions",
        remediation=(
            "Set 'agents.defaults.sandbox.mode: non-main' in openclaw.json to "
            "sandbox all non-main sessions. Use Docker as the default sandbox backend. "
            "Restrict allowed tools: allow bash/read/write, deny browser/canvas/cron. "
            "Reference: https://docs.openclaw.ai/gateway/sandboxing"
        ),
        references=[
            "https://docs.openclaw.ai/gateway/sandboxing",
            "https://docs.openclaw.ai/gateway/configuration",
        ],
    ),
    OpenClawCVEEntry(
        vuln_id="OCL-ADV-004",
        cve_id=None,
        severity="high",
        title="WebSocket Gateway Endpoint Exposed Without Authentication",
        description=(
            "The OpenClaw gateway WebSocket endpoint is accessible without "
            "authentication. Attackers can establish persistent WebSocket "
            "connections to the gateway, impersonate nodes (iOS/Android/Windows), "
            "inject messages into active sessions, or hijack agent sessions."
        ),
        check_path="/",
        remediation=(
            "Enable gateway-level token authentication before WebSocket upgrade. "
            "Restrict WebSocket access to trusted IP ranges using a reverse proxy. "
            "Bind to localhost unless remote node access is explicitly required."
        ),
        references=[
            "https://docs.openclaw.ai/gateway/security",
            "https://docs.openclaw.ai/nodes",
        ],
    ),
    OpenClawCVEEntry(
        vuln_id="OCL-ADV-005",
        cve_id=None,
        severity="medium",
        title="Health and Status Endpoint Information Disclosure",
        description=(
            "The /health and /status endpoints are publicly accessible and disclose "
            "internal gateway metadata including version information, connected "
            "channels, active sessions, and system health details. This information "
            "aids attackers in fingerprinting the deployment and targeting version-"
            "specific vulnerabilities."
        ),
        check_path="/health",
        remediation=(
            "Place the gateway behind an authenticated reverse proxy before public "
            "exposure. Restrict /health and /status to internal networks only. "
            "Consider disabling informational endpoints in production deployments."
        ),
        references=[
            "https://docs.openclaw.ai/gateway/security/exposure-runbook",
        ],
    ),
    OpenClawCVEEntry(
        vuln_id="OCL-ADV-006",
        cve_id=None,
        severity="medium",
        title="Webhook Automation Endpoint SSRF Risk",
        description=(
            "The OpenClaw webhook automation endpoint accepts arbitrary URLs for "
            "outbound webhook delivery. Without URL allowlisting, an attacker who "
            "can configure webhooks (via exposed API) can leverage the gateway as "
            "an SSRF proxy to reach internal network resources."
        ),
        check_path="/api/v1/webhooks",
        remediation=(
            "Restrict webhook URLs to a known allowlist. Validate that webhook "
            "targets do not resolve to RFC 1918 private address ranges. "
            "Require authentication to manage webhook configurations."
        ),
        references=[
            "https://docs.openclaw.ai/automation/webhook",
        ],
    ),
    OpenClawCVEEntry(
        vuln_id="OCL-ADV-007",
        cve_id=None,
        severity="medium",
        title="Session History and Message Log Exposure",
        description=(
            "The /api/v1/sessions/history endpoint returns full conversation logs "
            "without requiring authentication. Session histories may contain "
            "sensitive information, secrets, credentials, personal data, and "
            "private communications processed by the AI assistant."
        ),
        check_path="/api/v1/sessions/history",
        remediation=(
            "Require authentication for all /api/v1/sessions/* endpoints. "
            "Implement session-scoped access controls so users can only access "
            "their own session histories."
        ),
        references=[
            "https://docs.openclaw.ai/concepts/session",
        ],
    ),
    OpenClawCVEEntry(
        vuln_id="OCL-ADV-008",
        cve_id=None,
        severity="medium",
        title="Model API Key Leakage via Debug/Config Endpoint",
        description=(
            "The gateway configuration or debug endpoint may expose LLM provider "
            "API keys (OpenAI, Anthropic, etc.) in plaintext. These keys grant "
            "full access to the victim's AI provider account and can be used to "
            "generate content, incur costs, or exfiltrate training data."
        ),
        check_path="/api/v1/config",
        remediation=(
            "Never expose configuration endpoints publicly. Redact API keys in all "
            "API responses. Store keys in environment variables rather than config "
            "files accessible via API. Audit all API endpoints for credential exposure."
        ),
        references=[
            "https://docs.openclaw.ai/concepts/models",
        ],
    ),
    OpenClawCVEEntry(
        vuln_id="OCL-ADV-009",
        cve_id=None,
        severity="low",
        title="OpenClaw Gateway Version Fingerprinting",
        description=(
            "The gateway version is disclosed in HTTP response headers or the "
            "/health endpoint. Version information enables targeted exploitation "
            "of known version-specific vulnerabilities."
        ),
        check_path="/health",
        remediation=(
            "Suppress version information in response headers. Use a reverse proxy "
            "that strips server identification headers before public exposure."
        ),
        references=[
            "https://docs.openclaw.ai/gateway",
        ],
    ),
    OpenClawCVEEntry(
        vuln_id="OCL-ADV-010",
        cve_id=None,
        severity="info",
        title="OpenClaw Instance Detected (Fingerprint)",
        description=(
            "An OpenClaw gateway instance was detected at this target. The gateway "
            "is a personal AI assistant that has access to messaging channels, "
            "file systems, and LLM provider APIs. Any misconfiguration may have "
            "significant privacy and security implications."
        ),
        check_path="/health",
        remediation=(
            "Ensure the gateway is not publicly exposed without authentication. "
            "Follow the official security hardening guide before remote exposure."
        ),
        references=[
            "https://docs.openclaw.ai/gateway/security",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Fingerprint signatures that identify an OpenClaw instance
# ---------------------------------------------------------------------------
OPENCLAW_FINGERPRINTS: list[dict] = [
    {"header": "x-openclaw-version", "match_type": "present"},
    {"header": "x-openclaw-gateway", "match_type": "present"},
    {"header": "server", "match_type": "contains", "value": "openclaw"},
    {"body_key": "gateway", "match_type": "present"},
    {"body_key": "openclaw_version", "match_type": "present"},
    {"body_key": "version", "match_type": "contains", "value": "openclaw"},
    {"body_key": "status", "match_type": "contains", "value": "openclaw"},
    # OpenClaw 2026.x gateway: /health returns {"ok":true,"status":"live"}
    # combined with HTML title "OpenClaw Control" on /
    {"body_key": "ok", "match_type": "present"},
    {"html_title": "OpenClaw Control", "match_type": "present"},
]

# Paths to probe during fingerprinting
OPENCLAW_PROBE_PATHS: list[str] = [
    "/health",
    "/status",
    "/api/v1/status",
    "/api/v1/health",
    "/gateway/status",
    "/",
]

# Paths to probe for authenticated API access
OPENCLAW_API_PATHS: list[str] = [
    "/api/v1/status",
    "/api/v1/sessions",
    "/api/v1/sessions/history",
    "/api/v1/config",
    "/api/v1/channels",
    "/api/v1/webhooks",
    "/api/v1/agents",
    "/api/v1/nodes",
]

# Default OpenClaw gateway port
OPENCLAW_DEFAULT_PORT: int = 18789


def match_cves(
    version: str | None = None,
    accessible_paths: list[str] | None = None,
) -> list[OpenClawCVEEntry]:
    """Return CVE entries that match the discovered version and accessible paths."""
    matched: list[OpenClawCVEEntry] = []
    accessible_paths = accessible_paths or []

    for entry in OPENCLAW_CVE_DB:
        # Version matching
        if entry.affected_versions and version:
            if not any(version.startswith(v) for v in entry.affected_versions):
                continue

        # Path-based matching: include if the check_path was found accessible
        if entry.check_path and entry.check_path in accessible_paths:
            matched.append(entry)
        elif not entry.check_path:
            matched.append(entry)

    return matched
