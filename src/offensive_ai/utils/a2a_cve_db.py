"""
A2A (Agent-to-Agent) protocol security CVE and known-vulnerability database.

Sources:
- A2A Protocol Specification (a2a-protocol.org) v1.0.0
- Common misconfigurations in A2A agent deployments
- OWASP API Security Top 10 / LLM Top 10 applied to agentic systems
- Research on agent card spoofing, SSRF via push notifications, task IDOR

This database is used by A2AScanner to classify discovered weaknesses.
All entries are for defensive/detection purposes only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re


@dataclass
class A2ACVEEntry:
    vuln_id: str
    cve_id: str | None
    severity: str          # critical / high / medium / low / info
    title: str
    description: str
    affected_servers: list[str] = field(default_factory=list)   # name substrings
    affected_versions: list[str] = field(default_factory=list)  # version prefixes
    check_path: str = ""   # HTTP path used during scanning
    remediation: str = ""
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Dangerous keywords that should not appear in skill descriptions
# ---------------------------------------------------------------------------
DANGEROUS_SKILL_KEYWORDS: list[str] = [
    "exec", "execve", "execvp",
    "shell", "bash", "sh ", "/bin/sh", "/bin/bash", "zsh", "fish",
    "cmd.exe", "powershell", "pwsh",
    "eval", "subprocess", "popen", "system(",
    "rm -", "rmdir", "del ", "format c:",
    "sudo ", "su -", "doas",
    "kubectl", "helm", "terraform",
    "docker run", "docker exec",
    "aws ", "gcloud ", "az ",
    "os.system", "os.popen", "__import__",
    "ignore previous", "disregard instructions", "new instruction:",
    "override:", "jailbreak",
]

# ---------------------------------------------------------------------------
# Secret-pattern regexes (shared with scan_for_secrets)
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)api[_\-]?key\s*[:=]\s*\S+"),
    re.compile(r"(?i)secret\s*[:=]\s*\S+"),
    re.compile(r"(?i)password\s*[:=]\s*\S+"),
    re.compile(r"(?i)token\s*[:=]\s*\S+"),
    re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-_.~+/]+=*"),
    re.compile(r"(?i)private.?key"),
    re.compile(r"AKIA[0-9A-Z]{16}"),            # AWS access key
    re.compile(r"sk-[a-zA-Z0-9]{32,}"),         # OpenAI key
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),         # GitHub PAT
    re.compile(r"xox[baprs]-[0-9a-zA-Z\-]+"),   # Slack token
]

# ---------------------------------------------------------------------------
# Known advisories / misconfigurations
# ---------------------------------------------------------------------------
A2A_CVE_DB: list[A2ACVEEntry] = [
    A2ACVEEntry(
        vuln_id="A2A-ADV-2025-001",
        cve_id=None,
        severity="high",
        title="No Security Schemes Declared in Agent Card",
        description=(
            "The Agent Card's 'securitySchemes' field is absent or empty, meaning the "
            "agent has not declared any authentication requirement. Per A2A spec §7, agents "
            "MUST authenticate every request. Without a declared scheme, clients cannot know "
            "what credentials to present, and misconfigured agents may accept unauthenticated "
            "requests."
        ),
        affected_servers=[],
        remediation=(
            "Declare at least one security scheme in 'securitySchemes' (Bearer, OAuth2, "
            "OpenID Connect, mTLS, or API key). Reference the scheme in 'security'. "
            "Enforce it on all A2A endpoints — not just the Agent Card endpoint."
        ),
        references=[
            "https://a2a-protocol.org/specification/#7-authentication-and-authorization",
            "https://a2a-protocol.org/topics/enterprise-ready/",
        ],
    ),
    A2ACVEEntry(
        vuln_id="A2A-ADV-2025-002",
        cve_id=None,
        severity="high",
        title="Unauthenticated A2A Task Operations",
        description=(
            "The A2A agent accepts task requests (POST /message:send or equivalent JSON-RPC "
            "SendMessage) without valid authentication credentials. Any anonymous client can "
            "create tasks, read task history, and retrieve artifacts — exposing internal "
            "agent capabilities and data to the public."
        ),
        affected_servers=[],
        remediation=(
            "Require valid Bearer tokens (OAuth2/OIDC) or API keys on all task operations. "
            "Return HTTP 401 / JSON-RPC -32700 for unauthenticated requests. "
            "Follow A2A spec §7.4 Server Authentication Responsibilities."
        ),
        references=[
            "https://a2a-protocol.org/specification/#74-server-authentication-responsibilities",
            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        ],
    ),
    A2ACVEEntry(
        vuln_id="A2A-ADV-2025-003",
        cve_id=None,
        severity="medium",
        title="Agent Card Lacks JWS Signature",
        description=(
            "The Agent Card served at /.well-known/agent-card.json does not include a "
            "'signatures' field with a JSON Web Signature (JWS). Without a signature, "
            "a man-in-the-middle attacker can tamper with the card — substituting malicious "
            "endpoints, removing security schemes, or altering skill descriptions — and clients "
            "have no cryptographic means to detect the tampering."
        ),
        affected_servers=[],
        remediation=(
            "Sign the Agent Card using JWS (RFC 7515) with an ES256 or RS256 key. "
            "Publish the public key at a JWKS endpoint referenced in the card's 'jku' field. "
            "Clients SHOULD verify at least one signature before trusting the card. "
            "See A2A spec §8.4 Agent Card Signing."
        ),
        references=[
            "https://a2a-protocol.org/specification/#84-agent-card-signing",
            "https://tools.ietf.org/html/rfc7515",
        ],
    ),
    A2ACVEEntry(
        vuln_id="A2A-ADV-2025-004",
        cve_id=None,
        severity="critical",
        title="Credentials or Secrets Embedded in Agent Card",
        description=(
            "The Agent Card contains patterns matching credentials, API keys, tokens, or "
            "other secrets in its fields (name, description, skill descriptions, provider URL, "
            "or documentation URL). These are served publicly to any client that fetches "
            "/.well-known/agent-card.json — no authentication required."
        ),
        affected_servers=[],
        remediation=(
            "Remove all secrets from Agent Card fields immediately. "
            "Store credentials in environment variables or a secret manager. "
            "Perform secret scanning in CI/CD pipelines before publishing Agent Cards. "
            "Rotate any exposed credentials."
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/312.html",
            "https://a2a-protocol.org/specification/#133-extended-agent-card-access-control",
        ],
    ),
    A2ACVEEntry(
        vuln_id="A2A-ADV-2025-005",
        cve_id=None,
        severity="critical",
        title="Dangerous Skill Keywords Indicating High-Risk Capabilities",
        description=(
            "One or more agent skills have descriptions containing keywords associated with "
            "shell execution, code evaluation, file system write, or privilege escalation "
            "(e.g. 'exec', 'shell', 'bash', 'rm', 'sudo', 'kubectl'). An attacker who can "
            "send crafted messages to the agent may trigger these capabilities via prompt "
            "injection, achieving remote code execution or destructive data loss."
        ),
        affected_servers=[],
        remediation=(
            "Apply the principle of least privilege. Remove shell/exec/file-delete "
            "capabilities unless strictly required. Wrap dangerous capabilities behind "
            "human-in-the-loop confirmation (TASK_STATE_AUTH_REQUIRED). "
            "Sanitize and validate all inputs before passing to system calls."
        ),
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    ),
    A2ACVEEntry(
        vuln_id="A2A-ADV-2025-006",
        cve_id=None,
        severity="high",
        title="Push Notifications Enabled — SSRF Attack Surface",
        description=(
            "The Agent Card declares 'capabilities.pushNotifications: true'. This means the "
            "agent will make outbound HTTP POST requests to arbitrary webhook URLs supplied "
            "by clients. Without validation of webhook URLs, an attacker can register webhooks "
            "pointing to internal services (metadata endpoints, internal APIs, cloud IMDS), "
            "causing Server-Side Request Forgery (SSRF) and internal network enumeration."
        ),
        affected_servers=[],
        remediation=(
            "Validate webhook URLs before delivery: reject private IP ranges "
            "(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), link-local "
            "(169.254.0.0/16), and localhost. Implement URL allowlists. "
            "Follow A2A spec §13.2 Push Notification Security."
        ),
        references=[
            "https://a2a-protocol.org/specification/#132-push-notification-security",
            "https://owasp.org/www-project-top-10/#a10-server-side-request-forgery-ssrf",
        ],
    ),
    A2ACVEEntry(
        vuln_id="A2A-ADV-2025-007",
        cve_id=None,
        severity="high",
        title="Plaintext HTTP Endpoint Declared (No TLS)",
        description=(
            "One or more supported interfaces in the Agent Card use a plain HTTP URL "
            "(http://) rather than HTTPS. A2A spec §7.1 states that production deployments "
            "MUST use encrypted communication. Traffic over plain HTTP is susceptible to "
            "interception, credential theft, and message tampering."
        ),
        affected_servers=[],
        remediation=(
            "Serve all A2A endpoints exclusively over HTTPS (TLS 1.2+, preferably TLS 1.3). "
            "Enforce HSTS. Redirect HTTP to HTTPS. "
            "Update Agent Card 'supportedInterfaces' to use https:// URLs only."
        ),
        references=[
            "https://a2a-protocol.org/specification/#71-protocol-security",
            "https://cwe.mitre.org/data/definitions/319.html",
        ],
    ),
    A2ACVEEntry(
        vuln_id="A2A-ADV-2025-008",
        cve_id=None,
        severity="high",
        title="Extended Agent Card Accessible Without Authentication",
        description=(
            "The agent declares 'capabilities.extendedAgentCard: true', indicating a richer "
            "authenticated card is available at GET /extendedAgentCard. However, the endpoint "
            "responds successfully to unauthenticated requests, potentially exposing additional "
            "skills, internal service URLs, rate limits, or privileged capabilities to "
            "anonymous clients."
        ),
        affected_servers=[],
        check_path="/extendedAgentCard",
        remediation=(
            "Enforce authentication on GET /extendedAgentCard using the schemes declared in "
            "'securitySchemes'. Return HTTP 401 for unauthenticated requests. "
            "Follow A2A spec §13.3 Extended Agent Card Access Control."
        ),
        references=[
            "https://a2a-protocol.org/specification/#133-extended-agent-card-access-control",
            "https://a2a-protocol.org/specification/#3111-get-extended-agent-card",
        ],
    ),
    A2ACVEEntry(
        vuln_id="A2A-ADV-2025-009",
        cve_id=None,
        severity="low",
        title="No A2A Protocol Version Enforcement",
        description=(
            "The agent does not validate or enforce the A2A-Version request header. "
            "Per A2A spec §3.6, agents MUST return VersionNotSupportedError for unsupported "
            "versions. Without version enforcement, clients may silently downgrade to an "
            "older protocol version with fewer security controls, and the agent loses "
            "visibility into client version distribution."
        ),
        affected_servers=[],
        remediation=(
            "Validate the A2A-Version header on every request. "
            "Return JSON-RPC -32009 (VersionNotSupportedError) for unsupported versions. "
            "Document supported protocol versions in the Agent Card."
        ),
        references=[
            "https://a2a-protocol.org/specification/#36-versioning",
        ],
    ),
    A2ACVEEntry(
        vuln_id="A2A-ADV-2025-010",
        cve_id=None,
        severity="medium",
        title="Task Listing Without Authorization Scoping (IDOR Risk)",
        description=(
            "The GET /tasks (or ListTasks JSON-RPC) endpoint returns results without "
            "scoping to the authenticated caller's authorization boundary. An authenticated "
            "user may be able to enumerate tasks belonging to other users or tenants, "
            "disclosing sensitive task history, artifact contents, and contextIds. "
            "A2A spec §13.1 and §3.1.4 require strict scope limitation."
        ),
        affected_servers=[],
        check_path="/tasks",
        remediation=(
            "Implement per-identity authorization scoping on all task listing and retrieval "
            "operations. Never return tasks outside the authenticated client's authorized "
            "boundary. Follow A2A spec §13.1 Data Access and Authorization Scoping."
        ),
        references=[
            "https://a2a-protocol.org/specification/#131-data-access-and-authorization-scoping",
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Matching and helper functions
# ---------------------------------------------------------------------------

def match_cves(
    server_name: str | None = None,
    accessible_paths: list[str] | None = None,
) -> list[A2ACVEEntry]:
    """Match CVE entries against the discovered A2A agent profile."""
    matched: list[A2ACVEEntry] = []
    accessible_paths = accessible_paths or []

    for entry in A2A_CVE_DB:
        # Server-name substring matching (case-insensitive)
        if entry.affected_servers and server_name:
            if not any(s.lower() in server_name.lower() for s in entry.affected_servers):
                continue

        # Path-based matching
        if entry.check_path:
            if entry.check_path in accessible_paths:
                matched.append(entry)
        else:
            matched.append(entry)

    return matched


def scan_for_secrets(text: str) -> list[str]:
    """Return list of secret-pattern descriptions found in *text*."""
    found = []
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            found.append(pattern.pattern)
    return found


def scan_for_dangerous_keywords(text: str) -> list[str]:
    """Return dangerous keywords found in *text* (case-insensitive)."""
    lower = text.lower()
    return [kw for kw in DANGEROUS_SKILL_KEYWORDS if kw.lower() in lower]
