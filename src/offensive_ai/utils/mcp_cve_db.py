"""
MCP security CVE and known-vulnerability database.

Sources:
- Published MCP security advisories (2024-2025)
- Common misconfigurations found in MCP server implementations
- Research on tool-poisoning, path traversal, and prompt injection via MCP

This database is used by MCPScanner to match fingerprinted servers against
known vulnerabilities. All entries are for defensive/detection purposes only.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MCPCVEEntry:
    vuln_id: str
    cve_id: str | None
    severity: str          # critical / high / medium / low
    title: str
    description: str
    affected_servers: list[str] = field(default_factory=list)   # server name substrings
    affected_versions: list[str] = field(default_factory=list)  # version prefixes
    remediation: str = ""
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Known CVEs and advisories
# ---------------------------------------------------------------------------
MCP_CVE_DB: list[MCPCVEEntry] = [
    MCPCVEEntry(
        vuln_id="MCP-ADV-2024-001",
        cve_id=None,
        severity="critical",
        title="Tool-Poisoning via Malicious Tool Descriptions",
        description=(
            "MCP servers that serve tool definitions with hidden instructions "
            "embedded in descriptions can manipulate LLM clients into performing "
            "unauthorized actions (tool-poisoning attack). An attacker-controlled "
            "MCP server can inject 'invisible' instructions targeting the connecting LLM."
        ),
        affected_servers=[],  # Applies to all MCP servers
        affected_versions=[],
        remediation=(
            "Clients must display all tool descriptions to users before use. "
            "Implement tool-description allow-lists or signature verification. "
            "Never auto-trust tool descriptions from third-party servers."
        ),
        references=[
            "https://invariantlabs.ai/research/mcp-security",
            "https://www.pillar.security/blog/the-mcp-security-problem",
        ],
    ),
    MCPCVEEntry(
        vuln_id="MCP-ADV-2024-002",
        cve_id=None,
        severity="high",
        title="Unauthenticated MCP Endpoint Exposure",
        description=(
            "MCP servers deployed without authentication allow any client to "
            "enumerate tools, resources, and prompts, and invoke them without "
            "authorization. This can expose internal systems, files, and APIs."
        ),
        affected_servers=[],
        affected_versions=[],
        remediation=(
            "Require OAuth 2.0 or API key authentication on all MCP endpoints. "
            "Follow the MCP authorization specification (2025-03-26 draft). "
            "Do not expose MCP servers on public networks without authentication."
        ),
        references=[
            "https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/",
        ],
    ),
    MCPCVEEntry(
        vuln_id="MCP-ADV-2024-003",
        cve_id=None,
        severity="high",
        title="Path Traversal via Resource URI",
        description=(
            "MCP servers exposing file-system resources without URI sanitization "
            "may allow path traversal attacks (e.g. '../../etc/passwd') enabling "
            "disclosure of arbitrary files on the server."
        ),
        affected_servers=["filesystem", "file-server", "file_server", "local-files"],
        affected_versions=[],
        remediation=(
            "Validate and canonicalize all resource URIs. Enforce a strict "
            "allowed-path allowlist. Reject URIs containing '..', null bytes, or "
            "absolute paths outside the configured root."
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    ),
    MCPCVEEntry(
        vuln_id="MCP-ADV-2024-004",
        cve_id=None,
        severity="critical",
        title="Command Injection via Tool Arguments",
        description=(
            "MCP tools that execute shell commands using unsanitized arguments "
            "allow command injection. An LLM can be manipulated into passing "
            "malicious arguments to these tools."
        ),
        affected_servers=["shell", "bash", "exec", "run", "command", "terminal"],
        affected_versions=[],
        remediation=(
            "Never pass user/LLM-supplied data directly to shell commands. "
            "Use allow-lists for commands and arguments. "
            "Use parameterized subprocess calls (not shell=True in Python). "
            "Remove shell-execution tools unless strictly necessary."
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    ),
    MCPCVEEntry(
        vuln_id="MCP-ADV-2024-005",
        cve_id=None,
        severity="high",
        title="Secrets Exposed in Tool or Resource Descriptions",
        description=(
            "MCP server tool/resource/prompt descriptions contain embedded "
            "credentials, API keys, or internal URLs that are exposed to any "
            "connecting LLM client."
        ),
        affected_servers=[],
        affected_versions=[],
        remediation=(
            "Audit all tool/resource/prompt descriptions for sensitive data. "
            "Store credentials in environment variables or secret managers. "
            "Implement description content scanning in CI/CD pipelines."
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/312.html",
        ],
    ),
    MCPCVEEntry(
        vuln_id="MCP-ADV-2025-001",
        cve_id=None,
        severity="medium",
        title="Overly Broad Tool Scope (Excessive Agency via MCP)",
        description=(
            "MCP servers expose tools with capabilities far exceeding what the "
            "use-case requires (e.g. full filesystem read/write, unrestricted HTTP "
            "requests, database admin). This amplifies the impact of prompt "
            "injection attacks targeting the connected LLM."
        ),
        affected_servers=[],
        affected_versions=[],
        remediation=(
            "Apply principle of least privilege. Expose only the minimum set of "
            "tools needed. Scope tool permissions to specific paths, hosts, or "
            "operations. Require human confirmation for high-impact tool calls."
        ),
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
    ),
    MCPCVEEntry(
        vuln_id="MCP-ADV-2025-002",
        cve_id=None,
        severity="medium",
        title="Prompt Injection via MCP Tool Response",
        description=(
            "An MCP tool returns data containing embedded prompt injection "
            "instructions (e.g. from a web page, file, or database), which "
            "the LLM client then executes as instructions."
        ),
        affected_servers=[],
        affected_versions=[],
        remediation=(
            "LLM clients must treat MCP tool responses as untrusted data. "
            "Implement output sanitization before feeding tool results back into "
            "the LLM context. Use system-prompt defenses against indirect injection."
        ),
        references=[
            "https://invariantlabs.ai/research/mcp-security",
        ],
    ),
    MCPCVEEntry(
        vuln_id="MCP-ADV-2025-003",
        cve_id=None,
        severity="high",
        title="Rug-Pull: Dynamic Tool Redefinition After Approval",
        description=(
            "Some MCP servers allow tools to change their definitions after the "
            "client has approved them (rug-pull). An attacker-controlled server "
            "can gain approval under a benign description and then substitute a "
            "malicious implementation."
        ),
        affected_servers=[],
        affected_versions=[],
        remediation=(
            "Pin tool definitions at approval time. Re-verify tool descriptions "
            "on each invocation. Use cryptographic signatures for tool definitions "
            "from trusted servers."
        ),
        references=[
            "https://www.pillar.security/blog/the-mcp-security-problem",
        ],
    ),
]

# ---------------------------------------------------------------------------
# Dangerous keyword patterns for tool/resource/prompt description scanning
# ---------------------------------------------------------------------------
DANGEROUS_TOOL_KEYWORDS: list[str] = [
    # Instruction injection
    "ignore previous", "disregard", "forget your instructions",
    "new instructions", "override", "jailbreak",
    # Shell/system access
    "execute", "shell", "bash", "cmd.exe", "powershell", "eval(",
    "subprocess", "os.system", "__import__",
    # Credential/secret patterns
    "password", "api_key", "apikey", "secret", "token", "bearer",
    "sk-", "pk-", "aws_secret",
    # Sensitive paths
    "/etc/passwd", "/etc/shadow", "../../", "C:\\Windows\\System32",
]

SECRET_PATTERNS: list[str] = [
    "password", "passwd", "api_key", "apikey", "api-key",
    "secret", "token", "bearer", "authorization",
    "sk-", "pk-", "ghp_", "glpat-", "aws_access", "aws_secret",
    "private_key", "-----BEGIN",
]


def match_cves(server_name: str, server_version: str) -> list[MCPCVEEntry]:
    """Match a fingerprinted server against the CVE database."""
    name_lower = server_name.lower()
    version_lower = server_version.lower()
    matched: list[MCPCVEEntry] = []

    for entry in MCP_CVE_DB:
        # Entries with no affected_servers apply universally
        if not entry.affected_servers:
            matched.append(entry)
            continue
        for affected in entry.affected_servers:
            if affected.lower() in name_lower:
                matched.append(entry)
                break

    return matched


def scan_for_secrets(text: str) -> list[str]:
    """Return list of secret patterns found in text."""
    text_lower = text.lower()
    return [p for p in SECRET_PATTERNS if p in text_lower]


def scan_for_dangerous_keywords(text: str) -> list[str]:
    """Return list of dangerous keywords found in text."""
    text_lower = text.lower()
    return [k for k in DANGEROUS_TOOL_KEYWORDS if k in text_lower]
