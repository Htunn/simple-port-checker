"""
Static analysis rules used by PostmanScanner: secret-pattern regexes,
sensitive-endpoint keywords, and verbose-error-disclosure signatures.

Mirrors the rule-based approach used by the other `*_cve_db.py` modules,
but for generic API findings rather than protocol-specific CVEs.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Secret-pattern regexes (same family as a2a_cve_db / mcp_cve_db)
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)api[_\-]?key\s*[:=\"']\s*\S+"),
    re.compile(r"(?i)secret\s*[:=\"']\s*\S+"),
    re.compile(r"(?i)password\s*[:=\"']\s*\S+"),
    re.compile(r"(?i)\btoken\b\s*[:=\"']\s*\S+"),
    re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-_.~+/]+=*"),
    re.compile(r"(?i)private.?key"),
    re.compile(r"AKIA[0-9A-Z]{16}"),            # AWS access key
    re.compile(r"sk-[a-zA-Z0-9]{32,}"),         # OpenAI key
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),         # GitHub PAT
    re.compile(r"xox[baprs]-[0-9a-zA-Z\-]+"),   # Slack token
    re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),  # raw JWT
]

# ---------------------------------------------------------------------------
# Endpoint name/path keywords that suggest a sensitive operation
# ---------------------------------------------------------------------------
SENSITIVE_ENDPOINT_KEYWORDS: list[str] = [
    "admin", "account", "user", "users", "profile", "payment", "billing",
    "order", "orders", "invoice", "delete", "remove", "password", "reset",
    "token", "apikey", "api-key", "secret", "credential", "auth", "login",
    "signup", "register", "wallet", "transfer", "withdraw", "settings",
    "config", "internal", "private", "export", "backup",
]

# ---------------------------------------------------------------------------
# Verbose error / stack-trace disclosure signatures: (description, needle)
# ---------------------------------------------------------------------------
VERBOSE_ERROR_PATTERNS: list[tuple[str, str]] = [
    ("a Python traceback", "traceback (most recent call last)"),
    ("a Java stack trace", "at java."),
    ("a .NET exception", "system.exception"),
    ("a Node.js stack trace", "at node:"),
    ("a SQL error", "sql syntax"),
    ("a SQL error", "sqlstate"),
    ("a database driver error", "odbc driver"),
    ("a debug/dev error page", "django debug"),
    ("a debug/dev error page", "whitelabel error page"),
    ("an internal file path", "/var/www/"),
    ("an internal file path", "c:\\inetpub\\"),
]


def scan_for_secrets(text: str) -> list[str]:
    """Return list of secret-pattern descriptions found in *text*."""
    if not text:
        return []
    found = []
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            found.append(pattern.pattern)
    return found
