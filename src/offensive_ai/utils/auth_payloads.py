"""
Auth protocol (OIDC / OAuth 2.0 / SAML) attack payloads for authorized red-team testing.

IMPORTANT: These payloads are designed SOLELY for authorized penetration
testing. Do NOT use against systems without explicit written authorization.
Unauthorized use may violate computer crime laws.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# OAuth 2.0 redirect_uri open-redirect probes
# Sent as crafted redirect_uri values to detect insufficient validation.
# ---------------------------------------------------------------------------
OPEN_REDIRECT_PAYLOADS: list[dict] = [
    {
        "id": "AUTH-ATK-OR-001",
        "param": "redirect_uri",
        "payload": "https://evil.offensive-ai-probe.invalid/callback",
        "detect_in_response": ["code=", "token=", "id_token=", "access_token="],
        "severity": "high",
        "description": "Open redirect: attacker-controlled domain in redirect_uri",
    },
    {
        "id": "AUTH-ATK-OR-002",
        "param": "redirect_uri",
        "payload": "https://attacker.example.com%40legit.example.com/callback",
        "detect_in_response": ["code=", "token="],
        "severity": "high",
        "description": "Open redirect: URL-encoded @ sign to confuse host parsing",
    },
    {
        "id": "AUTH-ATK-OR-003",
        "param": "redirect_uri",
        "payload": "javascript:alert(1)//",
        "detect_in_response": ["javascript:", "alert("],
        "severity": "critical",
        "description": "Open redirect: javascript: URI scheme bypass",
    },
    {
        "id": "AUTH-ATK-OR-004",
        "param": "redirect_uri",
        "payload": "//evil.offensive-ai-probe.invalid/callback",
        "detect_in_response": ["code=", "token="],
        "severity": "high",
        "description": "Open redirect: protocol-relative URL",
    },
    {
        "id": "AUTH-ATK-OR-005",
        "param": "redirect_uri",
        "payload": "https://legit.example.com/../../../evil.offensive-ai-probe.invalid/callback",
        "detect_in_response": ["code=", "token="],
        "severity": "high",
        "description": "Open redirect: path traversal segments in redirect_uri",
    },
]

# ---------------------------------------------------------------------------
# PKCE bypass probes
# Test whether the server accepts authorization codes without code_verifier.
# ---------------------------------------------------------------------------
PKCE_BYPASS_PAYLOADS: list[dict] = [
    {
        "id": "AUTH-ATK-PK-001",
        "description": "PKCE bypass: omit code_challenge in authorization request",
        "severity": "high",
        "params_to_omit": ["code_challenge", "code_challenge_method"],
        "detect_in_response": ["code=", "error"],
    },
    {
        "id": "AUTH-ATK-PK-002",
        "description": "PKCE bypass: use plain method instead of S256",
        "severity": "medium",
        "override_params": {"code_challenge_method": "plain"},
        "detect_in_response": ["code="],
    },
    {
        "id": "AUTH-ATK-PK-003",
        "description": "PKCE bypass: send empty code_verifier in token exchange",
        "severity": "high",
        "override_params": {"code_verifier": ""},
        "detect_in_response": ["access_token", "id_token"],
    },
]

# ---------------------------------------------------------------------------
# State parameter bypass probes
# Probe for missing or static-state CSRF protection.
# ---------------------------------------------------------------------------
STATE_BYPASS_PAYLOADS: list[dict] = [
    {
        "id": "AUTH-ATK-ST-001",
        "description": "State bypass: omit state parameter entirely",
        "severity": "high",
        "params_to_omit": ["state"],
        "detect_in_response": ["code=", "token="],
    },
    {
        "id": "AUTH-ATK-ST-002",
        "description": "State bypass: use empty state value",
        "severity": "medium",
        "override_params": {"state": ""},
        "detect_in_response": ["code=", "token="],
    },
    {
        "id": "AUTH-ATK-ST-003",
        "description": "State bypass: use predictable static state",
        "severity": "medium",
        "override_params": {"state": "AAAAAAAAAAAAAAAA"},
        "detect_in_response": ["code=", "state=AAAAAAAAAAAAAAAA"],
    },
]

# ---------------------------------------------------------------------------
# Scope escalation probes
# Attempt to request scopes beyond what the client is permitted.
# ---------------------------------------------------------------------------
SCOPE_ESCALATION_PAYLOADS: list[dict] = [
    {
        "id": "AUTH-ATK-SC-001",
        "description": "Scope escalation: request admin scope",
        "severity": "high",
        "override_params": {"scope": "openid profile email admin"},
        "detect_in_response": ["admin", "access_token"],
    },
    {
        "id": "AUTH-ATK-SC-002",
        "description": "Scope escalation: request offline_access for persistent tokens",
        "severity": "medium",
        "override_params": {"scope": "openid offline_access"},
        "detect_in_response": ["refresh_token"],
    },
    {
        "id": "AUTH-ATK-SC-003",
        "description": "Scope escalation: request all scopes wildcard",
        "severity": "high",
        "override_params": {"scope": "*"},
        "detect_in_response": ["access_token"],
    },
]

# ---------------------------------------------------------------------------
# JWT algorithm confusion probes
# Submit tokens with alg=none or algorithm confusion payloads.
# ---------------------------------------------------------------------------
JWT_ALG_PAYLOADS: list[dict] = [
    {
        "id": "AUTH-ATK-JA-001",
        "description": "JWT alg=none: unsigned token accepted",
        "severity": "critical",
        # Header: {"alg":"none","typ":"JWT"} — base64url encoded
        "alg_header": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
        "detect_in_response": ["200", "access_token", "sub", "email"],
    },
    {
        "id": "AUTH-ATK-JA-002",
        "description": "JWT algorithm confusion: RS256 key used as HS256 HMAC secret",
        "severity": "critical",
        "alg_header": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "detect_in_response": ["200", "sub", "access_token"],
    },
]

# ---------------------------------------------------------------------------
# Authorization code replay / reuse probes
# ---------------------------------------------------------------------------
CODE_REUSE_PAYLOADS: list[dict] = [
    {
        "id": "AUTH-ATK-CR-001",
        "description": "Authorization code reuse: replay code after first exchange",
        "severity": "high",
        "detect_in_response": ["access_token", "id_token"],
    },
]

# ---------------------------------------------------------------------------
# SAML XML Signature Wrapping (XSW) payloads
# Sent to SAML ACS endpoints to test for XSW vulnerabilities.
# ---------------------------------------------------------------------------
SAML_XSW_PAYLOADS: list[dict] = [
    {
        "id": "AUTH-ATK-XW-001",
        "description": "SAML XSW1: forge assertion wrapped inside valid signed Response",
        "severity": "critical",
        "detect_in_response": ["samlp:Response", "200", "success", "authenticated"],
        "xsw_variant": "XSW1",
    },
    {
        "id": "AUTH-ATK-XW-002",
        "description": "SAML XSW2: move valid signature to sibling, forge NameID",
        "severity": "critical",
        "detect_in_response": ["200", "success", "authenticated"],
        "xsw_variant": "XSW2",
    },
    {
        "id": "AUTH-ATK-XW-003",
        "description": "SAML comment injection: XML comment in NameID value",
        "severity": "critical",
        "detect_in_response": ["200", "success", "authenticated"],
        "xsw_variant": "comment_inject",
    },
]

# ---------------------------------------------------------------------------
# JWKS algorithm confusion (deep mode)
# ---------------------------------------------------------------------------
JWKS_CONFUSION_PAYLOADS: list[dict] = [
    {
        "id": "AUTH-ATK-JC-001",
        "description": "JWKS confusion: use RS256 public key as HS256 HMAC secret",
        "severity": "critical",
        "detect_in_response": ["200", "sub", "access_token", "authenticated"],
    },
]
