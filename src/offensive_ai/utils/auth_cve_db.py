"""
Auth protocol (OIDC / OAuth 2.0 / SAML) CVE and known-vulnerability database.

Sources:
- Published CVEs affecting Spring Security OAuth, Shibboleth, OneLogin, Keycloak, and others
- IETF / OAuth WG security best-current-practice documents (RFC 9700, RFC 9449, etc.)
- OWASP Testing Guide – Testing for OAuth Weaknesses
- Research on XML Signature Wrapping, JWT confusion, and PKCE bypass

This database is used by AuthScanner to match detected security weaknesses
against known CVEs and advisories. All entries are for defensive / detection
purposes only.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AuthCVEEntry:
    vuln_id: str
    cve_id: str | None
    severity: str                          # critical / high / medium / low
    title: str
    description: str
    affected_providers: list[str] = field(default_factory=list)  # provider name substrings; empty = universal
    check_condition: str = ""              # key that must appear in detected_issues to match
    remediation: str = ""
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Known CVEs and advisories
# ---------------------------------------------------------------------------
AUTH_CVE_DB: list[AuthCVEEntry] = [
    # ------------------------------------------------------------------
    # OAuth 2.0 / OIDC — universal misconfigurations
    # ------------------------------------------------------------------
    AuthCVEEntry(
        vuln_id="AUTH-ADV-003",
        cve_id=None,
        severity="high",
        title="PKCE Not Enforced on Public Clients",
        description=(
            "The authorization server does not require PKCE (Proof Key for Code Exchange) "
            "for public clients. An attacker who intercepts the authorization code can "
            "exchange it for tokens without knowing the original code_verifier. "
            "PKCE is mandatory for public clients per RFC 7636 and OAuth 2.1."
        ),
        affected_providers=[],
        check_condition="pkce_not_required",
        remediation=(
            "Require code_challenge / code_verifier for all public clients. "
            "Reject authorization requests from public clients that omit code_challenge. "
            "Upgrade to OAuth 2.1 which mandates PKCE."
        ),
        references=[
            "https://datatracker.ietf.org/doc/html/rfc7636",
            "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1",
        ],
    ),
    AuthCVEEntry(
        vuln_id="AUTH-ADV-004",
        cve_id=None,
        severity="medium",
        title="Implicit Flow Enabled (Deprecated)",
        description=(
            "The authorization server advertises support for the implicit grant type "
            "(response_type=token). Implicit flow delivers access tokens directly in "
            "the redirect URI fragment, where they are exposed to the browser history "
            "and referrer headers. The implicit flow was deprecated in OAuth 2.0 Security "
            "Best Current Practice (RFC 9700) and removed from OAuth 2.1."
        ),
        affected_providers=[],
        check_condition="implicit_flow_enabled",
        remediation=(
            "Disable the implicit grant type. Migrate clients to the authorization code flow "
            "with PKCE. Remove 'token' from the response_types_supported list."
        ),
        references=[
            "https://datatracker.ietf.org/doc/html/rfc9700",
            "https://oauth.net/2/grant-types/implicit/",
        ],
    ),
    AuthCVEEntry(
        vuln_id="AUTH-ADV-005",
        cve_id=None,
        severity="high",
        title="State Parameter Not Required — CSRF Possible",
        description=(
            "The authorization server does not enforce the 'state' parameter in "
            "authorization requests. Without state validation, an attacker can craft "
            "a malicious authorization link and force a victim's browser to complete "
            "the OAuth flow, resulting in CSRF / login-CSRF attacks."
        ),
        affected_providers=[],
        check_condition="state_not_required",
        remediation=(
            "Require and validate the state parameter on every authorization request. "
            "Alternatively use PKCE (which binds the code to the initiating session) "
            "or OpenID Connect nonce validation."
        ),
        references=[
            "https://datatracker.ietf.org/doc/html/rfc6749#section-10.12",
            "https://portswigger.net/web-security/oauth/preventing",
        ],
    ),
    AuthCVEEntry(
        vuln_id="AUTH-ADV-006",
        cve_id=None,
        severity="critical",
        title="JWT Algorithm 'none' Accepted",
        description=(
            "The server accepts JWTs signed with the 'alg=none' algorithm, meaning an "
            "attacker can forge tokens with arbitrary claims by removing the signature "
            "and changing the algorithm header. This completely bypasses JWT verification."
        ),
        affected_providers=[],
        check_condition="alg_none_accepted",
        remediation=(
            "Explicitly reject tokens with alg=none. Maintain an allow-list of accepted "
            "signing algorithms (e.g. RS256, ES256). Never rely on the algorithm header "
            "in the token to select the verification key."
        ),
        references=[
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
            "https://cwe.mitre.org/data/definitions/347.html",
        ],
    ),
    AuthCVEEntry(
        vuln_id="AUTH-ADV-007",
        cve_id=None,
        severity="high",
        title="Authorization Code Reuse Not Prevented",
        description=(
            "The token endpoint does not invalidate authorization codes after first use "
            "(or does not invalidate issued tokens when a replayed code is detected). "
            "An attacker who captures an authorization code can exchange it for tokens "
            "after the legitimate client has already done so."
        ),
        affected_providers=[],
        check_condition="code_reuse_possible",
        remediation=(
            "Invalidate authorization codes immediately after first use. "
            "When a code is replayed, revoke all tokens previously issued for that code "
            "(per RFC 6749 §4.1.2 and RFC 9700 §4.14)."
        ),
        references=[
            "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2",
            "https://datatracker.ietf.org/doc/html/rfc9700#section-4.14",
        ],
    ),
    AuthCVEEntry(
        vuln_id="AUTH-ADV-009",
        cve_id=None,
        severity="low",
        title="JWKS Endpoint Lacks Cache-Control Headers",
        description=(
            "The JWKS (JSON Web Key Set) endpoint does not return appropriate "
            "Cache-Control headers. While the JWKS itself is public, missing cache "
            "controls may cause relying parties to fetch keys on every request "
            "(performance issue) or to cache stale keys after rotation (security issue)."
        ),
        affected_providers=[],
        check_condition="jwks_no_cache_control",
        remediation=(
            "Return 'Cache-Control: public, max-age=3600' on the JWKS endpoint. "
            "Implement key rotation with an overlap period and publish the new key "
            "before retiring the old one."
        ),
        references=[
            "https://datatracker.ietf.org/doc/html/rfc7517",
            "https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys",
        ],
    ),
    # ------------------------------------------------------------------
    # Provider-specific OAuth2 / OIDC CVEs
    # ------------------------------------------------------------------
    AuthCVEEntry(
        vuln_id="AUTH-ADV-001",
        cve_id="CVE-2019-3778",
        severity="high",
        title="Spring Security OAuth Open Redirect via redirect_uri",
        description=(
            "Spring Security OAuth 2.x before 2.3.6 and certain 2.4.x / 2.5.x releases "
            "allow open redirect via a crafted redirect_uri parameter. The authorization "
            "server insufficiently validates the redirect_uri, allowing attackers to redirect "
            "the authorization code to an attacker-controlled domain and steal tokens."
        ),
        affected_providers=["spring", "pivotal", "vmware"],
        check_condition="",
        remediation=(
            "Upgrade to Spring Security OAuth >= 2.3.6 / 2.4.2 / 2.5.1. "
            "Register exact redirect URIs (no wildcard matching). "
            "Validate redirect_uri strictly against the pre-registered list."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3778",
            "https://spring.io/blog/2019/05/31/spring-security-oauth-2-3-6-2-2-5-2-1-4-2-0-17-released",
        ],
    ),
    AuthCVEEntry(
        vuln_id="AUTH-ADV-002",
        cve_id="CVE-2021-27582",
        severity="high",
        title="Spring Security OAuth Implicit Flow Token Leak",
        description=(
            "Spring Security OAuth 2.5.0 does not properly validate the redirect URI "
            "during the implicit flow, allowing an attacker to steal access tokens "
            "via an open redirect to an attacker-controlled endpoint."
        ),
        affected_providers=["spring", "pivotal", "vmware"],
        check_condition="implicit_flow_enabled",
        remediation=(
            "Upgrade to Spring Security OAuth >= 2.5.1. "
            "Disable the implicit grant type. "
            "Use authorization code flow with PKCE instead."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-27582",
        ],
    ),
    AuthCVEEntry(
        vuln_id="AUTH-ADV-008",
        cve_id="CVE-2023-34462",
        severity="high",
        title="Redirect URI Lax Matching — Open Redirect",
        description=(
            "Certain OAuth servers (including Netty-based and some Keycloak versions) "
            "perform lax redirect_uri validation, accepting parameters appended after "
            "a registered URI (e.g., 'https://client.example.com/callback/../../../evil'). "
            "This can be leveraged to redirect the authorization code to attacker-controlled "
            "servers."
        ),
        affected_providers=["keycloak", "netty", "redhat"],
        check_condition="",
        remediation=(
            "Enforce exact string matching for redirect_uri against the registered list. "
            "Canonicalize URIs before comparison (resolve path traversal segments). "
            "Reject any redirect_uri containing '..' or encoded variants."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2023-34462",
        ],
    ),
    # ------------------------------------------------------------------
    # SAML — universal misconfigurations
    # ------------------------------------------------------------------
    AuthCVEEntry(
        vuln_id="AUTH-ADV-012",
        cve_id=None,
        severity="high",
        title="Missing SAML AudienceRestriction Validation",
        description=(
            "The service provider does not validate the AudienceRestriction element "
            "in SAML assertions. An attacker who obtains a valid SAML assertion "
            "destined for one service provider can replay it against another SP "
            "that shares the same IdP."
        ),
        affected_providers=[],
        check_condition="saml_no_audience_restriction",
        remediation=(
            "Validate the <AudienceRestriction> element and ensure the <Audience> "
            "value matches the SP's entity ID. Reject assertions intended for other SPs."
        ),
        references=[
            "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf",
            "https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html",
        ],
    ),
    AuthCVEEntry(
        vuln_id="AUTH-ADV-013",
        cve_id=None,
        severity="high",
        title="SAML Missing NotOnOrAfter — Replay Attack Window",
        description=(
            "The SAML assertion does not contain a NotOnOrAfter condition or the "
            "service provider does not enforce it. Without an expiry window, captured "
            "assertions can be replayed indefinitely to authenticate as the victim."
        ),
        affected_providers=[],
        check_condition="saml_no_expiry",
        remediation=(
            "Issue assertions with a short NotOnOrAfter window (e.g. 5 minutes). "
            "Validate NotOnOrAfter and reject assertions outside the window. "
            "Implement an assertion replay cache keyed on the assertion ID."
        ),
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html",
        ],
    ),
    # ------------------------------------------------------------------
    # SAML — provider-specific CVEs
    # ------------------------------------------------------------------
    AuthCVEEntry(
        vuln_id="AUTH-ADV-010",
        cve_id="CVE-2017-11427",
        severity="critical",
        title="XML Signature Wrapping (XSW) — OneLogin SAML Bypass",
        description=(
            "OneLogin's python-saml and ruby-saml libraries before certain versions "
            "are vulnerable to XML Signature Wrapping attacks. An attacker can copy a "
            "valid signed SAML assertion, wrap it with a crafted outer structure, and "
            "inject a forged assertion. The library verifies the outer signature but "
            "processes the inner forged content, allowing authentication bypass."
        ),
        affected_providers=["onelogin", "python-saml", "ruby-saml"],
        check_condition="",
        remediation=(
            "Upgrade python-saml >= 2.2.0 / ruby-saml >= 1.7.0. "
            "Ensure the library verifies that the signed element is also the element "
            "consumed by the application. "
            "Validate the SAML response against a strict schema."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2017-11427",
            "https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-providers",
        ],
    ),
    AuthCVEEntry(
        vuln_id="AUTH-ADV-011",
        cve_id="CVE-2018-0489",
        severity="critical",
        title="SAML Comment Injection — Shibboleth Signature Bypass",
        description=(
            "Shibboleth OpenSAML-C and XMLTooling-C before 1.6.4 / 3.0.4 are "
            "vulnerable to a comment injection attack where XML comments inserted "
            "within attribute values survive signature verification but alter the "
            "string value seen by the consuming application. An attacker can forge "
            "attribute values (e.g. username, role) in signed assertions."
        ),
        affected_providers=["shibboleth", "opensaml"],
        check_condition="",
        remediation=(
            "Upgrade Shibboleth Service Provider >= 2.6.1 / 3.0.4 and XMLTooling-C >= 1.6.4. "
            "Strip XML comments from SAML documents before processing. "
            "Apply the vendor-supplied security patches."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2018-0489",
            "https://shibboleth.net/community/advisories/secadv_20180202.txt",
        ],
    ),
    AuthCVEEntry(
        vuln_id="AUTH-ADV-014",
        cve_id="CVE-2023-41900",
        severity="high",
        title="Keycloak / OpenSAML SAML Assertion Bypass",
        description=(
            "Keycloak before 22.0.3 and related OpenSAML-based implementations "
            "are vulnerable to an authentication bypass where a specially crafted "
            "SAML response can be accepted without a valid IdP signature under "
            "certain SP configurations. Successful exploitation allows an attacker "
            "to authenticate as any user without valid credentials."
        ),
        affected_providers=["keycloak", "redhat", "opensaml"],
        check_condition="",
        remediation=(
            "Upgrade Keycloak >= 22.0.3 or apply the vendor security patch. "
            "Enforce strict signature validation on all SAML responses and assertions. "
            "Do not configure the SP to accept unsigned responses."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2023-41900",
            "https://access.redhat.com/security/cve/CVE-2023-41900",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Matching function
# ---------------------------------------------------------------------------

def match_cves(
    provider_name: str,
    detected_issues: list[str] | None = None,
) -> list[AuthCVEEntry]:
    """
    Match a detected auth provider and security issues against the CVE database.

    Args:
        provider_name:   Fingerprinted provider string (e.g. "keycloak 22.0.1").
        detected_issues: List of condition keys from security analysis
                         (e.g. ["pkce_not_required", "implicit_flow_enabled"]).

    Returns:
        List of matching AuthCVEEntry records.
    """
    name_lower = provider_name.lower()
    detected_issues = detected_issues or []
    matched: list[AuthCVEEntry] = []

    for entry in AUTH_CVE_DB:
        # Provider-specific entries: require a name substring match
        if entry.affected_providers:
            if not any(p.lower() in name_lower for p in entry.affected_providers):
                continue

        # Entries with a check_condition must have that condition in detected_issues
        if entry.check_condition:
            if entry.check_condition not in detected_issues:
                continue

        matched.append(entry)

    return matched
