"""
Auth protocol (OIDC / OAuth 2.0 / SAML) endpoint security scanner.

Passively fingerprints the authentication protocol in use, enumerates
discovery documents and metadata, checks security posture, and matches
findings against the auth CVE database.

Usage:
    scanner = AuthScanner("https://auth.example.com")
    result = await scanner.scan()

    # Override auto-detection:
    scanner = AuthScanner("https://idp.example.com", protocol="saml")
    result = await scanner.scan()
"""

from __future__ import annotations

import logging
import time
import xml.etree.ElementTree as ET
from typing import Any

import httpx

from ..models.auth_result import (
    AuthProtocol,
    AuthProviderInfo,
    AuthScanResult,
    AuthVulnerability,
    AuthVulnSeverity,
)
from ..utils.auth_cve_db import match_cves


from ..utils.constants import USER_AGENT
logger = logging.getLogger(__name__)

# SAML XML namespaces
_NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}

# Well-known discovery endpoint paths to probe (in priority order)
_OIDC_PATHS: list[str] = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

_SAML_PATHS: list[str] = [
    "/saml/metadata",
    "/saml2/metadata",
    "/metadata",
    "/FederationMetadata/2007-06/FederationMetadata.xml",
    "/saml/metadata.xml",
]


class AuthScanner:
    """Passive security scanner for OIDC, OAuth 2.0, and SAML endpoints."""

    def __init__(
        self,
        target: str,
        protocol: str = "auto",
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        judge: object | None = None,
    ) -> None:
        """
        Args:
            target:     Base URL of the auth server (e.g. "https://auth.example.com").
            protocol:   "auto", "oidc", "oauth2", or "saml".
            headers:    Extra HTTP headers (e.g. Authorization).
            timeout:    Per-request timeout in seconds.
            verify_tls: Verify TLS certificates. Set False for self-signed certs.
            judge:      Optional LLMJudge instance for AI-assisted finding triage.
        """
        self.target = target.rstrip("/")
        self.protocol = protocol
        self.headers = headers or {}
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._judge = judge

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self) -> AuthScanResult:
        """Fingerprint, enumerate, and assess security posture of the auth endpoint."""
        start = time.monotonic()
        result = AuthScanResult(target=self.target)

        async with httpx.AsyncClient(
            headers={
                "Accept": "application/json, application/xml, text/xml, */*",
                "User-Agent": USER_AGENT,
                **self.headers,
            },
            timeout=self.timeout,
            trust_env=False,
            follow_redirects=True,
            verify=self.verify_tls,  # noqa: S501 — intentional for security scanning
        ) as client:
            try:
                await self._detect_and_parse(client, result)
            except Exception as exc:
                logger.debug("Auth scan error: %s", exc)
                result.error = str(exc)

        if not result.error or result.provider_info.issuer or result.provider_info.endpoints:
            result.vulnerabilities = self._analyze_security(result)
            detected_issues = [v.vuln_id for v in result.vulnerabilities]
            result.cve_matches = self._match_cves(result, detected_issues)

            if self._judge and getattr(self._judge, "provider", None):
                self._phase_llm_triage(result)

        result.scan_duration = time.monotonic() - start
        return result

    # ------------------------------------------------------------------
    # Protocol detection and document parsing
    # ------------------------------------------------------------------

    async def _detect_and_parse(
        self, client: httpx.AsyncClient, result: AuthScanResult
    ) -> None:
        """Auto-detect or use the specified protocol and parse discovery docs."""
        proto = self.protocol.lower()

        if proto in ("oidc", "oauth2", "auto"):
            found = await self._try_oidc_discovery(client, result)
            if found:
                return

        if proto in ("saml", "auto"):
            found = await self._try_saml_metadata(client, result)
            if found:
                return

        if proto == "auto":
            result.error = (
                "Could not detect auth protocol. No OIDC discovery document "
                "or SAML metadata found at common paths."
            )

    async def _try_oidc_discovery(
        self, client: httpx.AsyncClient, result: AuthScanResult
    ) -> bool:
        """Probe well-known OIDC/OAuth2 endpoints. Returns True on success."""
        for path in _OIDC_PATHS:
            url = self.target + path
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct or resp.text.lstrip().startswith("{"):
                        doc = resp.json()
                        self._parse_oidc_discovery(doc, result, url)
                        return True
            except Exception as exc:
                logger.debug("OIDC probe %s failed: %s", url, exc)

        return False

    async def _try_saml_metadata(
        self, client: httpx.AsyncClient, result: AuthScanResult
    ) -> bool:
        """Probe well-known SAML metadata endpoints. Returns True on success."""
        for path in _SAML_PATHS:
            url = self.target + path
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    body = resp.text.strip()
                    if "xml" in ct or body.startswith("<"):
                        if self._parse_saml_metadata(body, result, url):
                            return True
            except Exception as exc:
                logger.debug("SAML probe %s failed: %s", url, exc)

        return False

    def _parse_oidc_discovery(
        self, doc: dict[str, Any], result: AuthScanResult, source_url: str
    ) -> None:
        """Extract security-relevant fields from an OIDC/OAuth2 discovery document."""
        result.provider_info.raw = doc
        result.provider_info.issuer = doc.get("issuer", "")

        # Determine protocol type: OIDC has id_token_signing_alg_values_supported
        if "id_token_signing_alg_values_supported" in doc or "userinfo_endpoint" in doc:
            result.protocol = AuthProtocol.OIDC
        else:
            result.protocol = AuthProtocol.OAUTH2

        # Fingerprint provider name from issuer
        issuer = result.provider_info.issuer.lower()
        for hint, name in [
            ("keycloak", "Keycloak"),
            ("auth0", "Auth0"),
            ("okta", "Okta"),
            ("microsoft", "Microsoft Entra ID"),
            ("azure", "Microsoft Entra ID"),
            ("google", "Google"),
            ("ping", "PingFederate"),
            ("shibboleth", "Shibboleth"),
            ("spring", "Spring Authorization Server"),
            ("cognito", "Amazon Cognito"),
            ("gitlab", "GitLab"),
            ("github", "GitHub"),
        ]:
            if hint in issuer:
                result.provider_info.name = name
                break
        else:
            result.provider_info.name = doc.get("issuer", source_url)

        # Endpoints
        for key in (
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
            "introspection_endpoint",
            "revocation_endpoint",
            "end_session_endpoint",
            "registration_endpoint",
        ):
            if key in doc:
                result.provider_info.endpoints[key] = doc[key]

        # Supported flows / grant types
        result.provider_info.supported_flows = doc.get(
            "grant_types_supported",
            doc.get("response_types_supported", []),
        )

        # Algorithms
        algs: list[str] = []
        for alg_key in (
            "id_token_signing_alg_values_supported",
            "token_endpoint_auth_signing_alg_values_supported",
            "request_object_signing_alg_values_supported",
        ):
            algs.extend(doc.get(alg_key, []))
        result.provider_info.supported_algorithms = list(dict.fromkeys(algs))

        # PKCE support
        code_challenge_methods = doc.get("code_challenge_methods_supported", [])
        result.provider_info.pkce_supported = bool(code_challenge_methods)
        # We can't passively determine pkce_required — flag it as unknown (False)
        # unless the server explicitly says so (non-standard extension)
        result.provider_info.pkce_required = doc.get("require_pkce", False)

        # Implicit flow
        response_types: list[str] = doc.get("response_types_supported", [])
        grant_types: list[str] = doc.get("grant_types_supported", [])
        result.provider_info.implicit_flow_enabled = (
            "token" in response_types
            or "implicit" in grant_types
        )

        # State — no standard way to detect requirement; default to unknown (False)
        result.provider_info.state_required = False

    def _parse_saml_metadata(
        self, xml_text: str, result: AuthScanResult, source_url: str
    ) -> bool:
        """
        Extract security-relevant fields from a SAML metadata XML document.
        Uses stdlib xml.etree.ElementTree with defused entity handling.
        Returns True if the document looks like valid SAML metadata.
        """
        try:
            # Reject XXE: ET does not expand external entities by default in CPython
            root = ET.fromstring(xml_text)  # noqa: S314  # nosec B314 — SAML metadata from known endpoint; ET does not expand external entities in CPython
        except ET.ParseError as exc:
            logger.debug("SAML XML parse error: %s", exc)
            return False

        # Must have SAML metadata namespace to count as valid
        tag = root.tag
        if "metadata" not in tag and "EntityDescriptor" not in tag:
            return False

        result.protocol = AuthProtocol.SAML
        result.provider_info.raw = {"xml_length": len(xml_text), "source": source_url}

        # Entity ID
        entity_id = root.get("entityID", "")
        result.provider_info.issuer = entity_id
        result.provider_info.name = entity_id or source_url

        # ACS and SLO endpoints
        endpoints: dict[str, str] = {}
        for acs in root.iter("{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService"):
            binding = acs.get("Binding", "")
            loc = acs.get("Location", "")
            if loc:
                endpoints[f"acs:{binding.split(':')[-1]}"] = loc
        for slo in root.iter("{urn:oasis:names:tc:SAML:2.0:metadata}SingleLogoutService"):
            binding = slo.get("Binding", "")
            loc = slo.get("Location", "")
            if loc:
                endpoints[f"slo:{binding.split(':')[-1]}"] = loc
        for sso in root.iter("{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService"):
            binding = sso.get("Binding", "")
            loc = sso.get("Location", "")
            if loc:
                endpoints[f"sso:{binding.split(':')[-1]}"] = loc

        result.provider_info.endpoints = endpoints

        # Signing key presence
        certs = list(root.iter("{http://www.w3.org/2000/09/xmldsig#}X509Certificate"))
        result.provider_info.raw["signing_certs_found"] = len(certs)

        return True

    # ------------------------------------------------------------------
    # Security analysis (no network)
    # ------------------------------------------------------------------

    def _analyze_security(self, result: AuthScanResult) -> list[AuthVulnerability]:
        """Generate AuthVulnerability objects from the provider's security posture."""
        vulns: list[AuthVulnerability] = []
        info = result.provider_info

        if result.protocol in (AuthProtocol.OIDC, AuthProtocol.OAUTH2):
            vulns.extend(self._analyze_oidc_security(result, info))
        elif result.protocol == AuthProtocol.SAML:
            vulns.extend(self._analyze_saml_security(result, info))

        return vulns

    def _analyze_oidc_security(
        self, result: AuthScanResult, info: AuthProviderInfo
    ) -> list[AuthVulnerability]:
        vulns: list[AuthVulnerability] = []

        # PKCE not required
        if info.pkce_supported and not info.pkce_required:
            vulns.append(AuthVulnerability(
                vuln_id="OAI-AUTH-PKCE-001",
                severity=AuthVulnSeverity.HIGH,
                title="PKCE Not Required for Public Clients",
                description=(
                    "The server advertises PKCE support but does not enforce it. "
                    "Public clients that omit code_challenge are not rejected, leaving "
                    "authorization codes vulnerable to interception and replay."
                ),
                evidence=f"code_challenge_methods_supported in discovery but require_pkce=false. "
                         f"Issuer: {info.issuer}",
                remediation=(
                    "Configure the authorization server to require PKCE for public clients. "
                    "Reject authorization requests that omit code_challenge."
                ),
                affected_component=result.provider_info.endpoints.get(
                    "authorization_endpoint", self.target
                ),
            ))

        # PKCE not advertised at all
        if not info.pkce_supported:
            vulns.append(AuthVulnerability(
                vuln_id="OAI-AUTH-PKCE-002",
                severity=AuthVulnSeverity.HIGH,
                title="PKCE Not Advertised by Server",
                description=(
                    "The discovery document does not list code_challenge_methods_supported. "
                    "PKCE is mandatory for public clients and should be supported by all "
                    "modern authorization servers (OAuth 2.1 requirement)."
                ),
                evidence=f"code_challenge_methods_supported absent from discovery. "
                         f"Issuer: {info.issuer}",
                remediation=(
                    "Enable PKCE on the authorization server and publish "
                    "code_challenge_methods_supported (at minimum ['S256']) in the "
                    "discovery document."
                ),
                affected_component=self.target,
            ))

        # Implicit flow enabled
        if info.implicit_flow_enabled:
            vulns.append(AuthVulnerability(
                vuln_id="OAI-AUTH-IMPL-001",
                severity=AuthVulnSeverity.MEDIUM,
                title="Implicit Flow Enabled (Deprecated)",
                description=(
                    "The server supports the implicit grant type or response_type=token. "
                    "The implicit flow delivers access tokens in the URL fragment where "
                    "they are exposed to the browser history, referrer headers, and "
                    "logging infrastructure. It was deprecated by RFC 9700 / OAuth 2.1."
                ),
                evidence=(
                    f"supported_flows includes 'implicit' or response_types includes 'token'. "
                    f"Supported flows: {info.supported_flows}"
                ),
                remediation=(
                    "Disable the implicit grant type. Migrate clients to the authorization "
                    "code flow with PKCE."
                ),
                affected_component=self.target,
            ))

        # JWT alg=none in supported algorithms
        algs_lower = [a.lower() for a in info.supported_algorithms]
        if "none" in algs_lower:
            vulns.append(AuthVulnerability(
                vuln_id="OAI-AUTH-JWTALGN-001",
                severity=AuthVulnSeverity.CRITICAL,
                title="JWT Algorithm 'none' Advertised",
                description=(
                    "The discovery document lists 'none' as a supported signing algorithm. "
                    "Accepting JWTs with alg=none means an attacker can forge tokens with "
                    "arbitrary claims without a valid signature."
                ),
                evidence=f"id_token_signing_alg_values_supported includes 'none'. "
                         f"Algorithms: {info.supported_algorithms}",
                remediation=(
                    "Remove 'none' from all alg_values_supported lists. "
                    "Enforce an allow-list of secure algorithms (RS256, ES256)."
                ),
                affected_component=self.target,
            ))

        # State parameter not required (info-level — cannot be passively confirmed)
        if not info.state_required:
            vulns.append(AuthVulnerability(
                vuln_id="OAI-AUTH-STATE-001",
                severity=AuthVulnSeverity.LOW,
                title="State Parameter Requirement Not Confirmed",
                description=(
                    "The discovery document does not confirm that the 'state' parameter "
                    "is required on authorization requests. Without enforced state "
                    "validation, CSRF attacks against the OAuth callback are possible."
                ),
                evidence="No require_state field found in discovery document.",
                remediation=(
                    "Enforce the state parameter and validate it matches the value sent "
                    "in the authorization request. Use PKCE as an additional CSRF control."
                ),
                affected_component=self.target,
            ))

        # JWKS endpoint missing cache-control (requires a probe; mark as INFO)
        jwks_uri = info.endpoints.get("jwks_uri", "")
        if jwks_uri:
            vulns.append(AuthVulnerability(
                vuln_id="OAI-AUTH-JWKS-001",
                severity=AuthVulnSeverity.INFO,
                title="JWKS Endpoint Detected — Cache-Control Should Be Verified",
                description=(
                    "A JWKS endpoint was detected. Verify that it returns appropriate "
                    "Cache-Control headers to ensure relying parties cache keys correctly "
                    "and handle key rotation gracefully."
                ),
                evidence=f"JWKS URI: {jwks_uri}",
                remediation=(
                    "Return 'Cache-Control: public, max-age=3600' on the JWKS endpoint."
                ),
                affected_component=jwks_uri,
            ))

        return vulns

    def _analyze_saml_security(
        self, result: AuthScanResult, info: AuthProviderInfo
    ) -> list[AuthVulnerability]:
        vulns: list[AuthVulnerability] = []

        # No signing certificates found in metadata
        certs_found = info.raw.get("signing_certs_found", 0)
        if certs_found == 0:
            vulns.append(AuthVulnerability(
                vuln_id="OAI-AUTH-SAML-NOSIG",
                severity=AuthVulnSeverity.HIGH,
                title="No Signing Certificates in SAML Metadata",
                description=(
                    "The SAML metadata does not contain any X.509 signing certificates. "
                    "Without published signing keys, relying parties cannot verify the "
                    "IdP's assertion signatures, which may lead to misconfigured SPs "
                    "that skip signature validation entirely."
                ),
                evidence=f"0 X509Certificate elements found in metadata. Source: {info.raw.get('source', '')}",
                remediation=(
                    "Publish the IdP's signing certificate in the metadata "
                    "<KeyDescriptor use='signing'> element."
                ),
                affected_component=info.raw.get("source", self.target),
            ))

        # No ACS endpoint found
        acs_endpoints = [k for k in info.endpoints if k.startswith("acs:")]
        if not acs_endpoints:
            vulns.append(AuthVulnerability(
                vuln_id="OAI-AUTH-SAML-NOACS",
                severity=AuthVulnSeverity.MEDIUM,
                title="No Assertion Consumer Service Endpoint in Metadata",
                description=(
                    "The SAML metadata does not advertise any Assertion Consumer Service "
                    "(ACS) endpoints. This may indicate an incomplete or misconfigured "
                    "SAML deployment."
                ),
                evidence="No AssertionConsumerService elements found in metadata.",
                remediation="Ensure the SP metadata includes at least one ACS endpoint.",
                affected_component=info.raw.get("source", self.target),
            ))

        # Generic XSW risk (informational — active testing required to confirm)
        vulns.append(AuthVulnerability(
            vuln_id="OAI-AUTH-SAML-XSW",
            severity=AuthVulnSeverity.INFO,
            title="SAML XML Signature Wrapping (XSW) — Active Testing Required",
            description=(
                "SAML implementations are historically vulnerable to XML Signature "
                "Wrapping (XSW) attacks where a valid signature is detached from its "
                "signed content. Passive scanning cannot confirm vulnerability — "
                "use auth-attack with --i-have-authorization to test actively."
            ),
            evidence=f"SAML endpoint detected at {info.raw.get('source', self.target)}",
            remediation=(
                "Ensure the SAML library validates that the signed element is the "
                "same element consumed during authentication. Keep libraries updated."
            ),
            references=[
                "https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-providers",
            ],
            affected_component=info.raw.get("source", self.target),
        ))

        return vulns

    def _match_cves(
        self, result: AuthScanResult, detected_issue_vuln_ids: list[str]
    ) -> list[AuthVulnerability]:
        """Query the CVE DB and convert matches to AuthVulnerability objects."""
        # Build condition keys from detected vulnerability IDs
        condition_map = {
            "OAI-AUTH-PKCE-001": "pkce_not_required",
            "OAI-AUTH-PKCE-002": "pkce_not_required",
            "OAI-AUTH-IMPL-001": "implicit_flow_enabled",
            "OAI-AUTH-JWTALGN-001": "alg_none_accepted",
            "OAI-AUTH-STATE-001": "state_not_required",
            "OAI-AUTH-SAML-NOSIG": "saml_no_audience_restriction",
        }
        detected_conditions = [
            condition_map[vid]
            for vid in detected_issue_vuln_ids
            if vid in condition_map
        ]

        provider_str = (
            f"{result.provider_info.name} {result.provider_info.issuer}".lower()
        )
        cve_entries = match_cves(provider_str, detected_conditions)

        cve_vulns: list[AuthVulnerability] = []
        for entry in cve_entries:
            cve_vulns.append(AuthVulnerability(
                vuln_id=entry.vuln_id,
                cve_id=entry.cve_id,
                severity=AuthVulnSeverity(entry.severity),
                title=entry.title,
                description=entry.description,
                remediation=entry.remediation,
                references=entry.references,
                affected_component=result.provider_info.issuer or self.target,
            ))

        return cve_vulns

    # ------------------------------------------------------------------
    # LLM Judge triage
    # ------------------------------------------------------------------

    def _phase_llm_triage(self, result: AuthScanResult) -> None:
        """Use LLM judge to enrich MEDIUM/LOW auth findings."""
        ambiguous = {AuthVulnSeverity.MEDIUM, AuthVulnSeverity.LOW}
        for vuln in result.vulnerabilities:
            if vuln.severity not in ambiguous:
                continue
            if not self._judge:
                continue
            try:
                verdict = self._judge.evaluate(
                    category=vuln.vuln_id,
                    probe=vuln.title,
                    response=vuln.evidence or vuln.description,
                )
                vuln.llm_confidence = float(verdict.get("confidence", 0.0))
                vuln.llm_reasoning = str(verdict.get("reason", ""))
                if verdict.get("vulnerable") and vuln.llm_confidence > 0.7:
                    if vuln.severity == AuthVulnSeverity.LOW:
                        vuln.severity = AuthVulnSeverity.MEDIUM
                        vuln.evidence += " [LLM: upgraded from LOW]"
            except Exception as exc:  # noqa: BLE001
                logger.debug("LLM triage error for %s: %s", vuln.vuln_id, exc)
