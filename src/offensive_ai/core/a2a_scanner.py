"""
A2A (Agent-to-Agent) protocol endpoint security scanner.

Discovers an A2A agent by fetching its Agent Card from the well-known URI,
fingerprints the declared capabilities and security schemes, probes task
endpoints for authentication posture, and matches findings against a database
of known A2A misconfigurations.

Usage:
    scanner = A2AScanner("https://agent.example.com")
    result = await scanner.scan()

The scanner probes the JSON-RPC binding (the most widely deployed A2A binding)
and does not require grpcio or any protobuf libraries.
"""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from ..models.a2a_result import (
    A2AAgentCard,
    A2AAuthPosture,
    A2ACapabilities,
    A2AScanResult,
    A2AServerInfo,
    A2ASkill,
    A2AVulnerability,
    A2AVulnSeverity,
)
from ..utils.a2a_cve_db import (
    DANGEROUS_SKILL_KEYWORDS,
    match_cves,
    scan_for_dangerous_keywords,
    scan_for_secrets,
)


from ..utils.constants import USER_AGENT
logger = logging.getLogger(__name__)

_AGENT_CARD_PATH = "/.well-known/agent-card.json"



class A2AScanner:
    """Security scanner for A2A (Agent-to-Agent) protocol endpoints."""

    def __init__(
        self,
        target: str,
        port: int | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        judge: object | None = None,
    ) -> None:
        """
        Args:
            target:     Base URL of the A2A agent (e.g. 'https://agent.example.com')
                        or a full URL to the agent card
                        (e.g. 'https://agent.example.com/.well-known/agent-card.json').
            port:       Override port (useful for non-standard ports).
            headers:    Extra HTTP headers (e.g. Authorization for auth-gated scans).
            timeout:    Per-request timeout in seconds.
            verify_tls: Verify TLS certificates. Set False for self-signed certs.
            judge:      Optional LLMJudge instance for AI-assisted triage.
        """
        self.target = self._normalise_target(target, port)
        self.headers = headers or {}
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._judge = judge

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self) -> A2AScanResult:
        """Fetch Agent Card, probe endpoints, assess security posture."""
        start = time.monotonic()
        result = A2AScanResult(target=self.target)

        async with httpx.AsyncClient(
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                **self.headers,
            },
            timeout=self.timeout,
            trust_env=False,
            verify=self.verify_tls,  # noqa: S501 — intentional for security scanning
            follow_redirects=True,
        ) as client:
            # Phase 1 — fetch and parse Agent Card
            card_data, card_error = await self._fetch_agent_card(client)
            if card_error:
                result.error = card_error
                result.scan_duration = time.monotonic() - start
                return result

            result.agent_card = self._parse_agent_card(card_data)

            # Phase 2 — derive server info from card
            result.server_info = self._build_server_info(result.agent_card)

            # Phase 3 — check transport security
            tls_vulns = self._check_transport_security(result.agent_card)
            result.vulnerabilities.extend(tls_vulns)

            # Phase 4 — auth posture (probe without credentials)
            result.auth_posture = await self._check_auth_posture(client, result.agent_card)

            # Phase 5 — probe extended agent card without auth (if declared)
            if result.agent_card.capabilities.extended_agent_card:
                extended_vuln = await self._probe_extended_card(client, result.agent_card)
                if extended_vuln:
                    result.vulnerabilities.append(extended_vuln)

        # Phase 6 — static security analysis (no network)
        result.vulnerabilities.extend(self._analyze_security(result))

        # Phase 7 — CVE matching
        accessible_paths: list[str] = []
        if result.auth_posture.unauthenticated_access:
            accessible_paths.append("/message:send")
        result.cve_matches = self._match_cves(result.agent_card, accessible_paths)

        # Phase 8 — optional LLM triage
        if self._judge and getattr(self._judge, "provider", None):
            self._phase_llm_triage(result)

        result.scan_duration = time.monotonic() - start
        return result

    # ------------------------------------------------------------------
    # Target normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_target(target: str, port: int | None) -> str:
        """Ensure *target* is a well-formed base URL without trailing slash."""
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        parsed = urlparse(target)
        # Strip agent-card path if the caller passed it as the target
        if parsed.path.endswith(_AGENT_CARD_PATH):
            parsed = parsed._replace(path="")
        elif parsed.path.endswith("/"):
            parsed = parsed._replace(path=parsed.path.rstrip("/"))
        if port is not None:
            parsed = parsed._replace(netloc=f"{parsed.hostname}:{port}")
        return urlunparse(parsed)

    # ------------------------------------------------------------------
    # Agent Card fetching & parsing
    # ------------------------------------------------------------------

    async def _fetch_agent_card(
        self, client: httpx.AsyncClient
    ) -> tuple[dict[str, Any], str | None]:
        url = self.target.rstrip("/") + _AGENT_CARD_PATH
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json(), None
        except httpx.HTTPStatusError as exc:
            return {}, f"HTTP {exc.response.status_code} fetching Agent Card: {exc.response.text[:200]}"
        except Exception as exc:
            return {}, f"Failed to fetch Agent Card from {url}: {exc}"

    def _parse_agent_card(self, data: dict[str, Any]) -> A2AAgentCard:
        raw_caps = data.get("capabilities", {})
        capabilities = A2ACapabilities(
            streaming=raw_caps.get("streaming", False),
            push_notifications=raw_caps.get("pushNotifications", False),
            extended_agent_card=raw_caps.get("extendedAgentCard", False),
            raw=raw_caps,
        )

        skills: list[A2ASkill] = []
        for raw_skill in data.get("skills", []):
            desc = raw_skill.get("description", "")
            dangerous_kw = scan_for_dangerous_keywords(desc)
            # Also scan name and tags
            name_tags_text = raw_skill.get("name", "") + " " + " ".join(raw_skill.get("tags", []))
            dangerous_kw += scan_for_dangerous_keywords(name_tags_text)
            dangerous_kw = list(dict.fromkeys(dangerous_kw))  # deduplicate, preserve order
            skills.append(A2ASkill(
                id=raw_skill.get("id", ""),
                name=raw_skill.get("name", ""),
                description=desc,
                tags=raw_skill.get("tags", []),
                input_modes=raw_skill.get("inputModes", []),
                output_modes=raw_skill.get("outputModes", []),
                examples=raw_skill.get("examples", []),
                has_dangerous_keywords=bool(dangerous_kw),
                dangerous_keywords_found=dangerous_kw,
            ))

        provider = data.get("provider", {})
        return A2AAgentCard(
            name=data.get("name", ""),
            description=data.get("description", ""),
            version=data.get("version", ""),
            provider_organization=provider.get("organization", ""),
            provider_url=provider.get("url", ""),
            documentation_url=data.get("documentationUrl", ""),
            icon_url=data.get("iconUrl", ""),
            supported_interfaces=data.get("supportedInterfaces", []),
            security_schemes=data.get("securitySchemes", {}),
            security=data.get("security", []),
            capabilities=capabilities,
            skills=skills,
            default_input_modes=data.get("defaultInputModes", []),
            default_output_modes=data.get("defaultOutputModes", []),
            is_signed=bool(data.get("signatures")),
            raw=data,
        )

    def _build_server_info(self, card: A2AAgentCard) -> A2AServerInfo:
        bindings = [
            iface.get("protocolBinding", "")
            for iface in card.supported_interfaces
        ]
        endpoint = ""
        if card.supported_interfaces:
            endpoint = card.supported_interfaces[0].get("url", "")
        proto_version = ""
        if card.supported_interfaces:
            proto_version = card.supported_interfaces[0].get("protocolVersion", "")
        return A2AServerInfo(
            protocol_version=proto_version,
            supported_bindings=[b for b in bindings if b],
            endpoint_url=endpoint,
            raw=card.raw,
        )

    # ------------------------------------------------------------------
    # Transport security check
    # ------------------------------------------------------------------

    def _check_transport_security(self, card: A2AAgentCard) -> list[A2AVulnerability]:
        vulns: list[A2AVulnerability] = []
        http_urls = [
            iface.get("url", "")
            for iface in card.supported_interfaces
            if iface.get("url", "").startswith("http://")
        ]
        if http_urls:
            vulns.append(A2AVulnerability(
                vuln_id="OAI-A2A-TLS-001",
                severity=A2AVulnSeverity.HIGH,
                title="Plaintext HTTP Endpoint Declared in Agent Card",
                description=(
                    "The Agent Card lists one or more supported interfaces using a plain "
                    "HTTP URL. Traffic over HTTP is not encrypted, exposing credentials, "
                    "task contents, and artifacts to interception and tampering."
                ),
                evidence=", ".join(http_urls[:3]),
                remediation=(
                    "Replace all http:// URLs with https:// in supportedInterfaces. "
                    "Enforce HSTS. Disable HTTP entirely or redirect to HTTPS."
                ),
                references=["https://a2a-protocol.org/specification/#71-protocol-security"],
                affected_component="supportedInterfaces",
            ))
        return vulns

    # ------------------------------------------------------------------
    # Authentication posture
    # ------------------------------------------------------------------

    async def _check_auth_posture(
        self, client: httpx.AsyncClient, card: A2AAgentCard
    ) -> A2AAuthPosture:
        posture = A2AAuthPosture(
            requires_auth=bool(card.security_schemes),
            scheme_names=list(card.security_schemes.keys()),
            auth_type=self._infer_auth_type(card.security_schemes),
        )

        # Determine the JSON-RPC endpoint to probe
        jsonrpc_url = self._jsonrpc_endpoint(card)
        if not jsonrpc_url:
            posture.notes = "Could not determine JSON-RPC endpoint from Agent Card."
            return posture

        # Probe POST /message:send (JSON-RPC SendMessage) without auth
        send_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "SendMessage",
            "params": {
                "message": {
                    "role": "ROLE_USER",
                    "parts": [{"text": "offensive-ai probe"}],
                    "messageId": "offensive-ai-probe-001",
                }
            },
        }
        probe_client = httpx.AsyncClient(
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                "A2A-Version": "1.0",
            },
            timeout=self.timeout,
            trust_env=False,
            verify=False,  # noqa: S501 — intentional, probing posture
        )
        async with probe_client:
            try:
                resp = await probe_client.post(jsonrpc_url, json=send_payload)
                if resp.status_code == 200:
                    body = resp.text[:500]
                    # A 200 with a task or message result indicates no auth gate
                    if '"task"' in body or '"message"' in body or '"result"' in body:
                        posture.unauthenticated_access = True
                        posture.requires_auth = False
                        posture.auth_type = "none"
                        posture.notes = "Agent accepted SendMessage without authentication."
                elif resp.status_code in (401, 403):
                    posture.requires_auth = True
                    www_auth = resp.headers.get("WWW-Authenticate", "")
                    if "bearer" in www_auth.lower():
                        posture.auth_type = "bearer"
                    elif "basic" in www_auth.lower():
                        posture.auth_type = "basic"
                    posture.notes = f"HTTP {resp.status_code} — auth required."
            except Exception as exc:
                posture.notes = f"Auth probe error: {exc}"

        return posture

    @staticmethod
    def _infer_auth_type(security_schemes: dict[str, Any]) -> str:
        for scheme_def in security_schemes.values():
            if "openIdConnectSecurityScheme" in scheme_def:
                return "oidc"
            if "oauth2SecurityScheme" in scheme_def:
                return "oauth2"
            if "httpAuthSecurityScheme" in scheme_def:
                return "bearer"
            if "apiKeySecurityScheme" in scheme_def:
                return "apiKey"
            if "mutualTlsSecurityScheme" in scheme_def:
                return "mtls"
        return "unknown" if security_schemes else "none"

    def _jsonrpc_endpoint(self, card: A2AAgentCard) -> str | None:
        """Return the best JSON-RPC endpoint URL from the Agent Card."""
        for iface in card.supported_interfaces:
            binding = iface.get("protocolBinding", "").upper()
            if binding in ("JSONRPC", "JSON-RPC", "HTTP+JSON", "HTTP"):
                return str(iface.get("url", ""))
        # Fallback: first interface regardless of binding
        if card.supported_interfaces:
            return str(card.supported_interfaces[0].get("url", ""))
        # Last resort: construct from base target
        return self.target

    # ------------------------------------------------------------------
    # Extended Agent Card probe
    # ------------------------------------------------------------------

    async def _probe_extended_card(
        self, client: httpx.AsyncClient, card: A2AAgentCard
    ) -> A2AVulnerability | None:
        """Probe GET /extendedAgentCard without credentials."""
        extended_url = self.target.rstrip("/") + "/extendedAgentCard"
        probe_client = httpx.AsyncClient(
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            timeout=self.timeout,
            trust_env=False,
            verify=False,  # noqa: S501 — intentional
        )
        async with probe_client:
            try:
                resp = await probe_client.get(extended_url)
                if resp.status_code == 200:
                    return A2AVulnerability(
                        vuln_id="OAI-A2A-AUTH-002",
                        severity=A2AVulnSeverity.HIGH,
                        title="Extended Agent Card Accessible Without Authentication",
                        description=(
                            "GET /extendedAgentCard returned HTTP 200 without an "
                            "Authorization header, exposing additional skills, capabilities, "
                            "or configuration to anonymous clients."
                        ),
                        evidence=f"HTTP 200 from {extended_url} (no auth): {resp.text[:200]}",
                        remediation=(
                            "Enforce authentication on /extendedAgentCard. "
                            "See A2A spec §13.3 Extended Agent Card Access Control."
                        ),
                        references=["https://a2a-protocol.org/specification/#133-extended-agent-card-access-control"],
                        affected_component="/extendedAgentCard",
                    )
            except Exception:
                pass
        return None

    # ------------------------------------------------------------------
    # Static security analysis
    # ------------------------------------------------------------------

    def _analyze_security(self, result: A2AScanResult) -> list[A2AVulnerability]:
        vulns: list[A2AVulnerability] = []
        card = result.agent_card

        # 1. No securitySchemes declared
        if not card.security_schemes:
            vulns.append(A2AVulnerability(
                vuln_id="OAI-A2A-AUTH-001",
                severity=A2AVulnSeverity.HIGH,
                title="No Security Schemes Declared in Agent Card",
                description=(
                    "The Agent Card has no 'securitySchemes' field. Clients cannot "
                    "determine what credentials to present, and unauthenticated agents "
                    "may allow anonymous access."
                ),
                remediation=(
                    "Add a 'securitySchemes' block and reference it in 'security'. "
                    "Follow A2A spec §7 Authentication and Authorization."
                ),
                references=["https://a2a-protocol.org/specification/#7-authentication-and-authorization"],
                affected_component="securitySchemes",
            ))

        # 2. Unauthenticated access confirmed by probe
        if result.auth_posture.unauthenticated_access:
            vulns.append(A2AVulnerability(
                vuln_id="OAI-A2A-AUTH-003",
                severity=A2AVulnSeverity.HIGH,
                title="Unauthenticated A2A Task Operations Accepted",
                description=(
                    "The agent accepted a SendMessage JSON-RPC call without any "
                    "Authorization header and returned a successful response. "
                    "Any anonymous client can create and interact with tasks."
                ),
                evidence=result.auth_posture.notes,
                remediation=(
                    "Require valid authentication on all A2A endpoints. "
                    "Return HTTP 401 / JSON-RPC error -32700 for unauthenticated requests."
                ),
                references=["https://a2a-protocol.org/specification/#74-server-authentication-responsibilities"],
                affected_component="SendMessage",
            ))

        # 3. Agent Card not signed
        if not card.is_signed:
            vulns.append(A2AVulnerability(
                vuln_id="OAI-A2A-INT-001",
                severity=A2AVulnSeverity.MEDIUM,
                title="Agent Card Lacks JWS Signature",
                description=(
                    "The Agent Card served at /.well-known/agent-card.json does not "
                    "include a 'signatures' field. Without JWS signing, a MITM attacker "
                    "can tamper with the card to redirect clients to malicious endpoints "
                    "or suppress security scheme declarations."
                ),
                remediation=(
                    "Sign the Agent Card using JWS (RFC 7515) with ES256 or RS256. "
                    "Publish the JWKS at a URL referenced in the 'jku' header parameter. "
                    "See A2A spec §8.4 Agent Card Signing."
                ),
                references=["https://a2a-protocol.org/specification/#84-agent-card-signing"],
                affected_component="signatures",
            ))

        # 4. Secrets in Agent Card fields
        card_text = " ".join([
            card.name, card.description, card.documentation_url, card.provider_url,
            " ".join(s.description for s in card.skills),
            " ".join(e for s in card.skills for e in s.examples),
        ])
        secrets = scan_for_secrets(card_text)
        if secrets:
            vulns.append(A2AVulnerability(
                vuln_id="OAI-A2A-SEC-001",
                severity=A2AVulnSeverity.CRITICAL,
                title="Credentials or Secrets Embedded in Agent Card",
                description=(
                    "The publicly accessible Agent Card contains patterns matching "
                    "credentials, API keys, or tokens. These are exposed to any client "
                    "that fetches /.well-known/agent-card.json."
                ),
                evidence=f"Patterns matched: {', '.join(secrets[:5])}",
                remediation=(
                    "Remove all secrets from Agent Card fields. "
                    "Rotate any exposed credentials immediately."
                ),
                references=["https://cwe.mitre.org/data/definitions/312.html"],
                affected_component="agentCard",
            ))

        # 5. Dangerous skill keywords
        for skill in card.skills:
            if skill.has_dangerous_keywords:
                vulns.append(A2AVulnerability(
                    vuln_id="OAI-A2A-SKILL-001",
                    severity=A2AVulnSeverity.CRITICAL,
                    title=f"Dangerous Keywords in Skill: '{skill.name}'",
                    description=(
                        f"Skill '{skill.name}' description/tags contain keywords associated "
                        f"with shell execution, code evaluation, or destructive file operations: "
                        f"{', '.join(skill.dangerous_keywords_found[:5])}. "
                        "An attacker exploiting prompt injection may trigger these capabilities."
                    ),
                    evidence=skill.description[:300],
                    remediation=(
                        "Apply least-privilege. Remove shell/exec capabilities unless required. "
                        "Gate destructive actions behind TASK_STATE_AUTH_REQUIRED."
                    ),
                    references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
                    affected_component=f"skill:{skill.id}",
                ))
            # Secrets in skill descriptions/examples
            skill_text = skill.description + " " + " ".join(skill.examples)
            secrets = scan_for_secrets(skill_text)
            if secrets:
                vulns.append(A2AVulnerability(
                    vuln_id="OAI-A2A-SEC-002",
                    severity=A2AVulnSeverity.CRITICAL,
                    title=f"Secret Pattern in Skill Description: '{skill.name}'",
                    description=(
                        f"Skill '{skill.name}' description or examples contain patterns "
                        f"matching credentials/API keys: {', '.join(secrets[:5])}."
                    ),
                    evidence=skill.description[:300],
                    remediation=(
                        "Remove all secrets from skill descriptions and examples. "
                        "Rotate any exposed credentials."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/312.html"],
                    affected_component=f"skill:{skill.id}",
                ))

        # 6. Push notifications declared — note SSRF risk
        if card.capabilities.push_notifications:
            vulns.append(A2AVulnerability(
                vuln_id="OAI-A2A-SSRF-001",
                severity=A2AVulnSeverity.HIGH,
                title="Push Notifications Enabled — SSRF Attack Surface",
                description=(
                    "The Agent Card declares 'capabilities.pushNotifications: true'. "
                    "Without webhook URL validation, an attacker can register webhooks "
                    "targeting internal network services (cloud metadata endpoints, "
                    "internal APIs), causing SSRF."
                ),
                remediation=(
                    "Validate webhook URLs: reject private IP ranges "
                    "(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16). "
                    "Implement URL allowlists. See A2A spec §13.2."
                ),
                references=["https://a2a-protocol.org/specification/#132-push-notification-security"],
                affected_component="capabilities.pushNotifications",
            ))

        return vulns

    def _match_cves(self, card: A2AAgentCard, accessible_paths: list[str]) -> list[A2AVulnerability]:
        """Match CVE entries and convert to A2AVulnerability objects."""
        entries = match_cves(
            server_name=card.name or None,
            accessible_paths=accessible_paths,
        )
        vulns = []
        for entry in entries:
            vulns.append(A2AVulnerability(
                vuln_id=entry.vuln_id,
                cve_id=entry.cve_id,
                severity=A2AVulnSeverity(entry.severity),
                title=entry.title,
                description=entry.description,
                remediation=entry.remediation,
                references=entry.references,
            ))
        return vulns

    # ------------------------------------------------------------------
    # Optional LLM triage
    # ------------------------------------------------------------------

    def _phase_llm_triage(self, result: A2AScanResult) -> None:
        """Use LLM judge to enrich MEDIUM/LOW A2A findings."""
        ambiguous = {A2AVulnSeverity.MEDIUM, A2AVulnSeverity.LOW}
        for vuln in result.vulnerabilities:
            if vuln.severity not in ambiguous:
                continue
            if not self._judge:
                continue
            try:
                verdict = self._judge.evaluate(  # type: ignore[attr-defined]
                    category=vuln.vuln_id,
                    probe=vuln.title,
                    response=vuln.evidence or vuln.description,
                )
                vuln.llm_confidence = float(verdict.get("confidence", 0.0))
                vuln.llm_reasoning = str(verdict.get("reason", ""))
                if verdict.get("vulnerable") and vuln.llm_confidence > 0.7:
                    if vuln.severity == A2AVulnSeverity.LOW:
                        vuln.severity = A2AVulnSeverity.MEDIUM
                        vuln.evidence += " [LLM: upgraded from LOW]"
            except Exception as exc:  # noqa: BLE001
                logger.debug("LLM triage error for %s: %s", vuln.vuln_id, exc)
