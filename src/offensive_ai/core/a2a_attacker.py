"""
A2A endpoint attacker module for authorized red-team engagements.

THIS MODULE PERFORMS ACTIVE ATTACKS AGAINST A2A ENDPOINTS.
It must ONLY be used against systems for which you have EXPLICIT WRITTEN
AUTHORIZATION. Unauthorized use may violate the Computer Fraud and Abuse Act,
the Computer Misuse Act, and equivalent laws worldwide.

Usage (requires --i-have-authorization flag via CLI, or authorized=True in code):
    attacker = A2AAttacker(authorized=True)
    report = await attacker.attack("https://agent.example.com", mode="deep")
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

import httpx

from ..exceptions import AuthorizationRequired
from ..utils.constants import USER_AGENT

from ._base import BaseAttacker
from ..models.a2a_result import (
    A2AAttackReport,
    A2AAttackResult,
    A2AScanResult,
    A2AVulnSeverity,
)
from ..utils.a2a_payloads import (
    AUTH_BYPASS_PAYLOADS,
    JSONRPC_MANIPULATION_PAYLOADS,
    MESSAGE_INJECTION_PAYLOADS,
    SSRF_WEBHOOK_PAYLOADS,
    TASK_ENUM_PAYLOADS,
)

logger = logging.getLogger(__name__)
_AGENT_CARD_PATH = "/.well-known/agent-card.json"


class A2AAttacker(BaseAttacker):
    """
    Active attack module for A2A (Agent-to-Agent) protocol endpoints.

    Requires authorized=True. Will refuse all operations if not authorized.
    """

    _MODULE_NAME = "A2A"

    def __init__(self, authorized: bool = False, judge: object | None = None) -> None:
        super().__init__(authorized=authorized, judge=judge)

    async def attack(
        self,
        target: str,
        mode: str = "safe",
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        scan_result: A2AScanResult | None = None,
    ) -> A2AAttackReport:
        """
        Run attack suite against the A2A agent.

        Args:
            target:      Base URL of the A2A agent (e.g. 'https://agent.example.com').
            mode:        "safe" (auth bypass probes only) or "deep" (full suite).
            headers:     HTTP headers for authenticated-context attacks.
            timeout:     Per-request timeout in seconds.
            verify_tls:  Verify TLS certificates.
            scan_result: Optional prior A2AScanResult to guide endpoint selection.
        """
        logger.warning(
            "A2A attack started against target=%s mode=%s timestamp=%s",
            target,
            mode,
            datetime.now(timezone.utc).isoformat(),
        )

        base_url = self._normalise_base(target)
        jsonrpc_url = self._resolve_jsonrpc_url(base_url, scan_result)
        headers = headers or {}
        start = time.monotonic()
        all_results: list[A2AAttackResult] = []

        # Auth bypass probes — always run (safe + deep)
        ab_results = await self._attack_auth_bypass(jsonrpc_url, headers, timeout)
        all_results.extend(ab_results)

        if mode == "deep":
            # SSRF via push notification webhooks
            ssrf_results = await self._attack_ssrf_webhook(jsonrpc_url, headers, timeout, scan_result)
            all_results.extend(ssrf_results)

            # Message injection via task message parts
            mi_results = await self._attack_message_injection(jsonrpc_url, headers, timeout)
            all_results.extend(mi_results)

            # Task enumeration / IDOR
            te_results = await self._attack_task_enumeration(jsonrpc_url, headers, timeout)
            all_results.extend(te_results)

            # JSON-RPC protocol manipulation
            jrpc_results = await self._attack_jsonrpc_manipulation(jsonrpc_url, headers, timeout)
            all_results.extend(jrpc_results)

        triggered = [r for r in all_results if r.triggered]
        report = A2AAttackReport(
            target=target,
            authorized=True,
            attacks_run=len(all_results),
            attacks_triggered=len(triggered),
            results=all_results,
            scan_duration=time.monotonic() - start,
        )

        # Optional LLM enrichment
        if self._judge and getattr(self._judge, "provider", None):
            self._enrich_with_llm(report)

        return report

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_base(target: str) -> str:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return target.rstrip("/")

    @staticmethod
    def _resolve_jsonrpc_url(base_url: str, scan_result: A2AScanResult | None) -> str:
        """Pick the best JSON-RPC endpoint from scan result or fall back to base URL."""
        if scan_result and scan_result.agent_card.supported_interfaces:
            for iface in scan_result.agent_card.supported_interfaces:
                binding = iface.get("protocolBinding", "").upper()
                if binding in ("JSONRPC", "JSON-RPC", "HTTP+JSON", "HTTP"):
                    return iface.get("url", base_url)
            # Fall back to first interface
            return scan_result.agent_card.supported_interfaces[0].get("url", base_url)
        return base_url

    def _make_client(
        self, extra_headers: dict | None = None, timeout: float = 15.0
    ) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                "A2A-Version": "1.0",
                **(extra_headers or {}),
            },
            timeout=timeout,
            trust_env=False,
            verify=False,  # noqa: S501 — intentional for attack testing
        )

    # ------------------------------------------------------------------
    # Auth bypass
    # ------------------------------------------------------------------

    async def _attack_auth_bypass(
        self,
        jsonrpc_url: str,
        headers: dict,
        timeout: float,
    ) -> list[A2AAttackResult]:
        results: list[A2AAttackResult] = []

        send_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "SendMessage",
            "params": {
                "message": {
                    "role": "ROLE_USER",
                    "parts": [{"text": "offensive-ai probe"}],
                    "messageId": "oai-ab-probe",
                }
            },
        }

        for probe in AUTH_BYPASS_PAYLOADS:
            test_headers = {**probe.get("headers", {}), **headers}
            triggered = False
            response_text = ""
            try:
                async with self._make_client(test_headers, timeout) as client:
                    resp = await client.post(jsonrpc_url, json=send_payload)
                    response_text = resp.text[:500]
                    if probe.get("detect") == "http_200" and resp.status_code == 200:
                        # Distinguish between a real success vs an error JSON-RPC response
                        if '"result"' in response_text or '"task"' in response_text:
                            triggered = True
            except Exception as exc:
                response_text = str(exc)

            results.append(A2AAttackResult(
                attack_id=probe["id"],
                target=jsonrpc_url,
                attack_type="auth_bypass",
                payload=str(probe.get("headers", {})),
                response=response_text,
                triggered=triggered,
                severity=A2AVulnSeverity(probe["severity"]) if triggered else A2AVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=response_text if triggered else "",
            ))
        return results

    # ------------------------------------------------------------------
    # SSRF via push notification webhook
    # ------------------------------------------------------------------

    async def _attack_ssrf_webhook(
        self,
        jsonrpc_url: str,
        headers: dict,
        timeout: float,
        scan_result: A2AScanResult | None,
    ) -> list[A2AAttackResult]:
        results: list[A2AAttackResult] = []

        # Only attempt SSRF if agent has push notification support
        if scan_result and not scan_result.agent_card.capabilities.push_notifications:
            return results

        for probe in SSRF_WEBHOOK_PAYLOADS:
            # Attempt to create a push notification config with the SSRF URL
            create_config_payload = {
                "jsonrpc": "2.0",
                "id": 50,
                "method": "CreateTaskPushNotificationConfig",
                "params": {
                    "taskId": "offensive-ai-probe-task",
                    "pushNotificationConfig": {
                        "url": probe["webhook_url"],
                        "authentication": {"scheme": "Bearer", "credentials": "offensive-ai-probe"},
                    },
                },
            }
            triggered = False
            response_text = ""
            evidence = ""
            try:
                async with self._make_client(headers, timeout) as client:
                    resp = await client.post(jsonrpc_url, json=create_config_payload)
                    response_text = resp.text[:500]
                    # A result (not an error about the task not found) suggests SSRF was attempted
                    if '"result"' in response_text:
                        for signal in probe.get("detect_in_response", []):
                            if signal.lower() in response_text.lower():
                                triggered = True
                                evidence = f"SSRF signal '{signal}' detected"
                                break
                        if not triggered:
                            # config accepted = agent will try outbound request
                            triggered = True
                            evidence = "Webhook config accepted with private/SSRF URL"
            except Exception as exc:
                response_text = str(exc)

            results.append(A2AAttackResult(
                attack_id=probe["id"],
                target=jsonrpc_url,
                attack_type="ssrf",
                payload=probe["webhook_url"],
                response=response_text,
                triggered=triggered,
                severity=A2AVulnSeverity(probe["severity"]) if triggered else A2AVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=evidence,
            ))
        return results

    # ------------------------------------------------------------------
    # Message injection (prompt injection via task message parts)
    # ------------------------------------------------------------------

    async def _attack_message_injection(
        self,
        jsonrpc_url: str,
        headers: dict,
        timeout: float,
    ) -> list[A2AAttackResult]:
        results: list[A2AAttackResult] = []

        for probe in MESSAGE_INJECTION_PAYLOADS:
            send_payload = {
                "jsonrpc": "2.0",
                "id": 60,
                "method": "SendMessage",
                "params": {
                    "message": {
                        "role": "ROLE_USER",
                        "parts": [{"text": probe["payload"]}],
                        "messageId": f"oai-mi-{probe['id'].lower()}",
                    }
                },
            }
            triggered = False
            response_text = ""
            evidence = ""
            try:
                async with self._make_client(headers, timeout) as client:
                    resp = await client.post(jsonrpc_url, json=send_payload)
                    response_text = resp.text[:1000]
                    for signal in probe.get("detect_in_response", []):
                        if signal.lower() in response_text.lower():
                            triggered = True
                            evidence = f"Injection signal '{signal}' found in response"
                            break
            except Exception as exc:
                response_text = str(exc)

            results.append(A2AAttackResult(
                attack_id=probe["id"],
                target=jsonrpc_url,
                attack_type="message_injection",
                payload=probe["payload"][:200],
                response=response_text,
                triggered=triggered,
                severity=A2AVulnSeverity(probe["severity"]) if triggered else A2AVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=evidence,
            ))
        return results

    # ------------------------------------------------------------------
    # Task enumeration / IDOR
    # ------------------------------------------------------------------

    async def _attack_task_enumeration(
        self,
        jsonrpc_url: str,
        headers: dict,
        timeout: float,
    ) -> list[A2AAttackResult]:
        results: list[A2AAttackResult] = []

        for probe in TASK_ENUM_PAYLOADS:
            get_payload = {
                "jsonrpc": "2.0",
                "id": 70,
                "method": "GetTask",
                "params": {"id": probe["task_id"]},
            }
            triggered = False
            response_text = ""
            evidence = ""
            try:
                async with self._make_client(headers, timeout) as client:
                    resp = await client.post(jsonrpc_url, json=get_payload)
                    response_text = resp.text[:500]
                    for signal in probe.get("detect_in_response", []):
                        if signal.lower() in response_text.lower():
                            triggered = True
                            evidence = f"Task data signal '{signal}' found (IDOR)"
                            break
            except Exception as exc:
                response_text = str(exc)

            results.append(A2AAttackResult(
                attack_id=probe["id"],
                target=jsonrpc_url,
                attack_type="task_enum",
                payload=probe["task_id"],
                response=response_text,
                triggered=triggered,
                severity=A2AVulnSeverity(probe["severity"]) if triggered else A2AVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=evidence,
            ))
        return results

    # ------------------------------------------------------------------
    # JSON-RPC protocol manipulation
    # ------------------------------------------------------------------

    async def _attack_jsonrpc_manipulation(
        self,
        jsonrpc_url: str,
        headers: dict,
        timeout: float,
    ) -> list[A2AAttackResult]:
        results: list[A2AAttackResult] = []

        for probe in JSONRPC_MANIPULATION_PAYLOADS:
            payload = {
                "jsonrpc": "2.0",
                "id": 80,
                "method": probe["method"],
                "params": probe.get("params", {}),
            }
            triggered = False
            response_text = ""
            evidence = ""
            try:
                async with self._make_client(headers, timeout) as client:
                    resp = await client.post(jsonrpc_url, json=payload)
                    response_text = resp.text[:500]
                    for signal in probe.get("detect_in_response", []):
                        if signal.lower() in response_text.lower():
                            triggered = True
                            evidence = f"Unexpected signal '{signal}' in response to malformed request"
                            break
            except Exception as exc:
                response_text = str(exc)

            results.append(A2AAttackResult(
                attack_id=probe["id"],
                target=jsonrpc_url,
                attack_type="jsonrpc",
                payload=json.dumps({"method": probe["method"], "params": probe.get("params", {})})[:200],
                response=response_text,
                triggered=triggered,
                severity=A2AVulnSeverity(probe["severity"]) if triggered else A2AVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=evidence,
            ))
        return results

    # ------------------------------------------------------------------
    # Optional LLM enrichment
    # ------------------------------------------------------------------

    def _enrich_with_llm(self, report: A2AAttackReport) -> None:
        if not self._judge:
            return
        triggered = [r for r in report.results if r.triggered]
        if not triggered:
            return
        try:
            summary = "; ".join(f"{r.attack_id}:{r.title}" for r in triggered[:5])
            verdict = self._judge.evaluate(
                category="A2A attack-path",
                probe=summary,
                response=f"{len(triggered)} attack(s) triggered",
            )
            reason = verdict.get("reason", "")
            if reason:
                triggered[0].evidence += f" [LLM analysis: {reason}]"
        except Exception as exc:  # noqa: BLE001
            logger.debug("LLM enrichment error: %s", exc)
