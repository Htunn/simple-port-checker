"""
Blockchain JSON-RPC node attacker module for authorized red-team engagements.

THIS MODULE PERFORMS ACTIVE ATTACKS AGAINST BLOCKCHAIN JSON-RPC ENDPOINTS.
It must ONLY be used against systems for which you have EXPLICIT WRITTEN
AUTHORIZATION. Unauthorized use may violate the Computer Fraud and Abuse Act,
the Computer Misuse Act, and equivalent laws worldwide.

Design note — every payload is engineered to be non-destructive:
  * admin_addPeer uses a non-routable loopback enode (no real peer is added)
  * eth_sign / eth_sendTransaction only target an account the node itself
    already discloses via eth_accounts, using a fixed benign message or a
    zero-value self-transfer — no funds are ever sent to a third party
  * debug_*/txpool_* probes are read-only

Usage (requires --i-have-authorization flag via CLI, or authorized=True in code):
    attacker = BlockchainAttacker(authorized=True)
    report = await attacker.attack(target, port=8545, mode="deep")
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ._base import BaseAttacker
from ..models.blockchain_result import (
    BlockchainAttackReport,
    BlockchainAttackResult,
    BlockchainScanResult,
    BlockchainVulnSeverity,
)
from ..utils.blockchain_payloads import (
    ADMIN_ABUSE_PAYLOADS,
    DEBUG_LEAK_PAYLOADS,
    UNRESTRICTED_SIGNING_PAYLOADS,
)
from ..utils.constants import USER_AGENT

logger = logging.getLogger(__name__)


class BlockchainAttacker(BaseAttacker):
    """
    Active attack module for blockchain JSON-RPC nodes (Ethereum/EVM-compatible).

    Requires authorized=True. Will refuse all operations if not authorized.
    """

    _MODULE_NAME = "BLOCKCHAIN"

    def __init__(self, authorized: bool = False, judge: Any | None = None) -> None:
        super().__init__(authorized=authorized, judge=judge)

    async def attack(
        self,
        target: str,
        port: int = 8545,
        mode: str = "safe",
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        scan_result: BlockchainScanResult | None = None,
    ) -> BlockchainAttackReport:
        """
        Run attack suite against the blockchain JSON-RPC endpoint.

        Args:
            target:      Hostname/IP, or full URL (http(s)://host[:port]).
            port:        RPC port, used when `target` has no scheme.
            mode:        "safe" (read-only admin/peer probes) or "deep"
                         (adds debug/txpool leak checks and unrestricted
                         signing tests against discovered accounts).
            headers:     HTTP headers.
            timeout:     Per-request timeout.
            verify_tls:  Verify TLS certificates for https:// targets.
            scan_result: Optional prior BlockchainScanResult to reuse discovered accounts.
        """
        logger.warning(
            "Blockchain attack started against target=%s port=%s mode=%s timestamp=%s",
            target,
            port,
            mode,
            datetime.now(timezone.utc).isoformat(),
        )

        url = self._resolve_url(target, port)
        headers = headers or {}
        start = time.monotonic()
        all_results: list[BlockchainAttackResult] = []

        async with self._make_client(headers, timeout, verify_tls) as client:
            # Admin namespace abuse — always run (safe + deep); every payload
            # is read-only or uses a non-functional loopback value.
            all_results.extend(await self._attack_admin_abuse(client, url))

            if mode == "deep":
                all_results.extend(await self._attack_debug_leak(client, url))

                accounts = (scan_result.wallet_addresses if scan_result else []) or (
                    await self._discover_accounts(client, url)
                )
                if accounts:
                    all_results.extend(
                        await self._attack_unrestricted_signing(client, url, accounts)
                    )

        triggered = [r for r in all_results if r.triggered]
        report = BlockchainAttackReport(
            target=target,
            authorized=True,
            attacks_run=len(all_results),
            attacks_triggered=len(triggered),
            results=all_results,
            scan_duration=time.monotonic() - start,
        )

        if self._judge and getattr(self._judge, "provider", None):
            self._enrich_with_llm(report)

        return report

    def _enrich_with_llm(self, report: BlockchainAttackReport) -> None:
        """Use LLM judge to build an attack-path narrative for triggered attacks."""
        if not self._judge:
            return
        triggered = [r for r in report.results if r.triggered]
        if not triggered:
            return
        try:
            summary = "; ".join(f"{r.attack_id}:{r.title}" for r in triggered[:5])
            verdict = self._judge.evaluate(
                category="Blockchain attack-path",
                probe=summary,
                response=f"{len(triggered)} attack(s) triggered",
            )
            reason = verdict.get("reason", "")
            if reason:
                triggered[0].evidence += f" [LLM analysis: {reason}]"
        except Exception as exc:  # noqa: BLE001
            logger.debug("LLM enrichment error: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_url(target: str, port: int) -> str:
        if target.startswith(("http://", "https://")):
            return target
        return f"http://{target}:{port}"

    @staticmethod
    def _make_client(
        extra_headers: dict[str, str], timeout: float, verify_tls: bool
    ) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                **extra_headers,
            },
            timeout=timeout,
            trust_env=False,
            verify=verify_tls,  # noqa: S501 — intentional for attack testing
        )

    @staticmethod
    async def _rpc_call(
        client: httpx.AsyncClient, url: str, method: str, params: list, req_id: int = 1
    ) -> tuple[Any, dict | None]:
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        try:
            resp = await client.post(url, json=payload)
            data = resp.json()
            if "error" in data and data["error"] is not None:
                return None, data["error"]
            return data.get("result"), None
        except Exception as exc:  # noqa: BLE001
            return None, {"message": str(exc)}

    async def _discover_accounts(self, client: httpx.AsyncClient, url: str) -> list[str]:
        for method in ("eth_accounts", "personal_listAccounts"):
            value, err = await self._rpc_call(client, url, method, [])
            if err is None and isinstance(value, list) and value:
                return [str(a) for a in value]
        return []

    # ------------------------------------------------------------------
    # Admin namespace abuse
    # ------------------------------------------------------------------

    async def _attack_admin_abuse(
        self, client: httpx.AsyncClient, url: str
    ) -> list[BlockchainAttackResult]:
        results: list[BlockchainAttackResult] = []
        for probe in ADMIN_ABUSE_PAYLOADS:
            value, err = await self._rpc_call(client, url, probe["method"], probe["params"])
            triggered = err is None
            results.append(BlockchainAttackResult(
                attack_id=probe["id"],
                target=url,
                attack_type="admin_abuse",
                method=probe["method"],
                payload=str(probe["params"]),
                response=str(value)[:300] if triggered else str(err),
                triggered=triggered,
                severity=BlockchainVulnSeverity(probe["severity"]) if triggered else BlockchainVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=str(value)[:300] if triggered else "",
            ))
        return results

    # ------------------------------------------------------------------
    # Debug / txpool information leak
    # ------------------------------------------------------------------

    async def _attack_debug_leak(
        self, client: httpx.AsyncClient, url: str
    ) -> list[BlockchainAttackResult]:
        results: list[BlockchainAttackResult] = []
        for probe in DEBUG_LEAK_PAYLOADS:
            value, err = await self._rpc_call(client, url, probe["method"], probe["params"])
            triggered = err is None and value is not None
            results.append(BlockchainAttackResult(
                attack_id=probe["id"],
                target=url,
                attack_type="debug_leak",
                method=probe["method"],
                payload=str(probe["params"]),
                response=str(value)[:300] if triggered else str(err),
                triggered=triggered,
                severity=BlockchainVulnSeverity(probe["severity"]) if triggered else BlockchainVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=str(value)[:300] if triggered else "",
            ))
        return results

    # ------------------------------------------------------------------
    # Unrestricted signing / transaction capability
    # ------------------------------------------------------------------

    async def _attack_unrestricted_signing(
        self, client: httpx.AsyncClient, url: str, accounts: list[str]
    ) -> list[BlockchainAttackResult]:
        results: list[BlockchainAttackResult] = []
        account = accounts[0]
        for probe in UNRESTRICTED_SIGNING_PAYLOADS:
            params = [
                p.format(account=account) if isinstance(p, str) else
                {k: (v.format(account=account) if isinstance(v, str) else v) for k, v in p.items()}
                for p in probe["params_template"]
            ]
            value, err = await self._rpc_call(client, url, probe["method"], params)
            triggered = err is None and value is not None
            results.append(BlockchainAttackResult(
                attack_id=probe["id"],
                target=url,
                attack_type="unrestricted_signing",
                method=probe["method"],
                payload=str(params),
                response=str(value)[:300] if triggered else str(err),
                triggered=triggered,
                severity=BlockchainVulnSeverity(probe["severity"]) if triggered else BlockchainVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=f"account={account} result={value}"[:300] if triggered else "",
            ))
        return results
