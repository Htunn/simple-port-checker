"""
Blockchain JSON-RPC node security scanner (Ethereum / EVM-compatible chains).

Connects to a node's JSON-RPC endpoint, fingerprints the client and chain,
enumerates exposed RPC namespaces (admin/debug/wallet/mining), and matches
findings against known misconfiguration advisories. Also provides a
best-effort static analyzer for smart contract ABI/bytecode.

This module talks raw JSON-RPC over plain HTTP(S) via httpx — no web3 SDK
is required. WebSocket RPC ("ws://", port 8546) is not yet supported; use
the HTTP JSON-RPC listener of the target node.

Usage:
    scanner = BlockchainScanner("http://node.example.com", port=8545)
    result = await scanner.scan()
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from ..models.blockchain_result import (
    BlockchainNodeInfo,
    BlockchainScanResult,
    BlockchainVulnerability,
    BlockchainVulnSeverity,
    ChainType,
    ContractAuditResult,
    ContractFinding,
)
from ..utils.blockchain_cve_db import fingerprint_chain, match_cves
from ..utils.blockchain_payloads import (
    DEBUG_PROBE_METHODS,
    MINING_STATUS_METHODS,
    NODE_INFO_METHODS,
    PEER_EXPOSURE_METHODS,
    WALLET_ENUM_METHODS,
)
from ..utils.constants import USER_AGENT

logger = logging.getLogger(__name__)


class BlockchainScanner:
    """Passive security scanner for blockchain JSON-RPC endpoints."""

    def __init__(
        self,
        target: str,
        port: int = 8545,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        judge: Any | None = None,
    ) -> None:
        """
        Args:
            target:     Hostname/IP, or full URL (http(s)://host[:port]).
            port:       RPC port, used when `target` has no scheme (default 8545).
            headers:    Extra HTTP headers.
            timeout:    Per-request timeout in seconds.
            verify_tls: Verify TLS certificates for https:// targets.
            judge:      Optional LLMJudge instance for AI-assisted triage.
        """
        self.target = target
        self.port = port
        self.headers = headers or {}
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._judge = judge

    def _rpc_url(self) -> str:
        if self.target.startswith(("http://", "https://")):
            return self.target
        return f"http://{self.target}:{self.port}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self) -> BlockchainScanResult:
        start = time.monotonic()
        url = self._rpc_url()
        result = BlockchainScanResult(target=self.target, port=self.port)

        async with httpx.AsyncClient(
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                **self.headers,
            },
            timeout=self.timeout,
            trust_env=False,
            verify=self.verify_tls,  # noqa: S501 — intentional for security scanning
        ) as client:
            node_info, error = await self._probe_node_info(client, url)
            if error:
                result.error = error
                result.scan_duration = time.monotonic() - start
                return result
            result.node_info = node_info

            exposed_categories: set[str] = set()

            peer_exposed = await self._probe_methods(client, url, PEER_EXPOSURE_METHODS)
            if peer_exposed:
                result.admin_api_exposed = True
                exposed_categories.add("admin")
                result.exposed_methods.extend(peer_exposed)

            wallets = await self._probe_wallets(client, url)
            if wallets:
                result.wallet_addresses = wallets
                exposed_categories.add("wallet")

            result.is_mining = await self._probe_mining(client, url)

            debug_exposed = await self._probe_methods(client, url, DEBUG_PROBE_METHODS)
            if debug_exposed:
                result.debug_api_exposed = True
                exposed_categories.add("debug")
                result.exposed_methods.extend(debug_exposed)

        result.vulnerabilities = self._analyze_security(result)
        result.cve_matches = self._match_cves(node_info.client_version, list(exposed_categories))

        if self._judge and getattr(self._judge, "provider", None):
            self._phase_llm_triage(result)

        result.scan_duration = time.monotonic() - start
        return result

    # ------------------------------------------------------------------
    # JSON-RPC helpers
    # ------------------------------------------------------------------

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

    async def _probe_node_info(
        self, client: httpx.AsyncClient, url: str
    ) -> tuple[BlockchainNodeInfo, str | None]:
        info = BlockchainNodeInfo()
        got_any = False
        for method, params in NODE_INFO_METHODS:
            value, err = await self._rpc_call(client, url, method, params)
            if err is not None:
                continue
            got_any = True
            if method == "web3_clientVersion":
                info.client_version = str(value)
            elif method == "net_version":
                info.network_id = str(value)
            elif method == "eth_chainId":
                info.chain_id = str(int(value, 16)) if isinstance(value, str) and value.startswith("0x") else str(value)
            elif method == "eth_blockNumber":
                info.latest_block = str(value)
            elif method == "eth_syncing":
                info.is_syncing = bool(value)
            elif method == "net_peerCount":
                try:
                    info.peer_count = int(value, 16) if isinstance(value, str) else int(value)
                except (TypeError, ValueError):
                    pass

        if not got_any:
            return info, (
                "No JSON-RPC methods responded — target may not be a blockchain "
                "RPC endpoint, or is unreachable."
            )
        info.chain_type = ChainType(fingerprint_chain(info.client_version, info.chain_id))
        return info, None

    async def _probe_methods(
        self, client: httpx.AsyncClient, url: str, methods: list[tuple[str, list]]
    ) -> list[str]:
        exposed = []
        for method, params in methods:
            _, err = await self._rpc_call(client, url, method, params)
            if err is None:
                exposed.append(method)
        return exposed

    async def _probe_wallets(self, client: httpx.AsyncClient, url: str) -> list[str]:
        for method, params in WALLET_ENUM_METHODS:
            value, err = await self._rpc_call(client, url, method, params)
            if err is None and isinstance(value, list) and value:
                return [str(a) for a in value]
        return []

    async def _probe_mining(self, client: httpx.AsyncClient, url: str) -> bool | None:
        value, err = await self._rpc_call(client, url, "eth_mining", [])
        if err is None:
            return bool(value)
        return None

    # ------------------------------------------------------------------
    # Security analysis (no network)
    # ------------------------------------------------------------------

    def _analyze_security(self, result: BlockchainScanResult) -> list[BlockchainVulnerability]:
        vulns: list[BlockchainVulnerability] = []

        if result.admin_api_exposed:
            vulns.append(BlockchainVulnerability(
                vuln_id="OAI-CHAIN-ADMIN-001",
                severity=BlockchainVulnSeverity.CRITICAL,
                title="Admin RPC Namespace Reachable Without Authentication",
                description=(
                    "One or more admin_* methods responded without authentication: "
                    f"{', '.join(result.exposed_methods) or 'admin_*'}. This namespace "
                    "can be used to add peers, disclose the node's data directory, "
                    "or reconfigure RPC interfaces."
                ),
                remediation="Disable the admin_ namespace on public interfaces (--http.api without admin).",
                references=["https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-admin"],
                affected_method="admin_*",
            ))

        if result.wallet_addresses:
            vulns.append(BlockchainVulnerability(
                vuln_id="OAI-CHAIN-WALLET-001",
                severity=BlockchainVulnSeverity.CRITICAL,
                title="Node-Managed Wallet Addresses Disclosed",
                description=(
                    f"eth_accounts/personal_listAccounts returned "
                    f"{len(result.wallet_addresses)} address(es) without authentication: "
                    f"{', '.join(result.wallet_addresses[:5])}."
                ),
                remediation="Disable local account management; use an external signer (e.g. Clef).",
                references=["https://geth.ethereum.org/docs/tools/clef/introduction"],
                affected_method="eth_accounts",
            ))

        if result.debug_api_exposed:
            vulns.append(BlockchainVulnerability(
                vuln_id="OAI-CHAIN-DEBUG-001",
                severity=BlockchainVulnSeverity.HIGH,
                title="Debug/Txpool RPC Namespace Reachable Without Authentication",
                description=(
                    "One or more debug_*/txpool_* methods responded without "
                    f"authentication: {', '.join(result.exposed_methods) or 'debug_*'}."
                ),
                remediation="Disable debug_/txpool_ namespaces in production.",
                references=["https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-debug"],
                affected_method="debug_*",
            ))

        if result.node_info.client_version:
            vulns.append(BlockchainVulnerability(
                vuln_id="OAI-CHAIN-FP-001",
                severity=BlockchainVulnSeverity.MEDIUM,
                title="Verbose Client Version Disclosed",
                description=f"web3_clientVersion returned: {result.node_info.client_version}",
                remediation="Use a reverse proxy to strip or generalize the client version string.",
                affected_method="web3_clientVersion",
            ))

        return vulns

    def _match_cves(
        self, client_version: str | None, exposed_categories: list[str]
    ) -> list[BlockchainVulnerability]:
        entries = match_cves(client_version, exposed_categories)
        return [
            BlockchainVulnerability(
                vuln_id=e.vuln_id,
                cve_id=e.cve_id,
                severity=BlockchainVulnSeverity(e.severity),
                title=e.title,
                description=e.description,
                remediation=e.remediation,
                references=e.references,
            )
            for e in entries
        ]

    def _phase_llm_triage(self, result: BlockchainScanResult) -> None:
        """Use LLM judge to enrich MEDIUM/LOW blockchain findings."""
        ambiguous = {BlockchainVulnSeverity.MEDIUM, BlockchainVulnSeverity.LOW}
        for vuln in result.vulnerabilities:
            if vuln.severity not in ambiguous or not self._judge:
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
                    if vuln.severity == BlockchainVulnSeverity.LOW:
                        vuln.severity = BlockchainVulnSeverity.MEDIUM
                        vuln.evidence += " [LLM: upgraded from LOW]"
            except Exception as exc:  # noqa: BLE001
                logger.debug("LLM triage error for %s: %s", vuln.vuln_id, exc)


# ===========================================================================
# Smart contract static analysis (heuristic — not a full disassembler)
# ===========================================================================

_SELFDESTRUCT = 0xFF
_DELEGATECALL = 0xF4
_CALL = 0xF1
_SSTORE = 0x55
_ARITHMETIC_OPS = {0x01, 0x02, 0x03}  # ADD, MUL, SUB
_INVALID = 0xFE

_SEVERITY_WEIGHT: dict[BlockchainVulnSeverity, int] = {
    BlockchainVulnSeverity.CRITICAL: 10,
    BlockchainVulnSeverity.HIGH: 6,
    BlockchainVulnSeverity.MEDIUM: 3,
    BlockchainVulnSeverity.LOW: 1,
    BlockchainVulnSeverity.INFO: 0,
}


def _iter_opcodes(bytecode_hex: str) -> list[int]:
    """Iterate raw EVM opcodes, skipping over PUSH1..PUSH32 immediate data."""
    code = bytes.fromhex(bytecode_hex.removeprefix("0x").strip())
    opcodes: list[int] = []
    i, n = 0, len(code)
    while i < n:
        op = code[i]
        opcodes.append(op)
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            i += 1 + (op - 0x5F)
        else:
            i += 1
    return opcodes


def _audit_abi(abi: list[dict]) -> list[ContractFinding]:
    findings: list[ContractFinding] = []
    functions = [f for f in abi if f.get("type") == "function"]
    names = {f.get("name", "").lower() for f in functions}

    if names & {"selfdestruct", "kill", "suicide"}:
        findings.append(ContractFinding(
            finding_id="CHAIN-SC-001",
            severity=BlockchainVulnSeverity.HIGH,
            title="Self-Destruct Function Exposed in ABI",
            description=(
                "ABI exposes a function matching selfdestruct/kill/suicide naming. "
                "Solidity ABI does not expose modifiers, so manual review is "
                "required to confirm access control (e.g. onlyOwner)."
            ),
            remediation="Restrict self-destruct capability to a trusted multisig/timelock.",
            references=["https://owasp.org/www-project-smart-contract-top-10/"],
        ))

    parameterless_withdraw = [
        f for f in functions
        if "withdraw" in f.get("name", "").lower()
        and f.get("stateMutability") in ("payable", "nonpayable")
        and not f.get("inputs")
    ]
    if parameterless_withdraw:
        fn_names = ", ".join(f["name"] for f in parameterless_withdraw)
        findings.append(ContractFinding(
            finding_id="CHAIN-SC-002",
            severity=BlockchainVulnSeverity.MEDIUM,
            title="Parameterless Withdraw Function",
            description=(
                f"Function(s) {fn_names} take no parameters — verify they restrict "
                "withdrawals to msg.sender's own balance rather than any address."
            ),
            remediation="Ensure withdraw functions are scoped to the caller's own balance/role.",
            references=["https://owasp.org/www-project-smart-contract-top-10/"],
        ))

    has_fallback = any(f.get("type") in ("fallback", "receive") for f in abi)
    if has_fallback and len(functions) <= 1:
        findings.append(ContractFinding(
            finding_id="CHAIN-SC-003",
            severity=BlockchainVulnSeverity.INFO,
            title="Possible Proxy Contract Pattern",
            description=(
                "Contract exposes a fallback/receive function with few or no named "
                "functions, consistent with a delegatecall proxy. Audit the "
                "implementation contract separately."
            ),
            remediation="Confirm the proxy follows a vetted standard (e.g. EIP-1967).",
            references=["https://eips.ethereum.org/EIPS/eip-1967"],
        ))

    return findings


def _audit_bytecode(opcodes: list[int]) -> list[ContractFinding]:
    findings: list[ContractFinding] = []

    if _SELFDESTRUCT in opcodes:
        findings.append(ContractFinding(
            finding_id="CHAIN-SC-010",
            severity=BlockchainVulnSeverity.HIGH,
            title="SELFDESTRUCT Opcode Present",
            description="Bytecode contains SELFDESTRUCT (0xff). Confirm it is access-controlled.",
            remediation="Restrict SELFDESTRUCT to a governance-controlled path; see EIP-6780.",
            references=["https://eips.ethereum.org/EIPS/eip-6780"],
        ))

    if _DELEGATECALL in opcodes:
        findings.append(ContractFinding(
            finding_id="CHAIN-SC-011",
            severity=BlockchainVulnSeverity.MEDIUM,
            title="DELEGATECALL Opcode Present",
            description=(
                "Bytecode contains DELEGATECALL (0xf4). Verify the target address is "
                "immutable/trusted — delegatecall to an attacker-controlled address "
                "is a full contract takeover primitive."
            ),
            remediation="Use a vetted proxy pattern (EIP-1967) with an access-controlled implementation slot.",
            references=["https://swcregistry.io/docs/SWC-112"],
        ))

    call_idx = opcodes.index(_CALL) if _CALL in opcodes else None
    sstore_idx = opcodes.index(_SSTORE) if _SSTORE in opcodes else None
    if call_idx is not None and sstore_idx is not None and call_idx < sstore_idx:
        findings.append(ContractFinding(
            finding_id="CHAIN-SC-012",
            severity=BlockchainVulnSeverity.MEDIUM,
            title="Possible Re-Entrancy Pattern (CALL Before SSTORE)",
            description=(
                "An external CALL opcode appears before an SSTORE in the bytecode "
                "stream — consistent with a checks-effects-interactions violation. "
                "Heuristic only; manual review required."
            ),
            remediation="Update state before external calls, or use a re-entrancy guard.",
            references=["https://swcregistry.io/docs/SWC-107"],
        ))

    if (_ARITHMETIC_OPS & set(opcodes)) and _INVALID not in opcodes:
        findings.append(ContractFinding(
            finding_id="CHAIN-SC-013",
            severity=BlockchainVulnSeverity.LOW,
            title="Arithmetic Without Visible Overflow Check",
            description=(
                "Bytecode performs ADD/SUB/MUL without the INVALID (0xfe) opcode "
                "pattern typical of Solidity >=0.8 checked arithmetic. May indicate "
                "an older compiler without automatic overflow protection. Heuristic only."
            ),
            remediation="Recompile with Solidity >=0.8.0, or use OpenZeppelin SafeMath for older versions.",
            references=["https://swcregistry.io/docs/SWC-101"],
        ))

    return findings


def analyze_contract(
    abi: list[dict] | None = None,
    bytecode: str | None = None,
    target: str = "contract",
) -> ContractAuditResult:
    """Run heuristic static analysis on a smart contract ABI and/or bytecode.

    Not a full disassembler or symbolic execution engine — findings flag
    patterns that warrant manual review, mapped to the OWASP Smart Contract
    Top 10 / SWC Registry where applicable.
    """
    result = ContractAuditResult(target=target, has_abi=bool(abi), has_bytecode=bool(bytecode))
    findings: list[ContractFinding] = []

    if abi:
        findings.extend(_audit_abi(abi))

    if bytecode:
        try:
            opcodes = _iter_opcodes(bytecode)
        except ValueError as exc:
            result.error = f"Invalid bytecode hex: {exc}"
            opcodes = []
        findings.extend(_audit_bytecode(opcodes))

    result.findings = findings
    result.risk_score = float(sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings))
    return result
