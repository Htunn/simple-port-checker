"""Blockchain JSON-RPC node security scan/attack/contract-audit result models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .severity import VulnSeverity
from .vulnerability import BaseVulnerability

# Backward-compatible alias
BlockchainVulnSeverity = VulnSeverity


class ChainType(str, Enum):
    ETHEREUM = "ethereum"
    POLYGON = "polygon"
    BSC = "bsc"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    AVALANCHE = "avalanche"
    SUBSTRATE = "substrate"
    UNKNOWN = "unknown"


class BlockchainTransport(str, Enum):
    HTTP = "http"
    WS = "ws"


class BlockchainNodeInfo(BaseModel):
    """Fingerprint of a blockchain node derived from node-info RPC calls."""
    client_version: str = ""
    chain_type: ChainType = ChainType.UNKNOWN
    chain_id: str | None = None
    network_id: str | None = None
    is_syncing: bool | None = None
    peer_count: int | None = None
    latest_block: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class BlockchainVulnerability(BaseVulnerability):
    """A security vulnerability found on a blockchain JSON-RPC endpoint."""
    affected_method: str = ""   # e.g. "admin_peers", "eth_accounts"


class BlockchainScanResult(BaseModel):
    """Full security scan result for a single blockchain JSON-RPC endpoint."""
    target: str
    port: int = 8545
    transport: BlockchainTransport = BlockchainTransport.HTTP
    node_info: BlockchainNodeInfo = Field(default_factory=BlockchainNodeInfo)
    exposed_methods: list[str] = Field(default_factory=list)
    wallet_addresses: list[str] = Field(default_factory=list)
    is_mining: bool | None = None
    admin_api_exposed: bool = False
    debug_api_exposed: bool = False
    vulnerabilities: list[BlockchainVulnerability] = Field(default_factory=list)
    cve_matches: list[BlockchainVulnerability] = Field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None

    @property
    def critical_vulns(self) -> list[BlockchainVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == BlockchainVulnSeverity.CRITICAL]

    @property
    def high_vulns(self) -> list[BlockchainVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == BlockchainVulnSeverity.HIGH]

    @property
    def has_critical(self) -> bool:
        return bool(self.critical_vulns)

    @property
    def all_vulns(self) -> list[BlockchainVulnerability]:
        return self.vulnerabilities + self.cve_matches

    model_config = {"populate_by_name": True}


class BlockchainAttackResult(BaseModel):
    """Result of a single attack probe against a blockchain JSON-RPC endpoint."""
    attack_id: str
    target: str
    attack_type: str = ""   # "admin_abuse", "debug_leak", "unrestricted_signing"
    method: str = ""
    payload: str = ""
    response: str = ""
    triggered: bool = False
    severity: BlockchainVulnSeverity = BlockchainVulnSeverity.INFO
    title: str = ""
    description: str = ""
    evidence: str = ""
    error: str = ""


class BlockchainAttackReport(BaseModel):
    """Aggregated results from an authorized blockchain node attack session."""
    target: str
    authorized: bool = True
    attacks_run: int = 0
    attacks_triggered: int = 0
    results: list[BlockchainAttackResult] = Field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    authorization_note: str = (
        "This attack was performed under explicit authorization. "
        "Unauthorized use of this tool is illegal."
    )

    @property
    def successful_attacks(self) -> list[BlockchainAttackResult]:
        return [r for r in self.results if r.triggered]


class ContractFinding(BaseModel):
    """A single heuristic static-analysis finding for a smart contract ABI/bytecode."""
    finding_id: str
    severity: BlockchainVulnSeverity
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)


class ContractAuditResult(BaseModel):
    """Result of heuristic static analysis of a smart contract ABI and/or bytecode.

    This is best-effort opcode/ABI-shape heuristic analysis, not a full EVM
    disassembler or symbolic execution engine — findings require manual review.
    """
    target: str
    has_abi: bool = False
    has_bytecode: bool = False
    findings: list[ContractFinding] = Field(default_factory=list)
    risk_score: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None

    @property
    def critical_findings(self) -> list[ContractFinding]:
        return [f for f in self.findings if f.severity == BlockchainVulnSeverity.CRITICAL]

    @property
    def has_critical(self) -> bool:
        return bool(self.critical_findings)
