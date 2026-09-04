"""
Blockchain JSON-RPC node security advisory database.

Sources:
- Publicly documented misconfigurations of exposed Ethereum/EVM JSON-RPC nodes
  (unauthenticated admin_/debug_/personal_ namespaces, wallet enumeration via
  eth_accounts, unrestricted eth_sendTransaction / eth_sign on unlocked accounts)
- go-ethereum (geth) / Erigon / Besu / Nethermind RPC namespace documentation
- OWASP Smart Contract Top 10 (referenced by contract-audit findings)

This database is used by BlockchainScanner to classify discovered weaknesses.
All entries are for defensive/detection purposes only.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BlockchainCVEEntry:
    vuln_id: str
    cve_id: str | None
    severity: str                              # critical / high / medium / low / info
    title: str
    description: str
    affected_clients: list[str] = field(default_factory=list)  # clientVersion substrings
    requires_category: str = ""                # "" = universal, else "admin"/"debug"/"wallet"
    requires_client_version: bool = False
    remediation: str = ""
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Known advisories / misconfiguration classes
# ---------------------------------------------------------------------------
BLOCKCHAIN_CVE_DB: list[BlockchainCVEEntry] = [
    BlockchainCVEEntry(
        vuln_id="CHAIN-ADV-2024-001",
        cve_id=None,
        severity="critical",
        title="Unauthenticated JSON-RPC Endpoint Exposed",
        description=(
            "The node's JSON-RPC interface responded to unauthenticated requests. "
            "Any client that can reach the port can query chain state and, if "
            "admin/debug/wallet namespaces are enabled, control the node directly."
        ),
        remediation=(
            "Bind JSON-RPC to localhost or a private network. Place an authenticating "
            "reverse proxy in front of any publicly reachable RPC endpoint. Disable "
            "unused namespaces with --http.api / --ws.api allow-lists."
        ),
        references=[
            "https://geth.ethereum.org/docs/interacting-with-geth/rpc",
            "https://consensys.io/diligence/blog/2019/07/hack-your-way-to-safety/",
        ],
    ),
    BlockchainCVEEntry(
        vuln_id="CHAIN-ADV-2024-002",
        cve_id=None,
        severity="critical",
        title="Admin Namespace (admin_*) Enabled and Reachable",
        description=(
            "The admin_ RPC namespace answered without authentication. Methods such "
            "as admin_addPeer, admin_startRPC, and admin_datadir can be used to add "
            "malicious peers, expose additional interfaces, or disclose filesystem paths."
        ),
        affected_clients=["Geth", "erigon", "besu", "nethermind", "bor"],
        requires_category="admin",
        remediation=(
            "Never expose the admin_ namespace on a public interface. Use "
            "--http.api eth,net,web3 (excluding admin) or firewall the admin port."
        ),
        references=["https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-admin"],
    ),
    BlockchainCVEEntry(
        vuln_id="CHAIN-ADV-2024-003",
        cve_id=None,
        severity="high",
        title="Debug/Txpool Namespace Enabled and Reachable",
        description=(
            "The debug_ and/or txpool_ RPC namespace answered without authentication. "
            "Methods such as debug_traceTransaction, debug_dumpBlock, and "
            "txpool_content can leak internal state, storage slots, and pending "
            "transaction contents useful for front-running or key-material research."
        ),
        affected_clients=["Geth", "erigon", "besu"],
        requires_category="debug",
        remediation="Disable the debug_/txpool_ namespaces in production (--http.api without debug,txpool).",
        references=["https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-debug"],
    ),
    BlockchainCVEEntry(
        vuln_id="CHAIN-ADV-2024-004",
        cve_id=None,
        severity="critical",
        title="Wallet Address / Unlocked Account Enumeration",
        description=(
            "eth_accounts (or personal_listAccounts) returned one or more wallet "
            "addresses without authentication, indicating the node manages local "
            "keys directly. Combined with unauthenticated eth_sign/eth_sendTransaction, "
            "this can allow arbitrary message or transaction signing by any client."
        ),
        requires_category="wallet",
        remediation=(
            "Do not run production nodes with local unlocked accounts. Use an "
            "external signer (e.g. Clef) and disable personal_/eth_accounts on "
            "publicly reachable nodes."
        ),
        references=["https://geth.ethereum.org/docs/tools/clef/introduction"],
    ),
    BlockchainCVEEntry(
        vuln_id="CHAIN-ADV-2024-005",
        cve_id=None,
        severity="medium",
        title="Verbose Client Version Fingerprint Disclosure",
        description=(
            "web3_clientVersion returned a detailed client/version/OS/compiler "
            "string, simplifying targeted exploitation of known client CVEs."
        ),
        requires_client_version=True,
        remediation="Use a reverse proxy that strips or generalizes the web3_clientVersion response.",
        references=[],
    ),
]


# method -> category, used by the scanner/attacker to bucket exposed RPC methods
DANGEROUS_RPC_METHODS: dict[str, str] = {
    "admin_peers": "admin",
    "admin_nodeInfo": "admin",
    "admin_addPeer": "admin",
    "admin_removePeer": "admin",
    "admin_datadir": "admin",
    "admin_startRPC": "admin",
    "admin_startWS": "admin",
    "debug_traceTransaction": "debug",
    "debug_traceBlockByNumber": "debug",
    "debug_dumpBlock": "debug",
    "debug_storageRangeAt": "debug",
    "txpool_content": "debug",
    "txpool_status": "debug",
    "personal_listAccounts": "wallet",
    "personal_listWallets": "wallet",
    "personal_unlockAccount": "wallet",
    "eth_accounts": "wallet",
    "eth_sign": "wallet",
    "eth_sendTransaction": "wallet",
    "miner_start": "mining",
    "miner_stop": "mining",
    "miner_setEtherbase": "mining",
}

# clientVersion substring (lowercased) -> ChainType value. Kept as plain
# strings here to avoid a circular import with models.blockchain_result.
CLIENT_FINGERPRINTS: dict[str, str] = {
    "geth": "ethereum",
    "erigon": "ethereum",
    "besu": "ethereum",
    "nethermind": "ethereum",
    "reth": "ethereum",
    "bor": "polygon",
    "bsc": "bsc",
    "avalanchego": "avalanche",
    "substrate": "substrate",
    "parity": "substrate",
}

# chainId (decimal string) -> ChainType value
CHAIN_ID_MAP: dict[str, str] = {
    "1": "ethereum",
    "56": "bsc",
    "137": "polygon",
    "10": "optimism",
    "42161": "arbitrum",
    "43114": "avalanche",
}


def fingerprint_chain(client_version: str | None, chain_id: str | None) -> str:
    """Best-effort chain-type fingerprint from client version string / chainId."""
    if chain_id and chain_id in CHAIN_ID_MAP:
        return CHAIN_ID_MAP[chain_id]
    lowered = (client_version or "").lower()
    for needle, chain in CLIENT_FINGERPRINTS.items():
        if needle in lowered:
            return chain
    return "unknown"


def match_cves(
    client_version: str | None,
    exposed_categories: list[str],
) -> list[BlockchainCVEEntry]:
    """Match a discovered client version / exposed RPC categories against BLOCKCHAIN_CVE_DB."""
    matched: list[BlockchainCVEEntry] = []
    for entry in BLOCKCHAIN_CVE_DB:
        if entry.requires_category and entry.requires_category not in exposed_categories:
            continue
        if entry.requires_client_version and not client_version:
            continue
        if entry.affected_clients and client_version:
            if not any(c.lower() in client_version.lower() for c in entry.affected_clients):
                continue
        matched.append(entry)
    return matched
