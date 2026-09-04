"""Tests for the blockchain JSON-RPC scanner, CVE database, payloads, and result models."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from offensive_ai.core.blockchain_scanner import BlockchainScanner, analyze_contract
from offensive_ai.models.blockchain_result import (
    BlockchainNodeInfo,
    BlockchainScanResult,
    BlockchainVulnerability,
    BlockchainVulnSeverity,
    ChainType,
    ContractAuditResult,
)
from offensive_ai.utils.blockchain_cve_db import (
    BLOCKCHAIN_CVE_DB,
    DANGEROUS_RPC_METHODS,
    fingerprint_chain,
    match_cves,
)
from offensive_ai.utils.blockchain_payloads import (
    ADMIN_ABUSE_PAYLOADS,
    DEBUG_LEAK_PAYLOADS,
    DEBUG_PROBE_METHODS,
    MINING_STATUS_METHODS,
    NODE_INFO_METHODS,
    PEER_EXPOSURE_METHODS,
    UNRESTRICTED_SIGNING_PAYLOADS,
    WALLET_ENUM_METHODS,
)

TARGET = "http://node.example.com:8545"


# ---------------------------------------------------------------------------
# CVE Database tests
# ---------------------------------------------------------------------------

class TestBlockchainCveDatabase:
    def test_db_is_non_empty(self):
        assert len(BLOCKCHAIN_CVE_DB) >= 5

    def test_all_entries_have_required_fields(self):
        for entry in BLOCKCHAIN_CVE_DB:
            assert entry.vuln_id
            assert entry.severity in ("critical", "high", "medium", "low", "info")
            assert entry.title
            assert entry.description

    def test_universal_entry_always_matches(self):
        matches = match_cves(client_version=None, exposed_categories=[])
        ids = {m.vuln_id for m in matches}
        assert "CHAIN-ADV-2024-001" in ids

    def test_admin_category_required(self):
        without_admin = {m.vuln_id for m in match_cves(None, [])}
        with_admin = {m.vuln_id for m in match_cves(None, ["admin"])}
        assert "CHAIN-ADV-2024-002" not in without_admin
        assert "CHAIN-ADV-2024-002" in with_admin

    def test_debug_category_required(self):
        with_debug = {m.vuln_id for m in match_cves(None, ["debug"])}
        assert "CHAIN-ADV-2024-003" in with_debug

    def test_wallet_category_required(self):
        with_wallet = {m.vuln_id for m in match_cves(None, ["wallet"])}
        assert "CHAIN-ADV-2024-004" in with_wallet

    def test_client_version_required_entry(self):
        without_version = {m.vuln_id for m in match_cves(None, [])}
        with_version = {m.vuln_id for m in match_cves("Geth/v1.13.0", [])}
        assert "CHAIN-ADV-2024-005" not in without_version
        assert "CHAIN-ADV-2024-005" in with_version

    def test_affected_clients_filter(self):
        matches = match_cves("Geth/v1.13.0", ["admin"])
        ids = {m.vuln_id for m in matches}
        assert "CHAIN-ADV-2024-002" in ids
        non_matching = match_cves("SomeOtherClient/v1.0", ["admin"])
        ids2 = {m.vuln_id for m in non_matching}
        assert "CHAIN-ADV-2024-002" not in ids2

    def test_dangerous_rpc_methods_categories(self):
        assert DANGEROUS_RPC_METHODS["admin_peers"] == "admin"
        assert DANGEROUS_RPC_METHODS["eth_accounts"] == "wallet"
        assert DANGEROUS_RPC_METHODS["debug_dumpBlock"] == "debug"

    def test_fingerprint_chain_by_client(self):
        assert fingerprint_chain("Geth/v1.13.0-stable/linux-amd64/go1.21", None) == "ethereum"
        assert fingerprint_chain("bor/v1.0.0", None) == "polygon"

    def test_fingerprint_chain_by_chain_id(self):
        assert fingerprint_chain(None, "56") == "bsc"
        assert fingerprint_chain(None, "137") == "polygon"

    def test_fingerprint_chain_unknown(self):
        assert fingerprint_chain("SomeWeirdClient", None) == "unknown"


# ---------------------------------------------------------------------------
# Payload structure tests
# ---------------------------------------------------------------------------

class TestBlockchainPayloads:
    def test_node_info_methods_shape(self):
        for method, params in NODE_INFO_METHODS:
            assert isinstance(method, str) and method
            assert isinstance(params, list)

    def test_all_probe_lists_non_empty(self):
        for lst in (
            NODE_INFO_METHODS, PEER_EXPOSURE_METHODS, WALLET_ENUM_METHODS,
            MINING_STATUS_METHODS, DEBUG_PROBE_METHODS,
        ):
            assert len(lst) > 0

    def test_admin_abuse_payloads_ids_unique(self):
        ids = [p["id"] for p in ADMIN_ABUSE_PAYLOADS]
        assert len(ids) == len(set(ids))
        for p in ADMIN_ABUSE_PAYLOADS:
            assert "safety_note" in p
            assert p["severity"] in ("critical", "high", "medium", "low", "info")

    def test_admin_add_peer_uses_loopback(self):
        add_peer = next(p for p in ADMIN_ABUSE_PAYLOADS if p["method"] == "admin_addPeer")
        assert "127.0.0.1" in add_peer["params"][0]

    def test_debug_leak_payloads_are_read_only(self):
        for p in DEBUG_LEAK_PAYLOADS:
            assert "safety_note" in p

    def test_signing_payloads_zero_value(self):
        send_tx = next(p for p in UNRESTRICTED_SIGNING_PAYLOADS if p["method"] == "eth_sendTransaction")
        assert send_tx["params_template"][0]["value"] == "0x0"


# ---------------------------------------------------------------------------
# Scanner static analysis tests (no network)
# ---------------------------------------------------------------------------

class TestBlockchainScannerAnalyzeSecurity:
    def _make_scanner(self):
        return BlockchainScanner(target=TARGET)

    def test_admin_exposed_creates_critical_vuln(self):
        scanner = self._make_scanner()
        result = BlockchainScanResult(target=TARGET, admin_api_exposed=True, exposed_methods=["admin_peers"])
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-CHAIN-ADMIN-001" in ids

    def test_wallet_disclosed_creates_critical_vuln(self):
        scanner = self._make_scanner()
        result = BlockchainScanResult(target=TARGET, wallet_addresses=["0xabc123"])
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-CHAIN-WALLET-001" in ids

    def test_debug_exposed_creates_high_vuln(self):
        scanner = self._make_scanner()
        result = BlockchainScanResult(target=TARGET, debug_api_exposed=True, exposed_methods=["debug_dumpBlock"])
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-CHAIN-DEBUG-001" in ids

    def test_client_version_creates_medium_vuln(self):
        scanner = self._make_scanner()
        result = BlockchainScanResult(target=TARGET)
        result.node_info = BlockchainNodeInfo(client_version="Geth/v1.13.0")
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-CHAIN-FP-001" in ids

    def test_clean_result_no_vulns(self):
        scanner = self._make_scanner()
        result = BlockchainScanResult(target=TARGET)
        vulns = scanner._analyze_security(result)
        assert vulns == []

    def test_match_cves_delegates(self):
        scanner = self._make_scanner()
        vulns = scanner._match_cves("Geth/v1.13.0", ["admin"])
        assert any(isinstance(v, BlockchainVulnerability) for v in vulns)


# ---------------------------------------------------------------------------
# Contract audit (heuristic static analysis)
# ---------------------------------------------------------------------------

class TestAnalyzeContract:
    def test_empty_input_no_findings(self):
        result = analyze_contract()
        assert isinstance(result, ContractAuditResult)
        assert result.findings == []
        assert result.risk_score == 0.0

    def test_selfdestruct_abi_flagged(self):
        abi = [{"type": "function", "name": "kill", "inputs": [], "stateMutability": "nonpayable"}]
        result = analyze_contract(abi=abi)
        ids = {f.finding_id for f in result.findings}
        assert "CHAIN-SC-001" in ids

    def test_parameterless_withdraw_flagged(self):
        abi = [{"type": "function", "name": "withdraw", "inputs": [], "stateMutability": "nonpayable"}]
        result = analyze_contract(abi=abi)
        ids = {f.finding_id for f in result.findings}
        assert "CHAIN-SC-002" in ids

    def test_proxy_pattern_flagged(self):
        abi = [{"type": "fallback", "stateMutability": "payable"}]
        result = analyze_contract(abi=abi)
        ids = {f.finding_id for f in result.findings}
        assert "CHAIN-SC-003" in ids

    def test_selfdestruct_opcode_flagged(self):
        # PUSH1 0x00, SELFDESTRUCT
        bytecode = "0x6000ff"
        result = analyze_contract(bytecode=bytecode)
        ids = {f.finding_id for f in result.findings}
        assert "CHAIN-SC-010" in ids

    def test_delegatecall_opcode_flagged(self):
        bytecode = "0xf4"
        result = analyze_contract(bytecode=bytecode)
        ids = {f.finding_id for f in result.findings}
        assert "CHAIN-SC-011" in ids

    def test_reentrancy_pattern_flagged(self):
        # CALL (0xf1) followed later by SSTORE (0x55)
        bytecode = "0xf100000055"
        result = analyze_contract(bytecode=bytecode)
        ids = {f.finding_id for f in result.findings}
        assert "CHAIN-SC-012" in ids

    def test_sstore_before_call_not_flagged_as_reentrancy(self):
        bytecode = "0x55000000f1"
        result = analyze_contract(bytecode=bytecode)
        ids = {f.finding_id for f in result.findings}
        assert "CHAIN-SC-012" not in ids

    def test_unchecked_arithmetic_flagged(self):
        bytecode = "0x01"  # ADD with no INVALID opcode
        result = analyze_contract(bytecode=bytecode)
        ids = {f.finding_id for f in result.findings}
        assert "CHAIN-SC-013" in ids

    def test_checked_arithmetic_not_flagged(self):
        bytecode = "0x01fe"  # ADD followed by INVALID (checked math pattern)
        result = analyze_contract(bytecode=bytecode)
        ids = {f.finding_id for f in result.findings}
        assert "CHAIN-SC-013" not in ids

    def test_push_data_not_misparsed_as_opcode(self):
        # PUSH1 0xff — the 0xff is data, not a SELFDESTRUCT opcode
        bytecode = "0x60ff"
        result = analyze_contract(bytecode=bytecode)
        ids = {f.finding_id for f in result.findings}
        assert "CHAIN-SC-010" not in ids

    def test_invalid_bytecode_sets_error(self):
        result = analyze_contract(bytecode="0xZZ")
        assert result.error is not None

    def test_risk_score_increases_with_severity(self):
        low_result = analyze_contract(bytecode="0x01")
        high_result = analyze_contract(bytecode="0x6000ff")
        assert high_result.risk_score > low_result.risk_score

    def test_has_abi_and_bytecode_flags(self):
        result = analyze_contract(abi=[{"type": "function", "name": "foo"}], bytecode="0x00")
        assert result.has_abi is True
        assert result.has_bytecode is True


# ---------------------------------------------------------------------------
# Scanner HTTP integration (mocked)
# ---------------------------------------------------------------------------

def _rpc_factory(overrides: dict | None = None):
    overrides = overrides or {}
    default_ok = {"jsonrpc": "2.0", "id": 1, "result": None}
    default_error = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "method not found"}}

    def factory(request: httpx.Request):
        body = json.loads(request.content)
        method = body.get("method", "")
        if method in overrides:
            value = overrides[method]
            if value is None:
                return httpx.Response(200, json=default_error)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body.get("id"), "result": value})
        return httpx.Response(200, json=default_error)

    return factory


@pytest.mark.asyncio
class TestBlockchainScannerIntegration:
    async def test_scan_no_rpc_response_sets_error(self):
        scanner = BlockchainScanner(target=TARGET)
        with respx.mock:
            respx.post(TARGET).mock(side_effect=_rpc_factory({}))
            result = await scanner.scan()
        assert result.error is not None

    async def test_scan_fingerprints_geth(self):
        scanner = BlockchainScanner(target=TARGET)
        overrides = {
            "web3_clientVersion": "Geth/v1.13.0-stable/linux-amd64/go1.21",
            "net_version": "1",
            "eth_chainId": "0x1",
            "eth_blockNumber": "0x123",
            "eth_syncing": False,
            "net_peerCount": "0x5",
        }
        with respx.mock:
            respx.post(TARGET).mock(side_effect=_rpc_factory(overrides))
            result = await scanner.scan()
        assert result.error is None
        assert result.node_info.client_version.startswith("Geth")
        assert result.node_info.chain_type == ChainType.ETHEREUM
        assert result.node_info.chain_id == "1"
        assert result.node_info.peer_count == 5

    async def test_scan_detects_admin_exposure(self):
        scanner = BlockchainScanner(target=TARGET)
        overrides = {
            "web3_clientVersion": "Geth/v1.13.0",
            "admin_nodeInfo": {"id": "abc"},
            "admin_peers": [],
        }
        with respx.mock:
            respx.post(TARGET).mock(side_effect=_rpc_factory(overrides))
            result = await scanner.scan()
        assert result.admin_api_exposed is True
        ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OAI-CHAIN-ADMIN-001" in ids
        cve_ids = {v.vuln_id for v in result.cve_matches}
        assert "CHAIN-ADV-2024-002" in cve_ids

    async def test_scan_detects_wallet_exposure(self):
        scanner = BlockchainScanner(target=TARGET)
        overrides = {
            "web3_clientVersion": "Geth/v1.13.0",
            "eth_accounts": ["0xdeadbeef00000000000000000000000000dead"],
        }
        with respx.mock:
            respx.post(TARGET).mock(side_effect=_rpc_factory(overrides))
            result = await scanner.scan()
        assert result.wallet_addresses == ["0xdeadbeef00000000000000000000000000dead"]
        ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OAI-CHAIN-WALLET-001" in ids

    async def test_scan_detects_debug_exposure(self):
        scanner = BlockchainScanner(target=TARGET)
        overrides = {
            "web3_clientVersion": "Geth/v1.13.0",
            "debug_dumpBlock": {"root": "0x1"},
        }
        with respx.mock:
            respx.post(TARGET).mock(side_effect=_rpc_factory(overrides))
            result = await scanner.scan()
        assert result.debug_api_exposed is True

    async def test_scan_duration_positive(self):
        scanner = BlockchainScanner(target=TARGET)
        with respx.mock:
            respx.post(TARGET).mock(side_effect=_rpc_factory({"web3_clientVersion": "Geth/v1.13.0"}))
            result = await scanner.scan()
        assert result.scan_duration >= 0

    async def test_rpc_url_uses_port_when_no_scheme(self):
        scanner = BlockchainScanner(target="node.example.com", port=8545)
        assert scanner._rpc_url() == "http://node.example.com:8545"

    async def test_rpc_url_preserves_full_url(self):
        scanner = BlockchainScanner(target="https://node.example.com/rpc")
        assert scanner._rpc_url() == "https://node.example.com/rpc"
