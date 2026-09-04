"""Tests for the blockchain JSON-RPC attacker module."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from offensive_ai.exceptions import AuthorizationRequired
from offensive_ai.core.blockchain_attacker import BlockchainAttacker
from offensive_ai.models.blockchain_result import BlockchainAttackReport, BlockchainScanResult

TARGET_HOST = "node.example.com"
TARGET_URL = f"http://{TARGET_HOST}:8545"


def _rpc_factory(overrides: dict | None = None):
    overrides = overrides or {}
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


class TestBlockchainAttackerAuthorization:
    def test_requires_authorization(self):
        with pytest.raises(AuthorizationRequired):
            BlockchainAttacker(authorized=False)

    def test_authorized_instantiates(self):
        attacker = BlockchainAttacker(authorized=True)
        assert attacker.authorized is True

    def test_authorization_banner_logged(self, caplog):
        with caplog.at_level("WARNING"):
            BlockchainAttacker(authorized=True)
        assert any("AUTHORIZATION" in r.message.upper() for r in caplog.records)


class TestBlockchainAttackerHelpers:
    def test_resolve_url_with_scheme(self):
        assert BlockchainAttacker._resolve_url("https://node.example.com/rpc", 8545) == "https://node.example.com/rpc"

    def test_resolve_url_without_scheme(self):
        assert BlockchainAttacker._resolve_url("node.example.com", 8545) == "http://node.example.com:8545"


@pytest.mark.asyncio
class TestBlockchainAttackerSafeMode:
    async def test_admin_abuse_triggers_on_exposed_admin(self):
        attacker = BlockchainAttacker(authorized=True)
        overrides = {
            "admin_peers": [],
            "admin_nodeInfo": {"id": "abc"},
            "admin_addPeer": True,
        }
        with respx.mock:
            respx.post(TARGET_URL).mock(side_effect=_rpc_factory(overrides))
            report = await attacker.attack(target=TARGET_HOST, mode="safe")

        assert isinstance(report, BlockchainAttackReport)
        assert report.attacks_triggered == 3
        assert report.attacks_run == 3
        triggered_ids = {r.attack_id for r in report.successful_attacks}
        assert "CHAIN-ATK-ADMIN-001" in triggered_ids

    async def test_admin_abuse_no_trigger_when_blocked(self):
        attacker = BlockchainAttacker(authorized=True)
        with respx.mock:
            respx.post(TARGET_URL).mock(side_effect=_rpc_factory({}))
            report = await attacker.attack(target=TARGET_HOST, mode="safe")

        assert report.attacks_triggered == 0

    async def test_safe_mode_does_not_run_debug_or_signing(self):
        attacker = BlockchainAttacker(authorized=True)
        overrides = {
            "admin_peers": [],
            "debug_dumpBlock": {"root": "0x1"},
            "eth_accounts": ["0xabc"],
        }
        with respx.mock:
            respx.post(TARGET_URL).mock(side_effect=_rpc_factory(overrides))
            report = await attacker.attack(target=TARGET_HOST, mode="safe")

        attack_types = {r.attack_type for r in report.results}
        assert "debug_leak" not in attack_types
        assert "unrestricted_signing" not in attack_types


@pytest.mark.asyncio
class TestBlockchainAttackerDeepMode:
    async def test_deep_mode_runs_debug_leak(self):
        attacker = BlockchainAttacker(authorized=True)
        overrides = {"debug_dumpBlock": {"root": "0x1"}, "txpool_content": {"pending": {}}}
        with respx.mock:
            respx.post(TARGET_URL).mock(side_effect=_rpc_factory(overrides))
            report = await attacker.attack(target=TARGET_HOST, mode="deep")

        attack_types = {r.attack_type for r in report.results}
        assert "debug_leak" in attack_types
        triggered = {r.attack_id for r in report.successful_attacks}
        assert "CHAIN-ATK-DEBUG-001" in triggered

    async def test_deep_mode_discovers_accounts_and_signs(self):
        attacker = BlockchainAttacker(authorized=True)
        overrides = {
            "eth_accounts": ["0xdeadbeef00000000000000000000000000dead"],
            "eth_sign": "0xsignature",
            "eth_sendTransaction": "0xtxhash",
        }
        with respx.mock:
            respx.post(TARGET_URL).mock(side_effect=_rpc_factory(overrides))
            report = await attacker.attack(target=TARGET_HOST, mode="deep")

        attack_types = {r.attack_type for r in report.results}
        assert "unrestricted_signing" in attack_types
        signing_results = [r for r in report.results if r.attack_type == "unrestricted_signing"]
        assert all(r.triggered for r in signing_results)

    async def test_deep_mode_uses_scan_result_accounts_without_rediscovery(self):
        attacker = BlockchainAttacker(authorized=True)
        scan_result = BlockchainScanResult(
            target=TARGET_HOST, wallet_addresses=["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        )
        overrides = {"eth_sign": "0xsig", "eth_sendTransaction": "0xtx"}
        with respx.mock:
            respx.post(TARGET_URL).mock(side_effect=_rpc_factory(overrides))
            report = await attacker.attack(target=TARGET_HOST, mode="deep", scan_result=scan_result)

        signing_results = [r for r in report.results if r.attack_type == "unrestricted_signing"]
        assert len(signing_results) == 2
        assert all("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in r.evidence for r in signing_results)

    async def test_deep_mode_no_accounts_skips_signing(self):
        attacker = BlockchainAttacker(authorized=True)
        with respx.mock:
            respx.post(TARGET_URL).mock(side_effect=_rpc_factory({}))
            report = await attacker.attack(target=TARGET_HOST, mode="deep")

        attack_types = {r.attack_type for r in report.results}
        assert "unrestricted_signing" not in attack_types


class TestBlockchainAttackerLLMEnrichment:
    def test_enrich_with_llm_adds_analysis_to_evidence(self):
        attacker = BlockchainAttacker(authorized=True)

        class FakeJudge:
            provider = "openai"

            def evaluate(self, category, probe, response):
                return {"reason": "clear admin exposure", "confidence": 0.9, "vulnerable": True}

        attacker._judge = FakeJudge()
        report = BlockchainAttackReport(target=TARGET_HOST, attacks_run=1, attacks_triggered=1)
        from offensive_ai.models.blockchain_result import BlockchainAttackResult
        report.results.append(BlockchainAttackResult(
            attack_id="CHAIN-ATK-ADMIN-001", target=TARGET_URL, triggered=True, title="Admin exposed",
        ))
        attacker._enrich_with_llm(report)
        assert "LLM analysis" in report.results[0].evidence

    def test_enrich_with_llm_no_judge_noop(self):
        attacker = BlockchainAttacker(authorized=True)
        attacker._judge = None
        report = BlockchainAttackReport(target=TARGET_HOST)
        attacker._enrich_with_llm(report)  # should not raise

    def test_enrich_with_llm_no_triggered_noop(self):
        attacker = BlockchainAttacker(authorized=True)

        class FakeJudge:
            provider = "openai"

            def evaluate(self, *a, **kw):
                raise AssertionError("should not be called")

        attacker._judge = FakeJudge()
        report = BlockchainAttackReport(target=TARGET_HOST)
        attacker._enrich_with_llm(report)
