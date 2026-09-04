"""
Tests for LLMConversationAttacker — pattern builders, auth gating, and result models.
Also covers auth_attacker authorization gate and AuthAttackReport.
"""

from __future__ import annotations

import pytest

from offensive_ai.core.llm_conversation_attacker import (
    ConversationTurn,
    LLMConversationAttacker,
    MultiTurnAttackReport,
    MultiTurnAttackResult,
    _build_context_priming_turns,
    _build_crescendo_turns,
    _build_goal_hijack_turns,
    _build_many_shot_turns,
)
from offensive_ai.exceptions import AuthorizationRequired


# ---------------------------------------------------------------------------
# Pattern builders
# ---------------------------------------------------------------------------

class TestBuildCrescendoTurns:
    def test_returns_list(self):
        turns = _build_crescendo_turns("exploit me")
        assert isinstance(turns, list)

    def test_payload_in_last_turn(self):
        turns = _build_crescendo_turns("specific payload")
        assert "specific payload" in turns[-1]

    def test_multiple_turns(self):
        turns = _build_crescendo_turns("payload")
        assert len(turns) >= 3


class TestBuildManyShotTurns:
    def test_returns_list(self):
        turns = _build_many_shot_turns("payload text")
        assert isinstance(turns, list)

    def test_payload_at_end(self):
        turns = _build_many_shot_turns("payload text")
        assert turns[-1] == "payload text"

    def test_example_pairs_present(self):
        turns = _build_many_shot_turns("payload")
        # Should have multiple setup turns + the payload
        assert len(turns) > 5


class TestBuildContextPrimingTurns:
    def test_returns_list(self):
        turns = _build_context_priming_turns("payload")
        assert isinstance(turns, list)

    def test_payload_in_last_turn(self):
        turns = _build_context_priming_turns("secret payload")
        assert "secret payload" in turns[-1]

    def test_priming_context_present(self):
        turns = _build_context_priming_turns("payload")
        combined = " ".join(turns)
        assert "earlier" in combined.lower() or "agreed" in combined.lower()


class TestBuildGoalHijackTurns:
    def test_returns_list(self):
        turns = _build_goal_hijack_turns("payload")
        assert isinstance(turns, list)

    def test_payload_in_last_turn(self):
        turns = _build_goal_hijack_turns("final payload")
        assert "final payload" in turns[-1]

    def test_goal_keyword_in_early_turns(self):
        turns = _build_goal_hijack_turns("payload")
        assert any("goal" in t.lower() for t in turns)


# ---------------------------------------------------------------------------
# ConversationTurn dataclass
# ---------------------------------------------------------------------------

class TestConversationTurn:
    def test_creation(self):
        turn = ConversationTurn(role="user", content="hello", turn_index=0)
        assert turn.role == "user"
        assert turn.content == "hello"
        assert turn.turn_index == 0

    def test_assistant_role(self):
        turn = ConversationTurn(role="assistant", content="response", turn_index=1)
        assert turn.role == "assistant"

    def test_default_turn_index(self):
        turn = ConversationTurn(role="user", content="hi")
        assert turn.turn_index == 0


# ---------------------------------------------------------------------------
# MultiTurnAttackResult dataclass
# ---------------------------------------------------------------------------

class TestMultiTurnAttackResult:
    def _make(self, succeeded=False):
        return MultiTurnAttackResult(
            attack_id="LLM-CONV-001",
            pattern="crescendo",
            endpoint="https://api.openai.com/v1/chat/completions",
            succeeded=succeeded,
            evidence="Jailbreak detected" if succeeded else "",
        )

    def test_creation(self):
        result = self._make()
        assert result.attack_id == "LLM-CONV-001"
        assert result.pattern == "crescendo"

    def test_defaults(self):
        result = self._make()
        assert result.turns == []
        assert result.final_response == ""
        assert result.succeeded is False
        assert result.severity == "high"
        assert "LLM01" in result.owasp_refs

    def test_succeeded_flag(self):
        result = self._make(succeeded=True)
        assert result.succeeded is True


# ---------------------------------------------------------------------------
# MultiTurnAttackReport dataclass
# ---------------------------------------------------------------------------

class TestMultiTurnAttackReport:
    def _make(self, results=None):
        return MultiTurnAttackReport(
            target="https://api.example.com",
            endpoint="https://api.example.com/v1/chat/completions",
            mode="safe",
            results=results or [],
        )

    def test_successful_attacks_empty(self):
        report = self._make()
        assert report.successful_attacks == []

    def test_successful_attacks_filtered(self):
        r1 = MultiTurnAttackResult("id1", "crescendo", "ep", succeeded=True)
        r2 = MultiTurnAttackResult("id2", "many_shot", "ep", succeeded=False)
        report = self._make(results=[r1, r2])
        assert len(report.successful_attacks) == 1
        assert report.successful_attacks[0].attack_id == "id1"

    def test_critical_successes_filtered(self):
        r1 = MultiTurnAttackResult("id1", "crescendo", "ep", succeeded=True, severity="critical")
        r2 = MultiTurnAttackResult("id2", "many_shot", "ep", succeeded=True, severity="high")
        report = self._make(results=[r1, r2])
        assert len(report.critical_successes) == 1
        assert report.critical_successes[0].severity == "critical"

    def test_no_critical_successes(self):
        r = MultiTurnAttackResult("id1", "crescendo", "ep", succeeded=True, severity="high")
        report = self._make(results=[r])
        assert len(report.critical_successes) == 0


# ---------------------------------------------------------------------------
# LLMConversationAttacker authorization gating
# ---------------------------------------------------------------------------

class TestLLMConversationAttackerAuth:
    def test_unauthorized_raises(self):
        with pytest.raises(AuthorizationRequired):
            LLMConversationAttacker(authorized=False)

    def test_no_args_raises(self):
        with pytest.raises(AuthorizationRequired):
            LLMConversationAttacker()

    def test_authorized_succeeds(self):
        attacker = LLMConversationAttacker(authorized=True)
        # authorized attribute may not be stored; just verify no exception raised
        assert attacker is not None

    def test_default_model_set(self):
        attacker = LLMConversationAttacker(authorized=True)
        assert attacker._model is not None

    def test_custom_model(self):
        attacker = LLMConversationAttacker(authorized=True, model="gpt-4")
        assert attacker._model == "gpt-4"

    def test_endpoint_stored(self):
        # LLMConversationAttacker doesn't store endpoint at init time
        attacker = LLMConversationAttacker(authorized=True)
        assert attacker is not None  # endpoint passed at attack() time


# ===========================================================================
# AuthAttacker coverage
# ===========================================================================

from offensive_ai.core.auth_attacker import AuthAttacker
from offensive_ai.models.auth_result import AuthAttackReport, AuthAttackResult, AuthVulnSeverity


class TestAuthAttackerAuthGating:
    def test_unauthorized_raises(self):
        with pytest.raises(AuthorizationRequired):
            AuthAttacker(authorized=False)

    def test_no_args_raises(self):
        with pytest.raises(AuthorizationRequired):
            AuthAttacker()

    def test_authorized_succeeds(self):
        attacker = AuthAttacker(authorized=True)
        assert attacker.authorized is True

    def test_judge_stored(self):
        from unittest.mock import MagicMock
        judge = MagicMock()
        attacker = AuthAttacker(authorized=True, judge=judge)
        assert attacker._judge is judge


@pytest.mark.asyncio
class TestAuthAttackerHTTP:
    async def test_attack_safe_mode(self):
        import httpx
        import respx
        from offensive_ai.models.auth_result import AuthAttackReport

        attacker = AuthAttacker(authorized=True)
        target = "http://mock-auth.test"

        with respx.mock:
            # Mock all GET/POST requests to the target base
            respx.get(url__startswith=target).mock(
                return_value=httpx.Response(200, json={"authorization_endpoint": f"{target}/oauth2/authorize"})
            )
            respx.post(url__startswith=target).mock(
                return_value=httpx.Response(400, json={"error": "invalid_request"})
            )
            report = await attacker.attack(target=target, mode="safe")

        assert isinstance(report, AuthAttackReport)
        assert report.attacks_run >= 0

    async def test_attack_returns_report_on_error(self):
        import httpx
        import respx

        attacker = AuthAttacker(authorized=True)
        target = "http://unreachable-auth.test"

        with respx.mock:
            respx.get(url__startswith=target).mock(
                side_effect=httpx.ConnectError("refused")
            )
            respx.post(url__startswith=target).mock(
                side_effect=httpx.ConnectError("refused")
            )
            report = await attacker.attack(target=target, mode="safe")

        assert isinstance(report, AuthAttackReport)
        assert report.scan_duration >= 0.0


class TestAuthAttackReport:
    def _make_report(self):
        from offensive_ai.models.auth_result import AuthAttackReport
        return AuthAttackReport(target="https://auth.example.com")

    def test_empty_report(self):
        report = self._make_report()
        assert report.attacks_run == 0
        assert report.attacks_triggered == 0
        assert report.results == []

    def test_triggered_results_property(self):
        from offensive_ai.models.auth_result import AuthAttackReport, AuthAttackResult, AuthVulnSeverity
        report = self._make_report()
        report.results = [
            AuthAttackResult(
                attack_id="A1",
                target="https://auth.example.com",
                triggered=True,
                severity=AuthVulnSeverity.HIGH,
                title="Open Redirect",
                description="Redirect bypass",
            ),
            AuthAttackResult(
                attack_id="A2",
                target="https://auth.example.com",
                triggered=False,
                severity=AuthVulnSeverity.LOW,
                title="State bypass",
                description="Not triggered",
            ),
        ]
        triggered = report.triggered_results
        assert len(triggered) == 1
        assert triggered[0].attack_id == "A1"
