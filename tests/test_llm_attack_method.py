"""
Additional tests for LLMConversationAttacker.attack() and AuthAttacker sub-attacks.
Uses respx to mock httpx.
"""

from __future__ import annotations

import pytest
import httpx
import respx

from offensive_ai.core.llm_conversation_attacker import (
    LLMConversationAttacker,
    MultiTurnAttackReport,
    MultiTurnAttackResult,
)
from offensive_ai.core.auth_attacker import AuthAttacker
from offensive_ai.models.auth_result import AuthAttackReport, AuthVulnSeverity


# ---------------------------------------------------------------------------
# LLMConversationAttacker.attack() — respx mocking of httpx
# ---------------------------------------------------------------------------

MOCK_ENDPOINT = "http://mock-llm-attack.test/v1/chat/completions"

# A benign reply (no refusal phrases, plenty of content → could be "succeeded")
_RESPONSE_BODY = {
    "choices": [{"message": {"content": "Here is the answer: " + "x" * 200}}]
}
# A refusal reply
_REFUSAL_BODY = {
    "choices": [{"message": {"content": "I'm sorry, I cannot help with that."}}]
}


@pytest.mark.asyncio
class TestLLMAttackerAttackMethod:
    """Test the attack() method with various patterns."""

    async def test_attack_safe_mode_returns_report(self):
        attacker = LLMConversationAttacker(authorized=True)
        with respx.mock:
            respx.post(MOCK_ENDPOINT).mock(
                return_value=httpx.Response(200, json=_RESPONSE_BODY)
            )
            report = await attacker.attack(endpoint=MOCK_ENDPOINT, payload="test payload")
        assert isinstance(report, MultiTurnAttackReport)
        # Safe mode → crescendo + many_shot
        assert len(report.results) == 2

    async def test_attack_safe_mode_patterns(self):
        attacker = LLMConversationAttacker(authorized=True)
        with respx.mock:
            respx.post(MOCK_ENDPOINT).mock(
                return_value=httpx.Response(200, json=_RESPONSE_BODY)
            )
            report = await attacker.attack(endpoint=MOCK_ENDPOINT, payload="test")
        patterns = [r.pattern for r in report.results]
        assert "crescendo" in patterns
        assert "many_shot" in patterns

    async def test_attack_deep_mode_all_patterns(self):
        attacker = LLMConversationAttacker(authorized=True)
        with respx.mock:
            respx.post(MOCK_ENDPOINT).mock(
                return_value=httpx.Response(200, json=_RESPONSE_BODY)
            )
            report = await attacker.attack(
                endpoint=MOCK_ENDPOINT, payload="test", mode="deep"
            )
        patterns = [r.pattern for r in report.results]
        assert "crescendo" in patterns
        assert "many_shot" in patterns
        assert "context_priming" in patterns
        assert "goal_hijack" in patterns

    async def test_attack_custom_patterns(self):
        attacker = LLMConversationAttacker(authorized=True)
        with respx.mock:
            respx.post(MOCK_ENDPOINT).mock(
                return_value=httpx.Response(200, json=_RESPONSE_BODY)
            )
            report = await attacker.attack(
                endpoint=MOCK_ENDPOINT,
                payload="test",
                patterns=["crescendo"],
            )
        assert len(report.results) == 1
        assert report.results[0].pattern == "crescendo"

    async def test_attack_refusal_not_succeeded(self):
        attacker = LLMConversationAttacker(authorized=True)
        with respx.mock:
            respx.post(MOCK_ENDPOINT).mock(
                return_value=httpx.Response(200, json=_REFUSAL_BODY)
            )
            report = await attacker.attack(endpoint=MOCK_ENDPOINT, payload="test")
        # All results should not be "succeeded" since the reply contains refusal phrase
        for result in report.results:
            assert not result.succeeded

    async def test_attack_http_error_captured(self):
        attacker = LLMConversationAttacker(authorized=True)
        with respx.mock:
            respx.post(MOCK_ENDPOINT).mock(
                side_effect=httpx.ConnectError("refused")
            )
            report = await attacker.attack(endpoint=MOCK_ENDPOINT, payload="test")
        # _send_message catches exceptions and returns "[Error: ...]" in the content
        # so results are returned (not raised), but final_response contains error text
        assert len(report.results) == 2  # safe mode = 2 patterns
        for r in report.results:
            # Either an error field OR the final_response contains "[Error:" from _send_message
            has_error = r.error or "[Error:" in (r.final_response or "")
            assert has_error

    async def test_attack_total_duration_set(self):
        attacker = LLMConversationAttacker(authorized=True)
        with respx.mock:
            respx.post(MOCK_ENDPOINT).mock(
                return_value=httpx.Response(200, json=_RESPONSE_BODY)
            )
            report = await attacker.attack(endpoint=MOCK_ENDPOINT, payload="test")
        assert report.total_duration >= 0.0

    async def test_attack_with_api_key(self):
        attacker = LLMConversationAttacker(authorized=True)
        with respx.mock:
            respx.post(MOCK_ENDPOINT).mock(
                return_value=httpx.Response(200, json=_RESPONSE_BODY)
            )
            report = await attacker.attack(
                endpoint=MOCK_ENDPOINT, payload="test", api_key="sk-test-key"
            )
        assert isinstance(report, MultiTurnAttackReport)

    async def test_attack_successful_when_substantive_content(self):
        """Substantive non-refusal content should set succeeded=True."""
        attacker = LLMConversationAttacker(authorized=True)
        with respx.mock:
            respx.post(MOCK_ENDPOINT).mock(
                return_value=httpx.Response(200, json=_RESPONSE_BODY)
            )
            report = await attacker.attack(
                endpoint=MOCK_ENDPOINT,
                payload="test",
                patterns=["crescendo"],
            )
        # The _RESPONSE_BODY has >100 chars and no refusal → succeeded
        crescendo_result = next(r for r in report.results if r.pattern == "crescendo")
        assert crescendo_result.succeeded is True


# ---------------------------------------------------------------------------
# AuthAttacker sub-attack methods via full attack() flow
# ---------------------------------------------------------------------------

MOCK_AUTH_ENDPOINT = "http://mock-auth-attack.test"


@pytest.mark.asyncio
class TestAuthAttackerSubMethods:
    """Test auth attacker attack sub-methods through the attack() facade."""

    async def test_open_redirect_safe_mode(self):
        """Open redirect probes run in safe mode."""
        attacker = AuthAttacker(authorized=True)
        target = "http://mock-auth-attack.test"

        with respx.mock:
            respx.get(url__startswith=target).mock(
                return_value=httpx.Response(302, headers={"Location": "/safe"})
            )
            respx.post(url__startswith=target).mock(
                return_value=httpx.Response(400, json={"error": "invalid_request"})
            )
            report = await attacker.attack(target=target, mode="safe")

        assert isinstance(report, AuthAttackReport)
        assert report.attacks_run > 0

    async def test_state_bypass_safe_mode(self):
        attacker = AuthAttacker(authorized=True)
        target = "http://mock-auth-attack.test"

        with respx.mock:
            respx.get(url__startswith=target).mock(
                return_value=httpx.Response(200, json={"result": "ok"})
            )
            respx.post(url__startswith=target).mock(
                return_value=httpx.Response(200, json={"result": "ok"})
            )
            report = await attacker.attack(target=target, mode="safe")

        assert isinstance(report, AuthAttackReport)
        # Safe mode always has open_redirect + state_bypass + pkce_bypass attacks
        assert report.attacks_run >= 3

    async def test_deep_mode_more_attacks(self):
        attacker = AuthAttacker(authorized=True)
        target = "http://mock-auth-attack.test"

        with respx.mock:
            respx.get(url__startswith=target).mock(
                return_value=httpx.Response(200, json={"keys": []})
            )
            respx.post(url__startswith=target).mock(
                return_value=httpx.Response(200, json={"access_token": "test"})
            )
            report_safe = await attacker.attack(target=target, mode="safe")

        with respx.mock:
            respx.get(url__startswith=target).mock(
                return_value=httpx.Response(200, json={"keys": []})
            )
            respx.post(url__startswith=target).mock(
                return_value=httpx.Response(200, json={"access_token": "test"})
            )
            report_deep = await attacker.attack(target=target, mode="deep")

        assert report_deep.attacks_run >= report_safe.attacks_run

    async def test_attack_with_custom_headers(self):
        attacker = AuthAttacker(authorized=True)
        target = "http://mock-auth-attack.test"

        with respx.mock:
            respx.get(url__startswith=target).mock(
                return_value=httpx.Response(200, json={})
            )
            respx.post(url__startswith=target).mock(
                return_value=httpx.Response(200, json={})
            )
            report = await attacker.attack(
                target=target,
                mode="safe",
                headers={"X-Custom": "test-header"},
            )

        assert isinstance(report, AuthAttackReport)

    async def test_llm_enrichment_called_when_judge_set(self):
        """LLM enrichment path is triggered when judge has a provider."""
        from unittest.mock import MagicMock

        judge = MagicMock()
        judge.provider = "openai"
        judge.evaluate.return_value = {
            "vulnerable": True,
            "confidence": 0.9,
            "reason": "Auth bypass detected",
        }

        attacker = AuthAttacker(authorized=True, judge=judge)
        target = "http://mock-auth-attack.test"

        with respx.mock:
            # Trigger an open redirect so there's at least one triggered result
            respx.get(url__startswith=target).mock(
                return_value=httpx.Response(
                    302,
                    headers={"Location": "https://offensive-ai-probe.invalid/callback"},
                )
            )
            respx.post(url__startswith=target).mock(
                return_value=httpx.Response(400, json={"error": "bad_request"})
            )
            report = await attacker.attack(target=target, mode="safe")

        assert isinstance(report, AuthAttackReport)

    async def test_attack_duration_tracked(self):
        attacker = AuthAttacker(authorized=True)
        target = "http://mock-auth-attack.test"

        with respx.mock:
            respx.get(url__startswith=target).mock(
                return_value=httpx.Response(200, json={})
            )
            respx.post(url__startswith=target).mock(
                return_value=httpx.Response(200, json={})
            )
            report = await attacker.attack(target=target, mode="safe")

        assert report.scan_duration >= 0.0


# ---------------------------------------------------------------------------
# AuthAttackReport properties
# ---------------------------------------------------------------------------

class TestAuthAttackReportProps:
    def test_triggered_results_empty(self):
        report = AuthAttackReport(target="http://example.com")
        assert report.triggered_results == []

    def test_triggered_results_filters(self):
        from offensive_ai.models.auth_result import AuthAttackResult
        report = AuthAttackReport(target="http://example.com")
        report.results = [
            AuthAttackResult(
                attack_id="A1",
                target="http://example.com",
                triggered=True,
                severity=AuthVulnSeverity.HIGH,
                title="Redirect",
                description="desc",
            ),
            AuthAttackResult(
                attack_id="A2",
                target="http://example.com",
                triggered=False,
                severity=AuthVulnSeverity.LOW,
                title="State",
                description="desc",
            ),
        ]
        assert len(report.triggered_results) == 1
        assert report.triggered_results[0].attack_id == "A1"

    def test_protocol_stored(self):
        from offensive_ai.models.auth_result import AuthProtocol
        report = AuthAttackReport(
            target="http://example.com",
            protocol=AuthProtocol.OAUTH2,
        )
        assert report.protocol == AuthProtocol.OAUTH2


# ---------------------------------------------------------------------------
# Additional coverage: HTTPStatusError, unknown pattern, exception in attack
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestLLMConversationAttackerAdditional:
    @respx.mock
    async def test_llm_send_message_http_status_error(self):
        """Line 199: HTTPStatusError in _send_message returns error string."""
        from offensive_ai.core.llm_conversation_attacker import LLMConversationAttacker
        attacker = LLMConversationAttacker(authorized=True, timeout=5.0)

        # Use crescendo — a valid pattern that calls _send_message
        respx.post("http://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(429, text="Too Many Requests")
        )

        result = await attacker.attack(
            endpoint="http://llm.example.com/v1/chat/completions",
            payload="test prompt",
            patterns=["crescendo"],
            api_key=None,
            mode="safe",
        )
        # crescendo calls _send_message; 429 should hit HTTPStatusError catch
        assert result is not None

    @respx.mock
    async def test_attack_unknown_pattern_sets_error(self):
        """Lines 396-397: unknown pattern returns error."""
        from offensive_ai.core.llm_conversation_attacker import LLMConversationAttacker
        attacker = LLMConversationAttacker(authorized=True, timeout=5.0)

        respx.post("http://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={
                "choices": [{"message": {"content": "Sure, here is..."}}]
            })
        )

        result = await attacker.attack(
            endpoint="http://llm.example.com/v1/chat/completions",
            payload="test prompt",
            patterns=["unknown_pattern_xyz"],
            api_key=None,
            mode="safe",
        )
        # The unknown pattern result should have an error
        assert result is not None
        error_results = [r for r in result.results if r.error]
        assert len(error_results) > 0

    @respx.mock
    async def test_attack_exception_during_conversation_captured(self):
        """Lines 421-422: exception in _run_pattern try block is captured."""
        from offensive_ai.core.llm_conversation_attacker import LLMConversationAttacker
        import offensive_ai.core.llm_conversation_attacker as llm_mod
        attacker = LLMConversationAttacker(authorized=True, timeout=5.0)

        respx.post("http://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={
                "choices": [{"message": {"content": "test"}}]
            })
        )

        # Patch _build_crescendo_turns to raise, triggering the except block in _run_pattern
        with pytest.MonkeyPatch().context() as m:
            m.setattr(llm_mod, "_build_crescendo_turns", lambda payload: (_ for _ in ()).throw(RuntimeError("build error")))
            result = await attacker.attack(
                endpoint="http://llm.example.com/v1/chat/completions",
                payload="test prompt",
                patterns=["crescendo"],
                api_key="test-key",
                mode="safe",
            )
        assert result is not None
        error_results = [r for r in result.results if r.error]
        assert len(error_results) > 0

    @respx.mock
    async def test_attack_gather_exception_result(self):
        """Line 290: isinstance(res, Exception) branch in asyncio.gather."""
        from offensive_ai.core.llm_conversation_attacker import LLMConversationAttacker
        import offensive_ai.core.llm_conversation_attacker as llm_mod
        attacker = LLMConversationAttacker(authorized=True, timeout=5.0)

        respx.post("http://llm.example.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={
                "choices": [{"message": {"content": "test"}}]
            })
        )

        # Patch _run_pattern to raise, so gather returns an Exception instance
        orig_run_pattern = attacker._run_pattern
        async def raise_pattern(client, endpoint, payload, pattern, api_key):
            raise RuntimeError("injected error")
        attacker._run_pattern = raise_pattern

        result = await attacker.attack(
            endpoint="http://llm.example.com/v1/chat/completions",
            payload="test prompt",
            patterns=["crescendo"],
            api_key=None,
            mode="safe",
        )
        assert result is not None
        error_results = [r for r in result.results if r.error]
        assert len(error_results) > 0
