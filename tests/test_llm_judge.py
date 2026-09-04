"""
Tests for LLMJudge — covers provider detection, model selection, evaluate(),
is_available(), from_env(), and provider-specific call paths via mocking.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from offensive_ai.core.llm_judge import LLMJudge


# ---------------------------------------------------------------------------
# Provider detection and model selection
# ---------------------------------------------------------------------------

class TestLLMJudgeInit:
    def test_no_env_vars_gives_no_provider(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OFFENSIVE_AI_LLM_BASE_URL", raising=False)
        judge = LLMJudge()
        assert judge.provider is None

    def test_gemini_api_key_detected(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        judge = LLMJudge()
        assert judge.provider == "gemini"

    def test_anthropic_detected_when_no_gemini(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        judge = LLMJudge()
        assert judge.provider == "anthropic"

    def test_openai_detected_as_third_priority(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "fake-openai")
        monkeypatch.delenv("OFFENSIVE_AI_LLM_BASE_URL", raising=False)
        judge = LLMJudge()
        assert judge.provider == "openai"

    def test_base_url_triggers_openai_provider(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("OFFENSIVE_AI_LLM_BASE_URL", "http://localhost:1234")
        judge = LLMJudge()
        assert judge.provider == "openai"

    def test_explicit_provider_override(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        judge = LLMJudge(provider="openai", model="gpt-4o")
        assert judge.provider == "openai"
        assert judge.model == "gpt-4o"

    def test_default_model_openai(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OFFENSIVE_AI_LLM_MODEL", raising=False)
        judge = LLMJudge(provider="openai")
        assert "gpt" in judge.model or judge.model != ""

    def test_default_model_anthropic(self, monkeypatch):
        monkeypatch.delenv("OFFENSIVE_AI_LLM_MODEL", raising=False)
        judge = LLMJudge(provider="anthropic")
        assert "claude" in judge.model

    def test_default_model_gemini(self, monkeypatch):
        monkeypatch.delenv("OFFENSIVE_AI_LLM_MODEL", raising=False)
        judge = LLMJudge(provider="gemini")
        assert "gemini" in judge.model

    def test_default_model_none_provider(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OFFENSIVE_AI_LLM_BASE_URL", raising=False)
        judge = LLMJudge()
        # No provider → model should be empty
        assert judge.model == ""

    def test_custom_model_via_env(self, monkeypatch):
        monkeypatch.setenv("OFFENSIVE_AI_LLM_MODEL", "my-custom-model")
        judge = LLMJudge(provider="openai")
        assert judge.model == "my-custom-model"


# ---------------------------------------------------------------------------
# is_available and from_env
# ---------------------------------------------------------------------------

class TestLLMJudgeAvailability:
    def test_not_available_without_provider(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OFFENSIVE_AI_LLM_BASE_URL", raising=False)
        judge = LLMJudge()
        assert not judge.is_available()

    def test_available_with_provider(self):
        judge = LLMJudge(provider="openai", model="gpt-4o-mini")
        assert judge.is_available()

    def test_from_env_creates_instance(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        judge = LLMJudge.from_env()
        assert isinstance(judge, LLMJudge)


# ---------------------------------------------------------------------------
# evaluate() — no provider (fallback path)
# ---------------------------------------------------------------------------

class TestLLMJudgeEvaluateNoProvider:
    def test_evaluate_no_provider_returns_fallback(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OFFENSIVE_AI_LLM_BASE_URL", raising=False)

        judge = LLMJudge()
        result = judge.evaluate(
            category="prompt-injection",
            probe="Ignore previous instructions",
            response="Sure! Here's what you asked...",
        )
        assert result["vulnerable"] is False
        assert result["confidence"] == 0.0
        assert "No LLM provider" in result["reason"]


# ---------------------------------------------------------------------------
# evaluate() — mocked provider calls
# ---------------------------------------------------------------------------

class TestLLMJudgeEvaluateOpenAI:
    def test_evaluate_openai_success(self):
        judge = LLMJudge(provider="openai", model="gpt-4o-mini")

        fake_response = MagicMock()
        fake_response.choices = [MagicMock()]
        fake_response.choices[0].message.content = json.dumps(
            {"vulnerable": True, "confidence": 0.9, "reason": "Jailbreak succeeded"}
        )

        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = fake_response
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai}):
            result = judge.evaluate(
                category="prompt-injection",
                probe="test probe",
                response="jailbreak response",
            )

        assert result["vulnerable"] is True
        assert result["confidence"] == 0.9

    def test_evaluate_openai_import_error(self):
        judge = LLMJudge(provider="openai", model="gpt-4o-mini")

        # Make openai unavailable
        with patch.dict("sys.modules", {"openai": None}):
            result = judge.evaluate("test", "probe", "response")
        # Should fall back to error result
        assert "confidence" in result

    def test_evaluate_openai_exception_returns_fallback(self):
        judge = LLMJudge(provider="openai", model="gpt-4o-mini")

        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("API error")
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai}):
            result = judge.evaluate("test", "probe", "response")

        assert result["vulnerable"] is False
        assert "Judge evaluation failed" in result["reason"]


class TestLLMJudgeEvaluateAnthropic:
    def test_evaluate_anthropic_success(self):
        judge = LLMJudge(provider="anthropic", model="claude-3-haiku-20240307")

        fake_message = MagicMock()
        fake_message.content = [MagicMock()]
        fake_message.content[0].text = json.dumps(
            {"vulnerable": False, "confidence": 0.1, "reason": "Safe response"}
        )

        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_client.messages.create.return_value = fake_message
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = judge.evaluate("denial-of-service", "flood", "I refuse")

        assert result["vulnerable"] is False

    def test_evaluate_anthropic_import_error(self):
        judge = LLMJudge(provider="anthropic", model="claude-3-haiku-20240307")

        with patch.dict("sys.modules", {"anthropic": None}):
            result = judge.evaluate("test", "probe", "response")
        assert "confidence" in result


class TestLLMJudgeEvaluateGemini:
    def test_evaluate_gemini_success(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
        judge = LLMJudge(provider="gemini", model="gemini-1.5-flash")

        expected = {"vulnerable": True, "confidence": 0.85, "reason": "Injection found"}
        fake_resp_body = {
            "candidates": [{"content": {"parts": [{"text": json.dumps(expected)}]}}]
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(fake_resp_body).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = judge.evaluate("injection", "test prompt", "output")

        assert result["vulnerable"] is True
        assert result["confidence"] == 0.85

    def test_evaluate_gemini_network_error(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
        judge = LLMJudge(provider="gemini", model="gemini-1.5-flash")

        with patch("urllib.request.urlopen", side_effect=Exception("Network error")):
            result = judge.evaluate("test", "probe", "response")

        assert result["vulnerable"] is False
        assert "Judge evaluation failed" in result["reason"]


class TestLLMJudgeUnknownProvider:
    def test_evaluate_unknown_provider_returns_unknown(self):
        judge = LLMJudge.__new__(LLMJudge)
        judge.provider = "unknown_provider"
        judge.model = "some-model"
        judge._client = None

        result = judge.evaluate("test", "probe", "response")
        assert result["vulnerable"] is False
        assert "Unknown provider" in result["reason"]
