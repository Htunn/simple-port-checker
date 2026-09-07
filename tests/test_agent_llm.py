"""
Tests for AgentLLMClient — tool-schema adapters and per-provider chat()
round-trips (mocked SDK clients, mirroring the LLMJudge test mocking pattern).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from offensive_ai.core.agent_llm import (
    AgentLLMClient,
    ToolSpec,
    _tool_to_anthropic,
    _tool_to_gemini,
    _tool_to_openai,
)
from offensive_ai.exceptions import ConfigError


async def _noop_handler(**kwargs):
    return {}


def _sample_tool() -> ToolSpec:
    return ToolSpec(
        name="scan_mcp",
        description="Scan an MCP endpoint.",
        parameters={"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        handler=_noop_handler,
    )


class TestToolSchemaAdapters:
    def test_tool_to_openai_shape(self):
        wire = _tool_to_openai(_sample_tool())
        assert wire["type"] == "function"
        assert wire["function"]["name"] == "scan_mcp"
        assert wire["function"]["parameters"]["required"] == ["target"]

    def test_tool_to_anthropic_shape(self):
        wire = _tool_to_anthropic(_sample_tool())
        assert wire["name"] == "scan_mcp"
        assert wire["input_schema"]["required"] == ["target"]

    def test_tool_to_gemini_shape(self):
        wire = _tool_to_gemini(_sample_tool())
        decl = wire["function_declarations"][0]
        assert decl["name"] == "scan_mcp"
        assert decl["parameters"]["required"] == ["target"]


class TestAgentLLMClientAvailability:
    def test_no_provider_configured(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OFFENSIVE_AI_LLM_BASE_URL", raising=False)
        client = AgentLLMClient()
        assert not client.is_available()

    @pytest.mark.asyncio
    async def test_chat_without_provider_raises_config_error(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OFFENSIVE_AI_LLM_BASE_URL", raising=False)
        client = AgentLLMClient()
        with pytest.raises(ConfigError):
            await client.chat([{"role": "user", "content": "hi"}], [])


class TestAgentLLMClientOpenAI:
    @pytest.mark.asyncio
    async def test_chat_openai_parses_tool_calls(self):
        client = AgentLLMClient(provider="openai", model="gpt-4o-mini")

        fake_tool_call = MagicMock()
        fake_tool_call.id = "call_1"
        fake_tool_call.function.name = "scan_mcp"
        fake_tool_call.function.arguments = json.dumps({"target": "http://x"})

        fake_message = MagicMock()
        fake_message.content = None
        fake_message.tool_calls = [fake_tool_call]

        fake_response = MagicMock()
        fake_response.choices = [MagicMock(message=fake_message)]

        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = fake_response
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai}):
            turn = await client.chat([{"role": "user", "content": "scan http://x"}], [_sample_tool()])

        assert turn.tool_calls[0].name == "scan_mcp"
        assert turn.tool_calls[0].arguments == {"target": "http://x"}

    @pytest.mark.asyncio
    async def test_chat_openai_parses_plain_text(self):
        client = AgentLLMClient(provider="openai", model="gpt-4o-mini")

        fake_message = MagicMock()
        fake_message.content = "Hello there"
        fake_message.tool_calls = None
        fake_response = MagicMock()
        fake_response.choices = [MagicMock(message=fake_message)]

        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = fake_response
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai}):
            turn = await client.chat([{"role": "user", "content": "hi"}], [])

        assert turn.content == "Hello there"
        assert turn.tool_calls == []


class TestAgentLLMClientAnthropic:
    @pytest.mark.asyncio
    async def test_chat_anthropic_parses_tool_use(self):
        client = AgentLLMClient(provider="anthropic", model="claude-3-haiku-20240307")

        tool_use_block = MagicMock(type="tool_use", id="toolu_1", input={"target": "http://x"})
        tool_use_block.name = "scan_mcp"
        fake_response = MagicMock()
        fake_response.content = [tool_use_block]

        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_client.messages.create.return_value = fake_response
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            turn = await client.chat([{"role": "user", "content": "scan http://x"}], [_sample_tool()])

        assert turn.tool_calls[0].name == "scan_mcp"
        assert turn.tool_calls[0].arguments == {"target": "http://x"}

    @pytest.mark.asyncio
    async def test_chat_anthropic_groups_tool_results_into_user_message(self):
        client = AgentLLMClient(provider="anthropic", model="claude-3-haiku-20240307")

        text_block = MagicMock(type="text", text="All good")
        fake_response = MagicMock()
        fake_response.content = [text_block]

        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_client.messages.create.return_value = fake_response
        mock_anthropic.Anthropic.return_value = mock_client

        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "scan it"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{"id": "toolu_1", "name": "scan_mcp", "arguments": {"target": "http://x"}}],
            },
            {"role": "tool", "tool_call_id": "toolu_1", "name": "scan_mcp", "content": "{}"},
        ]
        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            turn = await client.chat(messages, [_sample_tool()])

        assert turn.content == "All good"
        _, kwargs = mock_client.messages.create.call_args
        assert kwargs["system"] == "sys"
        # last wire message should be the grouped tool_result user turn
        assert kwargs["messages"][-1]["role"] == "user"
        assert kwargs["messages"][-1]["content"][0]["type"] == "tool_result"


class TestAgentLLMClientGemini:
    @pytest.mark.asyncio
    async def test_chat_gemini_parses_function_call(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
        client = AgentLLMClient(provider="gemini", model="gemini-1.5-flash")

        fc = MagicMock()
        fc.name = "scan_mcp"
        fc.args = {"target": "http://x"}
        part = MagicMock()
        part.text = ""
        part.function_call = fc
        candidate = MagicMock()
        candidate.content.parts = [part]
        fake_response = MagicMock()
        fake_response.candidates = [candidate]

        mock_model = MagicMock()
        mock_model.generate_content.return_value = fake_response
        mock_genai = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        mock_google = MagicMock()
        mock_google.generativeai = mock_genai

        with patch.dict("sys.modules", {"google": mock_google, "google.generativeai": mock_genai}):
            turn = await client.chat([{"role": "user", "content": "scan http://x"}], [_sample_tool()])

        assert turn.tool_calls[0].name == "scan_mcp"
        assert turn.tool_calls[0].arguments == {"target": "http://x"}

    def test_gemini_contents_uses_user_role_for_tool_results(self):
        from offensive_ai.core.agent_llm import _gemini_contents

        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "scan it"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{"id": "c1", "name": "scan_mcp", "arguments": {"target": "http://x"}}],
            },
            {"role": "tool", "tool_call_id": "c1", "name": "scan_mcp", "content": "{}"},
        ]
        _, contents = _gemini_contents(messages)
        # The Gemini API rejects role "function"; tool results must be wrapped as role "user".
        assert contents[-1]["role"] == "user"
        assert "function_response" in contents[-1]["parts"][0]
