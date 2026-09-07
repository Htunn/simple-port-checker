"""
Tests for AgentSession — tool dispatch, the dual authorization gate for
attack tools, confirmation flow, and audit logging. Uses a scripted fake
AgentLLMClient so no real provider network calls are needed.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from offensive_ai.core.agent_llm import AgentTurn, ToolCall, ToolSpec
from offensive_ai.core.agent_session import AgentSession


class FakeLLM:
    """Replays a scripted sequence of AgentTurn responses, one per chat() call."""

    def __init__(self, turns: list[AgentTurn]) -> None:
        self._turns = list(turns)
        self.calls = 0

    async def chat(self, messages, tools) -> AgentTurn:
        self.calls += 1
        return self._turns.pop(0)


def _make_scan_tool(handler=None) -> ToolSpec:
    async def _default_handler(**kwargs):
        return {"ok": True, "kwargs": kwargs}

    return ToolSpec(
        name="scan_mcp",
        description="scan",
        parameters={"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        handler=handler or _default_handler,
        requires_authorization=False,
    )


def _make_attack_tool(handler=None) -> ToolSpec:
    async def _default_handler(**kwargs):
        return {"triggered": True, "kwargs": kwargs}

    return ToolSpec(
        name="attack_mcp",
        description="attack",
        parameters={"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        handler=handler or _default_handler,
        requires_authorization=True,
    )


class TestAgentSessionScannerTools:
    @pytest.mark.asyncio
    async def test_scan_tool_call_never_needs_confirmation(self):
        scan_tool = _make_scan_tool()
        confirm = AsyncMock(return_value=True)
        llm = FakeLLM(
            [
                AgentTurn(content=None, tool_calls=[ToolCall("c1", "scan_mcp", {"target": "http://x"})]),
                AgentTurn(content="scan complete", tool_calls=[]),
            ]
        )
        session = AgentSession(llm=llm, tools=[scan_tool], authorized=False, confirm_callback=confirm)

        reply = await session.step("scan http://x")

        assert reply == "scan complete"
        confirm.assert_not_awaited()


class TestAgentSessionAuthorizationGate:
    @pytest.mark.asyncio
    async def test_unauthorized_attack_tool_is_blocked_without_confirmation(self):
        attack_tool = _make_attack_tool()
        confirm = AsyncMock(return_value=True)
        llm = FakeLLM(
            [
                AgentTurn(content=None, tool_calls=[ToolCall("c1", "attack_mcp", {"target": "http://x"})]),
                AgentTurn(content="cannot proceed", tool_calls=[]),
            ]
        )
        session = AgentSession(llm=llm, tools=[attack_tool], authorized=False, confirm_callback=confirm)

        reply = await session.step("attack http://x")

        assert reply == "cannot proceed"
        confirm.assert_not_awaited()
        # the synthetic error must have been fed back to the LLM as a tool result
        tool_messages = [m for m in session.messages if m["role"] == "tool"]
        assert "requires explicit authorization" in tool_messages[-1]["content"]

    @pytest.mark.asyncio
    async def test_authorized_attack_tool_invokes_confirmation_before_executing(self):
        handler = AsyncMock(return_value={"triggered": True})
        attack_tool = _make_attack_tool(handler=handler)
        confirm = AsyncMock(return_value=True)
        llm = FakeLLM(
            [
                AgentTurn(content=None, tool_calls=[ToolCall("c1", "attack_mcp", {"target": "http://x"})]),
                AgentTurn(content="attack complete", tool_calls=[]),
            ]
        )
        session = AgentSession(llm=llm, tools=[attack_tool], authorized=True, confirm_callback=confirm)

        reply = await session.step("attack http://x")

        assert reply == "attack complete"
        confirm.assert_awaited_once_with("attack_mcp", {"target": "http://x"})
        handler.assert_awaited_once_with(target="http://x")

    @pytest.mark.asyncio
    async def test_declining_confirmation_skips_execution(self):
        handler = AsyncMock(return_value={"triggered": True})
        attack_tool = _make_attack_tool(handler=handler)
        confirm = AsyncMock(return_value=False)
        llm = FakeLLM(
            [
                AgentTurn(content=None, tool_calls=[ToolCall("c1", "attack_mcp", {"target": "http://x"})]),
                AgentTurn(content="ok, skipped", tool_calls=[]),
            ]
        )
        session = AgentSession(llm=llm, tools=[attack_tool], authorized=True, confirm_callback=confirm)

        reply = await session.step("attack http://x")

        assert reply == "ok, skipped"
        handler.assert_not_awaited()
        tool_messages = [m for m in session.messages if m["role"] == "tool"]
        assert "declined" in tool_messages[-1]["content"]

    @pytest.mark.asyncio
    async def test_audit_log_written_on_executed_attack(self):
        attack_tool = _make_attack_tool()
        confirm = AsyncMock(return_value=True)
        llm = FakeLLM(
            [
                AgentTurn(content=None, tool_calls=[ToolCall("c1", "attack_mcp", {"target": "http://x", "mode": "safe"})]),
                AgentTurn(content="done", tool_calls=[]),
            ]
        )
        session = AgentSession(llm=llm, tools=[attack_tool], authorized=True, confirm_callback=confirm)

        with patch("offensive_ai.core.agent_session.audit_log") as mock_audit:
            await session.step("attack http://x")

        mock_audit.assert_called_once()
        _, kwargs = mock_audit.call_args
        assert kwargs["target"] == "http://x"
        assert kwargs["module"] == "attack_mcp"


class TestAgentSessionHousekeeping:
    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error_without_crashing(self):
        llm = FakeLLM(
            [
                AgentTurn(content=None, tool_calls=[ToolCall("c1", "does_not_exist", {})]),
                AgentTurn(content="no such tool", tool_calls=[]),
            ]
        )
        session = AgentSession(llm=llm, tools=[], authorized=True)

        reply = await session.step("do something weird")

        assert reply == "no such tool"

    def test_clear_resets_history_but_keeps_system_prompt(self):
        llm = FakeLLM([])
        session = AgentSession(llm=llm, tools=[])
        session.messages.append({"role": "user", "content": "hi"})
        session.clear()
        assert len(session.messages) == 1
        assert session.messages[0]["role"] == "system"

    @pytest.mark.asyncio
    async def test_blank_completion_returns_fallback_message_not_empty_string(self):
        # Some providers (e.g. Gemini under safety filtering) can return a completion
        # with no text and no tool calls — this must never surface as silent empty output.
        llm = FakeLLM([AgentTurn(content=None, tool_calls=[])])
        session = AgentSession(llm=llm, tools=[])

        reply = await session.step("scan_mcp https://example.com")

        assert reply != ""
        assert "empty response" in reply
