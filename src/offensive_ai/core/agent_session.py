"""
Core agent loop: conversation history, tool dispatch, and the dual
authorization gate for attack tools. Framework-free — no prompt_toolkit or
other I/O dependency here, so this is fully unit-testable with a fake
``AgentLLMClient``.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from ..log_config import audit_log, new_correlation_id
from .agent_llm import AgentLLMClient, ToolSpec

#: Called before executing an attack tool: (tool_name, arguments) -> approved?
ConfirmCallback = Callable[[str, dict[str, Any]], Awaitable[bool]]

SYSTEM_PROMPT = (
    "You are the offensive-ai security agent. You have access to tools that scan, and "
    "when explicitly authorized, actively attack security targets during authorized "
    "red-team engagements. Always prefer read-only scan tools first. Only call attack "
    "tools when the user explicitly asks for an active attack against a target they have "
    "confirmed authorization for. Summarize tool results concisely and highlight the most "
    "severe findings."
)

#: Safety cap on chained tool calls within a single user turn.
_MAX_TOOL_ROUNDS = 8


class AgentSession:
    """Drives one REPL conversation: history, tool dispatch, authorization gating."""

    def __init__(
        self,
        llm: AgentLLMClient,
        tools: list[ToolSpec],
        authorized: bool = False,
        confirm_callback: ConfirmCallback | None = None,
    ) -> None:
        self._llm = llm
        self._tools = tools
        self._tools_by_name = {t.name: t for t in tools}
        self.authorized = authorized
        #: Public so a REPL front-end can attach its own confirmation UI after construction.
        self.confirm_callback = confirm_callback
        self.messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]

    def clear(self) -> None:
        """Reset the conversation history, keeping the system prompt."""
        self.messages = self.messages[:1]

    async def step(self, user_input: str) -> str:
        """Send *user_input*, execute any requested tool calls, and return the final reply."""
        self.messages.append({"role": "user", "content": user_input})

        for _ in range(_MAX_TOOL_ROUNDS):
            turn = await self._llm.chat(self.messages, self._tools)
            if not turn.tool_calls:
                # A blank completion (e.g. safety-filtered by the provider) must not be
                # rendered as silent empty output — surface it so the user can retry/rephrase.
                reply = turn.content or "(model returned an empty response — try rephrasing your request)"
                self.messages.append({"role": "assistant", "content": reply})
                return reply

            self.messages.append(
                {
                    "role": "assistant",
                    "content": turn.content,
                    "tool_calls": [
                        {"id": tc.call_id, "name": tc.name, "arguments": tc.arguments}
                        for tc in turn.tool_calls
                    ],
                }
            )
            for tc in turn.tool_calls:
                result = await self._execute_tool(tc.name, tc.arguments)
                self.messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.call_id,
                        "name": tc.name,
                        "content": json.dumps(result, default=str),
                    }
                )

        return "Stopped after too many chained tool calls — please refine your request."

    async def _execute_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        tool = self._tools_by_name.get(name)
        if tool is None:
            return {"error": f"Unknown tool: {name}"}

        if tool.requires_authorization:
            if not self.authorized:
                return {
                    "error": (
                        f"Tool '{name}' requires explicit authorization. Restart the agent "
                        "with --i-have-authorization to enable attack tools."
                    )
                }
            if self.confirm_callback is not None and not await self.confirm_callback(name, arguments):
                return {"error": f"User declined to run tool '{name}'."}

        new_correlation_id()
        try:
            result = await tool.handler(**arguments)
        except Exception as exc:  # tool handlers already self-catch; this is a last resort
            result = {"error": str(exc)}

        if tool.requires_authorization:
            target = arguments.get("target") or arguments.get("endpoint") or arguments.get("collection_path") or ""
            audit_log("agent_attack_tool_invoked", target=str(target), mode=str(arguments.get("mode", "")), module=name)

        return result
