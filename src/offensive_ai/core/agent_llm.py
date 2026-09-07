"""
Lightweight, provider-native tool-calling client for the agentic REPL.

No agent framework (LangChain/AutoGPT/etc.) is used — this module talks
directly to each provider's native function/tool-calling API and normalises
the request/response shape to a small common vocabulary (``ToolSpec``,
``ToolCall``, ``AgentTurn``).

Reuses the same provider auto-detection and env vars as ``LLMJudge``
(see ``utils.llm_provider``): GEMINI_API_KEY > ANTHROPIC_API_KEY > OPENAI_API_KEY.

Install optional providers:
    pip install offensive-ai[ai]      # openai, anthropic
    pip install offensive-ai[gemini]  # google-generativeai
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, cast

from ..exceptions import ConfigError
from ..utils.llm_provider import default_model, detect_provider


@dataclass
class ToolSpec:
    """Describes one callable tool exposed to the agent."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema object: {"type": "object", "properties": {...}, "required": [...]}
    handler: Callable[..., Awaitable[dict[str, Any]]]
    requires_authorization: bool = False


@dataclass
class ToolCall:
    """A tool invocation requested by the model."""

    call_id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentTurn:
    """One model response: optional natural-language content plus requested tool calls."""

    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)


class AgentLLMClient:
    """Provider-native tool-calling chat client (OpenAI / Anthropic / Gemini)."""

    def __init__(self, provider: str | None = None, model: str | None = None) -> None:
        self.provider = provider or detect_provider()
        self.model = model or default_model(self.provider)

    def is_available(self) -> bool:
        """Returns True if a provider is configured."""
        return self.provider is not None

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
    ) -> AgentTurn:
        """Send *messages* (in the common wire format, see agent_session.py) and
        return the model's next turn, translating *tools* to the provider's native schema.
        """
        if not self.provider:
            raise ConfigError(
                "No LLM provider configured for the agent. Set GEMINI_API_KEY, "
                "ANTHROPIC_API_KEY, or OPENAI_API_KEY, and install the matching extra: "
                "pip install offensive-ai[ai] (OpenAI/Anthropic) or "
                "pip install offensive-ai[gemini] (Gemini)."
            )
        if self.provider == "openai":
            return await asyncio.to_thread(self._chat_openai, messages, tools)
        if self.provider == "anthropic":
            return await asyncio.to_thread(self._chat_anthropic, messages, tools)
        if self.provider == "gemini":
            return await asyncio.to_thread(self._chat_gemini, messages, tools)
        raise ConfigError(f"Unsupported provider: {self.provider}")

    # ------------------------------------------------------------------
    # OpenAI
    # ------------------------------------------------------------------

    def _chat_openai(self, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> AgentTurn:
        try:
            import openai  # type: ignore[import-not-found] # lazy import — [ai] extra
        except ImportError as exc:
            raise ImportError(
                "OpenAI provider requires 'openai' package. Install with: pip install offensive-ai[ai]"
            ) from exc

        base_url = os.getenv("OFFENSIVE_AI_LLM_BASE_URL")
        client = openai.OpenAI(
            api_key=os.getenv("OPENAI_API_KEY", "dummy"),
            base_url=base_url if base_url else None,
        )
        wire_messages: Any = [_openai_message(m) for m in messages]
        wire_tools: Any = [_tool_to_openai(t) for t in tools] or None
        tool_choice: Any = "auto" if tools else None
        completion = client.chat.completions.create(
            model=self.model,
            messages=wire_messages,
            tools=wire_tools,
            tool_choice=tool_choice,
        )
        choice = completion.choices[0].message
        # we only ever send function-type tools, so .function is always present
        tool_calls = [
            ToolCall(
                call_id=tc.id,
                name=cast(Any, tc).function.name,
                arguments=json.loads(cast(Any, tc).function.arguments or "{}"),
            )
            for tc in (choice.tool_calls or [])
        ]
        return AgentTurn(content=choice.content, tool_calls=tool_calls)

    # ------------------------------------------------------------------
    # Anthropic
    # ------------------------------------------------------------------

    def _chat_anthropic(self, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> AgentTurn:
        try:
            import anthropic  # type: ignore[import-not-found] # lazy import — [ai] extra
        except ImportError as exc:
            raise ImportError(
                "Anthropic provider requires 'anthropic' package. Install with: pip install offensive-ai[ai]"
            ) from exc

        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        system, anthropic_messages = _anthropic_messages(messages)
        wire_messages: Any = anthropic_messages
        wire_tools: Any = [_tool_to_anthropic(t) for t in tools]
        response = client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system,
            messages=wire_messages,
            tools=wire_tools,
        )
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(call_id=block.id, name=block.name, arguments=block.input or {}))
        return AgentTurn(content="\n".join(text_parts) or None, tool_calls=tool_calls)

    # ------------------------------------------------------------------
    # Gemini
    # ------------------------------------------------------------------

    def _chat_gemini(self, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> AgentTurn:
        try:
            # lazy import — [gemini] extra; may be fully absent (import-not-found) or
            # present without stubs depending on what else pulled in the google namespace.
            import google.generativeai as genai  # type: ignore[import-not-found, import-untyped]
        except ImportError as exc:
            raise ImportError(
                "Gemini provider requires 'google-generativeai' package. "
                "Install with: pip install offensive-ai[gemini]"
            ) from exc

        genai.configure(api_key=os.getenv("GEMINI_API_KEY", ""))
        system, contents = _gemini_contents(messages)
        model = genai.GenerativeModel(
            self.model,
            system_instruction=system or None,
            tools=[_tool_to_gemini(t) for t in tools] or None,
        )
        response = model.generate_content(contents)
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for part in response.candidates[0].content.parts:
            if getattr(part, "text", ""):
                text_parts.append(part.text)
            fc = getattr(part, "function_call", None)
            if fc and fc.name:
                tool_calls.append(
                    ToolCall(call_id=fc.name, name=fc.name, arguments=dict(fc.args or {}))
                )
        return AgentTurn(content="\n".join(text_parts) or None, tool_calls=tool_calls)


# ---------------------------------------------------------------------------
# Tool schema adapters
# ---------------------------------------------------------------------------


def _tool_to_openai(tool: ToolSpec) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters,
        },
    }


def _tool_to_anthropic(tool: ToolSpec) -> dict[str, Any]:
    return {
        "name": tool.name,
        "description": tool.description,
        "input_schema": tool.parameters,
    }


def _tool_to_gemini(tool: ToolSpec) -> dict[str, Any]:
    return {
        "function_declarations": [
            {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            }
        ]
    }


# ---------------------------------------------------------------------------
# Message wire-format adapters
#
# Common format (produced by AgentSession):
#   {"role": "system", "content": str}
#   {"role": "user", "content": str}
#   {"role": "assistant", "content": str | None, "tool_calls": [{"id", "name", "arguments"}]}
#   {"role": "tool", "tool_call_id": str, "name": str, "content": str}
# ---------------------------------------------------------------------------


def _openai_message(message: dict[str, Any]) -> dict[str, Any]:
    role = message["role"]
    if role == "assistant" and message.get("tool_calls"):
        return {
            "role": "assistant",
            "content": message.get("content"),
            "tool_calls": [
                {
                    "id": tc["id"],
                    "type": "function",
                    "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"])},
                }
                for tc in message["tool_calls"]
            ],
        }
    if role == "tool":
        return {"role": "tool", "tool_call_id": message["tool_call_id"], "content": message["content"]}
    return {"role": role, "content": message.get("content", "")}


def _anthropic_messages(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    system_parts: list[str] = []
    wire: list[dict[str, Any]] = []
    pending_tool_results: list[dict[str, Any]] = []

    def _flush_tool_results() -> None:
        if pending_tool_results:
            wire.append({"role": "user", "content": list(pending_tool_results)})
            pending_tool_results.clear()

    for message in messages:
        role = message["role"]
        if role == "system":
            system_parts.append(message.get("content", ""))
        elif role == "tool":
            pending_tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": message["tool_call_id"],
                    "content": message["content"],
                }
            )
        elif role == "assistant" and message.get("tool_calls"):
            _flush_tool_results()
            content: list[dict[str, Any]] = []
            if message.get("content"):
                content.append({"type": "text", "text": message["content"]})
            for tc in message["tool_calls"]:
                content.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["arguments"]})
            wire.append({"role": "assistant", "content": content})
        else:
            _flush_tool_results()
            wire.append({"role": role, "content": message.get("content", "")})
    _flush_tool_results()
    return "\n".join(p for p in system_parts if p), wire


def _gemini_contents(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    system_parts: list[str] = []
    contents: list[dict[str, Any]] = []
    for message in messages:
        role = message["role"]
        if role == "system":
            system_parts.append(message.get("content", ""))
        elif role == "tool":
            # The current Gemini API rejects role "function" for tool results — "user" is required.
            contents.append(
                {
                    "role": "user",
                    "parts": [
                        {
                            "function_response": {
                                "name": message.get("name", ""),
                                "response": {"result": message["content"]},
                            }
                        }
                    ],
                }
            )
        elif role == "assistant" and message.get("tool_calls"):
            contents.append(
                {
                    "role": "model",
                    "parts": [
                        {"function_call": {"name": tc["name"], "args": tc["arguments"]}}
                        for tc in message["tool_calls"]
                    ],
                }
            )
        else:
            contents.append(
                {"role": "model" if role == "assistant" else "user", "parts": [{"text": message.get("content", "")}]}
            )
    return "\n".join(p for p in system_parts if p), contents
