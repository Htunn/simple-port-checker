"""
Tests for the agent tool registry: schema validity, name uniqueness,
authorization flags, and the generic error-handling contract of handlers.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from offensive_ai.core.agent_tools import ALL_TOOLS, ATTACKER_TOOLS, SCANNER_TOOLS


class TestToolRegistryShape:
    def test_tool_names_are_unique(self):
        names = [t.name for t in ALL_TOOLS]
        assert len(names) == len(set(names))

    def test_all_tools_is_union_of_scanner_and_attacker_tools(self):
        assert ALL_TOOLS == SCANNER_TOOLS + ATTACKER_TOOLS

    def test_scanner_tools_never_require_authorization(self):
        for tool in SCANNER_TOOLS:
            assert tool.requires_authorization is False, tool.name

    def test_attacker_tools_always_require_authorization(self):
        for tool in ATTACKER_TOOLS:
            assert tool.requires_authorization is True, tool.name

    def test_parameters_are_valid_json_schema_objects(self):
        for tool in ALL_TOOLS:
            params = tool.parameters
            assert params.get("type") == "object", tool.name
            assert isinstance(params.get("properties"), dict), tool.name
            required = params.get("required", [])
            assert isinstance(required, list), tool.name
            for key in required:
                assert key in params["properties"], f"{tool.name}: required key {key!r} missing from properties"

    def test_handlers_are_coroutine_functions(self):
        import asyncio

        for tool in ALL_TOOLS:
            assert asyncio.iscoroutinefunction(tool.handler), tool.name

    def test_descriptions_are_non_empty(self):
        for tool in ALL_TOOLS:
            assert tool.description.strip(), tool.name


class TestToolHandlerErrorHandling:
    """Handlers must never raise — always return {"error": ...} on failure."""

    @pytest.mark.asyncio
    async def test_scan_mcp_handler_catches_exceptions(self):
        tool = next(t for t in SCANNER_TOOLS if t.name == "scan_mcp")
        with patch("offensive_ai.core.agent_tools.MCPScanner") as mock_cls:
            mock_cls.return_value.scan = AsyncMock(side_effect=RuntimeError("boom"))
            result = await tool.handler(target="http://example.com")
        assert result == {"error": "boom"}

    @pytest.mark.asyncio
    async def test_attack_mcp_handler_catches_exceptions(self):
        tool = next(t for t in ATTACKER_TOOLS if t.name == "attack_mcp")
        with patch("offensive_ai.core.agent_tools.MCPAttacker") as mock_cls:
            mock_cls.return_value.attack = AsyncMock(side_effect=RuntimeError("boom"))
            result = await tool.handler(target="http://example.com")
        assert result == {"error": "boom"}

    @pytest.mark.asyncio
    async def test_scan_a2a_handler_returns_dumped_result_on_success(self):
        tool = next(t for t in SCANNER_TOOLS if t.name == "scan_a2a")
        fake_result = type("FakeResult", (), {"model_dump": lambda self, mode="json": {"target": "x"}})()
        with patch("offensive_ai.core.agent_tools.A2AScanner") as mock_cls:
            mock_cls.return_value.scan = AsyncMock(return_value=fake_result)
            result = await tool.handler(target="https://agent.example.com")
        assert result == {"target": "x"}
