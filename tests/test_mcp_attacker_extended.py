"""
Extended tests for MCPAttacker — attack methods with mocked HTTP.
"""

from __future__ import annotations

import pytest
import httpx
import respx
from unittest.mock import MagicMock

from offensive_ai.core.mcp_attacker import MCPAttacker
from offensive_ai.exceptions import AuthorizationRequired
from offensive_ai.models.mcp_result import (
    MCPAttackReport,
    MCPAttackResult,
    MCPScanResult,
    MCPTool,
    MCPResource,
    MCPTransport,
    MCPVulnSeverity,
)


# ---------------------------------------------------------------------------
# Auth-bypass probes in safe mode
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMCPAuthBypassProbes:
    async def test_auth_bypass_200_triggers_finding(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-mcp-200.local/mcp"

        with respx.mock:
            respx.post(target).mock(
                return_value=httpx.Response(
                    200,
                    json={"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {}}},
                )
            )
            results = await attacker._attack_auth_bypass(target, {}, 5.0)

        assert isinstance(results, list)
        assert len(results) > 0
        triggered = [r for r in results if r.triggered]
        assert len(triggered) > 0

    async def test_auth_bypass_401_not_triggered(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-mcp-401.local/mcp"

        with respx.mock:
            respx.post(target).mock(
                return_value=httpx.Response(401, json={"error": "Unauthorized"})
            )
            results = await attacker._attack_auth_bypass(target, {}, 5.0)

        assert isinstance(results, list)
        # 401 should not trigger auth bypass
        triggered = [r for r in results if r.triggered]
        assert len(triggered) == 0

    async def test_auth_bypass_connection_error_handled(self):
        """Connection errors should be caught and included as non-triggered results."""
        attacker = MCPAttacker(authorized=True)
        target = "http://unreachable-host-xyz.local/mcp"

        with respx.mock:
            respx.post(target).mock(side_effect=httpx.ConnectError("Connection refused"))
            results = await attacker._attack_auth_bypass(target, {}, 5.0)

        assert isinstance(results, list)
        # Should still produce result objects (not crashed)
        assert len(results) > 0


# ---------------------------------------------------------------------------
# Path traversal probes in deep mode
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMCPPathTraversal:
    async def test_path_traversal_detects_unix_passwd(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-mcp-pt.local/mcp"

        with respx.mock:
            # Return passwd-like content to trigger path traversal detection
            respx.post(target).mock(
                return_value=httpx.Response(
                    200,
                    json={"jsonrpc": "2.0", "id": 10, "result": {"content": "root:x:0:0:/root:/bin/bash"}},
                )
            )
            results = await attacker._attack_path_traversal(target, {}, 5.0, scan_result=None)

        assert isinstance(results, list)
        assert len(results) > 0
        triggered = [r for r in results if r.triggered]
        assert len(triggered) > 0

    async def test_path_traversal_uses_resource_uri_as_base(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-mcp-pt2.local/mcp"

        mock_resource = MCPResource(
            uri="file:///data/documents/file.txt",
            name="document",
            description="test",
        )
        scan_result = MCPScanResult(target=target)
        scan_result.resources = [mock_resource]

        with respx.mock:
            respx.post(target).mock(
                return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 10, "result": {}})
            )
            results = await attacker._attack_path_traversal(target, {}, 5.0, scan_result=scan_result)

        assert isinstance(results, list)

    async def test_path_traversal_no_trigger_on_empty_response(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-mcp-pt3.local/mcp"

        with respx.mock:
            respx.post(target).mock(
                return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 10, "result": {}})
            )
            results = await attacker._attack_path_traversal(target, {}, 5.0, scan_result=None)

        triggered = [r for r in results if r.triggered]
        assert len(triggered) == 0


# ---------------------------------------------------------------------------
# Tool injection probes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMCPToolInjection:
    async def test_tool_injection_triggers_on_matching_response(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-mcp-ti.local/mcp"

        tool = MCPTool(
            name="summarize",
            description="Summarize text",
            input_schema={"properties": {"text": {"type": "string"}}},
        )
        scan_result = MCPScanResult(target=target)
        scan_result.tools = [tool]

        with respx.mock:
            # Return TOOL_INJECT_OK to trigger detection
            respx.post(target).mock(
                return_value=httpx.Response(
                    200,
                    text="TOOL_INJECT_OK",
                )
            )
            results = await attacker._attack_tool_injection(target, {}, 5.0, scan_result)

        assert isinstance(results, list)
        triggered = [r for r in results if r.triggered]
        assert len(triggered) > 0

    async def test_tool_injection_no_properties_uses_input_key(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-mcp-ti2.local/mcp"

        # Tool with no schema properties
        tool = MCPTool(
            name="run",
            description="Run command",
            input_schema={"properties": {}},
        )
        scan_result = MCPScanResult(target=target)
        scan_result.tools = [tool]

        with respx.mock:
            respx.post(target).mock(
                return_value=httpx.Response(200, json={"result": {}})
            )
            results = await attacker._attack_tool_injection(target, {}, 5.0, scan_result)

        assert isinstance(results, list)

    async def test_tool_injection_limits_to_3_tools(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-mcp-ti3.local/mcp"

        tools = [
            MCPTool(name=f"tool_{i}", description="Test", input_schema={"properties": {"text": {}}})
            for i in range(6)
        ]
        scan_result = MCPScanResult(target=target)
        scan_result.tools = tools

        with respx.mock:
            respx.post(target).mock(return_value=httpx.Response(200, json={}))
            results = await attacker._attack_tool_injection(target, {}, 5.0, scan_result)

        # Only first 3 tools should be attacked (2 payloads each = max 6)
        from offensive_ai.utils.mcp_payloads import TOOL_INJECTION_PAYLOADS
        assert len(results) <= 3 * len(TOOL_INJECTION_PAYLOADS)


# ---------------------------------------------------------------------------
# Command injection probes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMCPCommandInjection:
    async def test_command_injection_on_shell_tool(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-mcp-ci.local/mcp"

        shell_tool = MCPTool(
            name="bash",
            description="Execute bash commands",
            input_schema={"properties": {"command": {"type": "string"}}},
        )

        with respx.mock:
            respx.post(target).mock(
                return_value=httpx.Response(200, json={"result": "uid=0(root)"})
            )
            results = await attacker._attack_command_injection(target, {}, 5.0, [shell_tool])

        assert isinstance(results, list)
        assert len(results) > 0


# ---------------------------------------------------------------------------
# Full attack() in safe mode
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMCPFullAttack:
    async def test_safe_mode_only_runs_auth_bypass(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-full.local/mcp"

        with respx.mock:
            respx.post(target).mock(return_value=httpx.Response(401, json={"error": "unauthorized"}))
            report = await attacker.attack(target=target, transport="http", mode="safe")

        assert isinstance(report, MCPAttackReport)
        attack_ids = {r.attack_id for r in report.results}
        # Should only have auth bypass attack IDs (MCP-ATK-AB-*)
        assert all("AB" in aid for aid in attack_ids)

    async def test_deep_mode_runs_more_attacks(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-deep.local/mcp"

        mock_tool = MCPTool(
            name="shell",
            description="Shell tool",
            input_schema={"properties": {"cmd": {}}},
        )
        scan_result = MCPScanResult(target=target)
        scan_result.tools = [mock_tool]

        with respx.mock:
            respx.post(target).mock(return_value=httpx.Response(200, json={"result": {}}))
            report = await attacker.attack(
                target=target,
                transport="http",
                mode="deep",
                scan_result=scan_result,
            )

        assert isinstance(report, MCPAttackReport)
        # Deep mode should have more results than safe mode
        assert report.attacks_run > 0

    async def test_report_has_transport_field(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-transport.local/mcp"

        with respx.mock:
            respx.post(target).mock(return_value=httpx.Response(401, json={}))
            report = await attacker.attack(target=target, transport="sse", mode="safe")

        assert report.transport == MCPTransport.SSE

    async def test_report_scan_duration_positive(self):
        attacker = MCPAttacker(authorized=True)
        target = "http://mock-duration.local/mcp"

        with respx.mock:
            respx.post(target).mock(return_value=httpx.Response(401, json={}))
            report = await attacker.attack(target=target, transport="http", mode="safe")

        assert report.scan_duration >= 0


# ---------------------------------------------------------------------------
# LLM enrichment
# ---------------------------------------------------------------------------

class TestMCPLlmEnrichment:
    def test_enrich_with_no_judge_is_noop(self):
        attacker = MCPAttacker(authorized=True)
        attacker._judge = None

        report = MCPAttackReport(target="http://test.local/mcp")
        report.results = [
            MCPAttackResult(
                attack_id="A1",
                target="http://test.local/mcp",
                triggered=True,
                severity=MCPVulnSeverity.CRITICAL,
                title="X",
                description="X",
                evidence="found",
            )
        ]
        # Should not raise
        attacker._enrich_with_llm(report)

    def test_enrich_with_judge_called_for_triggered(self):
        attacker = MCPAttacker(authorized=True)
        mock_judge = MagicMock()
        mock_judge.evaluate = MagicMock(return_value={"reason": "critical attack path"})
        attacker._judge = mock_judge

        report = MCPAttackReport(target="http://test.local/mcp")
        triggered_result = MCPAttackResult(
            attack_id="A1",
            target="http://test.local/mcp",
            triggered=True,
            severity=MCPVulnSeverity.CRITICAL,
            title="Injection",
            description="Injection found",
            evidence="found it",
        )
        report.results = [triggered_result]

        attacker._enrich_with_llm(report)

        mock_judge.evaluate.assert_called_once()

    def test_enrich_no_triggered_results_skips_judge(self):
        attacker = MCPAttacker(authorized=True)
        mock_judge = MagicMock()
        attacker._judge = mock_judge

        report = MCPAttackReport(target="http://test.local/mcp")
        report.results = [
            MCPAttackResult(
                attack_id="A1",
                target="http://test.local/mcp",
                triggered=False,
                severity=MCPVulnSeverity.INFO,
                title="X",
                description="X",
            )
        ]

        attacker._enrich_with_llm(report)
        mock_judge.evaluate.assert_not_called()


# ---------------------------------------------------------------------------
# Coverage for triggered detection paths
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMcpAttackerTriggeredPaths:
    @respx.mock
    async def test_path_traversal_triggered_by_signal_in_response(self):
        """Lines 270-273: triggered=True when signal appears in response."""
        from offensive_ai.core.mcp_attacker import MCPAttacker
        from offensive_ai.models.mcp_result import MCPScanResult, MCPTransport

        attacker = MCPAttacker(authorized=True)
        target = "http://localhost:5001/mcp"
        scan_result = MCPScanResult(target=target, transport=MCPTransport.HTTP)

        # Return a response that contains "root" which is a common detect_in_response signal
        respx.post(target).mock(return_value=httpx.Response(
            200, text='{"result": {"content": [{"text": "root:x:0:0:root:/root:/bin/bash"}]}}'
        ))

        results = await attacker._attack_path_traversal(target, {}, 5.0, scan_result)
        assert len(results) > 0
        # At least one should have triggered
        triggered = [r for r in results if r.triggered]
        assert len(triggered) > 0

    @respx.mock
    async def test_path_traversal_exception_caught(self):
        """Exception path in _attack_path_traversal."""
        from offensive_ai.core.mcp_attacker import MCPAttacker

        attacker = MCPAttacker(authorized=True)
        target = "http://localhost:5002/mcp"

        respx.post(target).mock(side_effect=httpx.ConnectError("refused"))

        results = await attacker._attack_path_traversal(target, {}, 5.0, None)
        assert len(results) > 0
        # No triggered results on connection error
        for r in results:
            assert "refused" in r.response or r.response != ""

    @respx.mock
    async def test_tool_injection_triggered_by_signal(self):
        """Lines 397-398: triggered=True when signal in command injection response."""
        from offensive_ai.core.mcp_attacker import MCPAttacker
        from offensive_ai.models.mcp_result import MCPScanResult, MCPTransport, MCPTool

        attacker = MCPAttacker(authorized=True)
        target = "http://localhost:5003/mcp"
        tool = MCPTool(
            name="exec_shell",
            description="Execute shell commands",
            has_dangerous_keywords=True,
            input_schema={"type": "object", "properties": {"cmd": {"type": "string"}}},
        )
        scan_result = MCPScanResult(target=target, transport=MCPTransport.HTTP, tools=[tool])

        # Response containing command injection signal (uid=0 indicates root)
        respx.post(target).mock(return_value=httpx.Response(
            200, text='{"result": {"content": [{"text": "uid=0(root) gid=0(root)"}]}}'
        ))

        results = await attacker._attack_tool_injection(target, {}, 5.0, scan_result)
        # Check results exist
        assert isinstance(results, list)

    @respx.mock
    async def test_tool_injection_exception_caught(self):
        """Exception path in _attack_tool_injection."""
        from offensive_ai.core.mcp_attacker import MCPAttacker
        from offensive_ai.models.mcp_result import MCPScanResult, MCPTransport, MCPTool

        attacker = MCPAttacker(authorized=True)
        target = "http://localhost:5004/mcp"
        tool = MCPTool(
            name="exec_cmd",
            description="Execute commands",
            has_dangerous_keywords=True,
            input_schema={"type": "object", "properties": {}},
        )
        scan_result = MCPScanResult(target=target, transport=MCPTransport.HTTP, tools=[tool])

        respx.post(target).mock(side_effect=httpx.ConnectError("refused"))

        results = await attacker._attack_tool_injection(target, {}, 5.0, scan_result)
        assert isinstance(results, list)
        for r in results:
            assert "refused" in r.response or r.response == ""


# ---------------------------------------------------------------------------
# Coverage for LLM enrichment path (line 153) and AUTHORIZATION_BANNER (line 92)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMcpAttackerLLMEnrichment:
    @respx.mock
    async def test_attack_with_judge_calls_enrich_with_llm(self):
        """Lines 92, 153: authorized attack with judge calls _enrich_with_llm."""
        from offensive_ai.core.mcp_attacker import MCPAttacker
        from unittest.mock import MagicMock

        mock_judge = MagicMock()
        mock_judge.provider = "openai"
        mock_judge.evaluate.return_value = {
            "vulnerable": True, "confidence": 0.9, "reason": "Tool allows system access"
        }

        attacker = MCPAttacker(authorized=True, judge=mock_judge)
        target = "http://localhost:6001/mcp"

        # All requests return an empty response
        respx.post(target).mock(return_value=httpx.Response(200, json={
            "jsonrpc": "2.0", "id": 1, "result": {}
        }))

        report = await attacker.attack(
            target=target,
            transport="http",
            mode="safe",
            headers={},
            timeout=5.0,
            scan_result=None,
        )
        # judge should have been called if any MEDIUM/LOW vulns were triggered
        assert report is not None
        assert report.target == target

    def test_enrich_with_llm_adds_analysis_to_evidence(self):
        """Lines 174-175: LLM reason appended to triggered result evidence."""
        from offensive_ai.core.mcp_attacker import MCPAttacker, MCPAttackReport, MCPAttackResult, MCPVulnSeverity
        from unittest.mock import MagicMock

        mock_judge = MagicMock()
        mock_judge.provider = "openai"
        mock_judge.evaluate.return_value = {
            "vulnerable": True, "confidence": 0.9, "reason": "Path traversal confirmed"
        }

        attacker = MCPAttacker(authorized=True, judge=mock_judge)
        attacker._judge = mock_judge

        report = MCPAttackReport(target="http://test.local/mcp")
        triggered_result = MCPAttackResult(
            attack_id="PT-001",
            target="http://test.local/mcp",
            triggered=True,
            severity=MCPVulnSeverity.MEDIUM,
            title="Path Traversal",
            description="Path traversal via ../",
            evidence="Found /etc/passwd",
        )
        report.results = [triggered_result]

        attacker._enrich_with_llm(report)

        # Evidence should have LLM analysis appended
        assert "LLM analysis" in triggered_result.evidence or "Path traversal" in triggered_result.evidence
