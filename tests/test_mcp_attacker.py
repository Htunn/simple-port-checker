"""Tests for MCP attacker — especially authorization gating."""

from __future__ import annotations

import pytest

from offensive_ai.core.mcp_attacker import AuthorizationRequired, MCPAttacker
from offensive_ai.models.mcp_result import MCPAttackReport, MCPTransport


class TestMCPAttackerAuthGating:
    def test_instantiation_without_authorization_raises(self):
        """MCPAttacker must raise AuthorizationRequired when authorized=False."""
        with pytest.raises(AuthorizationRequired):
            MCPAttacker(authorized=False)

    def test_instantiation_without_keyword_raises(self):
        """Default instantiation (no args) must also raise."""
        with pytest.raises(AuthorizationRequired):
            MCPAttacker()

    def test_instantiation_with_authorization_succeeds(self):
        """authorized=True must succeed without error."""
        attacker = MCPAttacker(authorized=True)
        assert attacker.authorized is True


class TestMCPAttackReport:
    def test_triggered_results_filtered(self):
        from offensive_ai.models.mcp_result import MCPAttackResult, MCPVulnSeverity
        report = MCPAttackReport(target="http://test.local/mcp")
        report.results = [
            MCPAttackResult(
                attack_id="A1", target="http://test.local/mcp",
                triggered=True, severity=MCPVulnSeverity.CRITICAL, title="X", description="X"
            ),
            MCPAttackResult(
                attack_id="A2", target="http://test.local/mcp",
                triggered=False, severity=MCPVulnSeverity.INFO, title="Y", description="Y"
            ),
        ]
        triggered = report.triggered_results
        assert len(triggered) == 1
        assert triggered[0].attack_id == "A1"

    def test_authorization_note_present(self):
        report = MCPAttackReport(target="http://test.local/mcp")
        assert "authorization" in report.authorization_note.lower()


@pytest.mark.asyncio
class TestMCPAttackerAuthBypass:
    async def test_auth_bypass_probes_run(self):
        """With mocked HTTP, auth-bypass probes should run and return results."""
        import httpx
        import respx

        attacker = MCPAttacker(authorized=True)
        target = "http://mock-mcp.local/mcp"

        with respx.mock:
            # Return 200 for all requests → triggers auth bypass finding
            respx.post(target).mock(
                return_value=httpx.Response(
                    200,
                    json={"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {}}},
                )
            )
            report = await attacker.attack(
                target=target,
                transport="http",
                mode="safe",
            )

        assert isinstance(report, MCPAttackReport)
        assert report.attacks_run > 0
        # At least auth bypass probes ran
        assert len(report.results) > 0

    async def test_attack_logs_authorization_target(self, caplog):
        """Authorization banner must appear in logs when attacker is instantiated."""
        import httpx
        import respx

        with caplog.at_level("WARNING"):
            attacker = MCPAttacker(authorized=True)

        target = "http://mock-banner.local/mcp"

        with respx.mock:
            respx.post(target).mock(
                return_value=httpx.Response(
                    401,
                    json={"error": "unauthorized"},
                )
            )
            await attacker.attack(target=target, transport="http", mode="safe")

        assert any("AUTHORIZATION" in r.message.upper() for r in caplog.records)
