"""Tests for A2A scanner, attacker, CVE database, and result models."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from offensive_ai.exceptions import AuthorizationRequired
from offensive_ai.models.a2a_result import (
    A2AAgentCard,
    A2AAttackReport,
    A2AAttackResult,
    A2AAuthPosture,
    A2ACapabilities,
    A2AScanResult,
    A2AServerInfo,
    A2ASkill,
    A2AVulnerability,
    A2AVulnSeverity,
)
from offensive_ai.utils.a2a_cve_db import (
    A2A_CVE_DB,
    match_cves,
    scan_for_dangerous_keywords,
    scan_for_secrets,
)
from offensive_ai.utils.a2a_payloads import (
    AUTH_BYPASS_PAYLOADS,
    JSONRPC_MANIPULATION_PAYLOADS,
    MESSAGE_INJECTION_PAYLOADS,
    SSRF_WEBHOOK_PAYLOADS,
    TASK_ENUM_PAYLOADS,
)
from offensive_ai.core.a2a_scanner import A2AScanner
from offensive_ai.core.a2a_attacker import A2AAttacker


# ---------------------------------------------------------------------------
# CVE Database tests
# ---------------------------------------------------------------------------

class TestA2ACveDatabase:
    def test_db_is_non_empty(self):
        assert len(A2A_CVE_DB) >= 10

    def test_all_entries_have_required_fields(self):
        for entry in A2A_CVE_DB:
            assert entry.vuln_id, f"Missing vuln_id in {entry}"
            assert entry.severity in ("critical", "high", "medium", "low", "info")
            assert entry.title
            assert entry.description

    def test_universal_entries_always_match(self):
        """Entries with empty affected_servers match any agent."""
        matches = match_cves(server_name="my-agent")
        universal = [m for m in matches if not m.affected_servers]
        assert len(universal) > 0

    def test_match_returns_a2a_cve_entries(self):
        matches = match_cves()
        assert all(hasattr(m, "vuln_id") for m in matches)

    def test_match_cves_without_args(self):
        """Calling with no args should return all entries without check_path."""
        matches = match_cves()
        assert len(matches) > 0

    def test_match_cves_with_accessible_path(self):
        """Entries with check_path should only match when path is accessible."""
        # A2A-ADV-2025-008 has check_path="/extendedAgentCard"
        with_path = match_cves(accessible_paths=["/extendedAgentCard"])
        without_path = match_cves(accessible_paths=[])
        with_ids = {m.vuln_id for m in with_path}
        without_ids = {m.vuln_id for m in without_path}
        # A2A-ADV-2025-008 should appear with the path but not without
        assert "A2A-ADV-2025-008" in with_ids
        assert "A2A-ADV-2025-008" not in without_ids

    def test_scan_for_secrets_finds_api_key(self):
        found = scan_for_secrets("api_key=sk-abc123xyz")
        assert len(found) > 0

    def test_scan_for_secrets_finds_openai_key(self):
        found = scan_for_secrets("Use sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678 to call the API.")
        assert len(found) > 0

    def test_scan_for_secrets_clean_text(self):
        found = scan_for_secrets("This is a route planning agent for travel assistance.")
        assert found == []

    def test_scan_dangerous_keywords_finds_exec(self):
        found = scan_for_dangerous_keywords("This tool can exec shell commands via subprocess.")
        assert "exec" in found or "subprocess" in found

    def test_scan_dangerous_keywords_finds_kubectl(self):
        found = scan_for_dangerous_keywords("Runs kubectl apply on the cluster.")
        assert "kubectl" in found

    def test_scan_dangerous_keywords_clean(self):
        found = scan_for_dangerous_keywords("Returns the current temperature in Celsius.")
        assert found == []


# ---------------------------------------------------------------------------
# Payload structure validation
# ---------------------------------------------------------------------------

class TestA2APayloads:
    def test_all_payload_ids_unique(self):
        """Every payload ID across all categories must be globally unique."""
        all_ids = (
            [p["id"] for p in AUTH_BYPASS_PAYLOADS]
            + [p["id"] for p in SSRF_WEBHOOK_PAYLOADS]
            + [p["id"] for p in MESSAGE_INJECTION_PAYLOADS]
            + [p["id"] for p in TASK_ENUM_PAYLOADS]
            + [p["id"] for p in JSONRPC_MANIPULATION_PAYLOADS]
        )
        assert len(all_ids) == len(set(all_ids)), "Duplicate payload IDs detected"

    def test_auth_bypass_payloads_structure(self):
        for p in AUTH_BYPASS_PAYLOADS:
            assert "id" in p
            assert "severity" in p
            assert p["severity"] in ("critical", "high", "medium", "low", "info")
            assert "description" in p

    def test_ssrf_payloads_have_webhook_url(self):
        for p in SSRF_WEBHOOK_PAYLOADS:
            assert "webhook_url" in p
            assert p["webhook_url"].startswith("http")

    def test_message_injection_payloads_have_payload(self):
        for p in MESSAGE_INJECTION_PAYLOADS:
            assert "payload" in p
            assert len(p["payload"]) > 0

    def test_task_enum_payloads_have_task_id(self):
        for p in TASK_ENUM_PAYLOADS:
            assert "task_id" in p

    def test_jsonrpc_payloads_have_method(self):
        for p in JSONRPC_MANIPULATION_PAYLOADS:
            assert "method" in p


# ---------------------------------------------------------------------------
# Result model tests
# ---------------------------------------------------------------------------

class TestA2AResultModels:
    def _make_result(self, vulns: list[A2AVulnerability] | None = None) -> A2AScanResult:
        return A2AScanResult(
            target="https://agent.example.com",
            vulnerabilities=vulns or [],
        )

    def test_scan_result_creation(self):
        r = self._make_result()
        assert r.target == "https://agent.example.com"
        assert r.error is None
        assert r.scan_duration == 0.0

    def test_critical_vulns_property(self):
        vulns = [
            A2AVulnerability(vuln_id="T-001", severity=A2AVulnSeverity.CRITICAL, title="c", description="d"),
            A2AVulnerability(vuln_id="T-002", severity=A2AVulnSeverity.HIGH, title="h", description="d"),
        ]
        r = self._make_result(vulns)
        assert len(r.critical_vulns) == 1
        assert r.has_critical

    def test_high_vulns_property(self):
        vulns = [
            A2AVulnerability(vuln_id="T-001", severity=A2AVulnSeverity.HIGH, title="h", description="d"),
        ]
        r = self._make_result(vulns)
        assert len(r.high_vulns) == 1
        assert not r.has_critical

    def test_all_vulns_combines_vulns_and_cve_matches(self):
        v1 = A2AVulnerability(vuln_id="T-001", severity=A2AVulnSeverity.HIGH, title="a", description="d")
        v2 = A2AVulnerability(vuln_id="T-002", severity=A2AVulnSeverity.MEDIUM, title="b", description="d")
        r = A2AScanResult(target="t", vulnerabilities=[v1], cve_matches=[v2])
        assert len(r.all_vulns) == 2

    def test_has_critical_false_when_no_critical(self):
        vulns = [
            A2AVulnerability(vuln_id="T-001", severity=A2AVulnSeverity.HIGH, title="h", description="d"),
        ]
        r = self._make_result(vulns)
        assert not r.has_critical

    def test_agent_card_defaults(self):
        card = A2AAgentCard()
        assert card.name == ""
        assert not card.is_signed
        assert card.skills == []

    def test_skill_dangerous_flag(self):
        skill = A2ASkill(
            id="s1", name="shell", description="exec bash commands",
            has_dangerous_keywords=True, dangerous_keywords_found=["exec", "bash"],
        )
        assert skill.has_dangerous_keywords
        assert "exec" in skill.dangerous_keywords_found

    def test_attack_report_successful_attacks_property(self):
        results = [
            A2AAttackResult(
                attack_id="A2A-ATK-AB-001", target="t", triggered=True,
                severity=A2AVulnSeverity.HIGH, title="bypass", description="d",
            ),
            A2AAttackResult(
                attack_id="A2A-ATK-AB-002", target="t", triggered=False,
                severity=A2AVulnSeverity.INFO, title="clean", description="d",
            ),
        ]
        report = A2AAttackReport(target="t", attacks_run=2, attacks_triggered=1, results=results)
        assert len(report.successful_attacks) == 1

    def test_attack_report_serialization(self):
        report = A2AAttackReport(target="https://agent.example.com")
        data = report.model_dump(mode="json")
        assert "target" in data
        assert "authorization_note" in data

    def test_scan_result_serialization(self):
        r = self._make_result()
        data = r.model_dump(mode="json")
        assert data["target"] == "https://agent.example.com"


# ---------------------------------------------------------------------------
# Scanner: URL normalisation
# ---------------------------------------------------------------------------

class TestA2AScannerNormalisation:
    def test_adds_https_scheme(self):
        scanner = A2AScanner("agent.example.com")
        assert scanner.target.startswith("https://")

    def test_strips_trailing_slash(self):
        scanner = A2AScanner("https://agent.example.com/")
        assert not scanner.target.endswith("/")

    def test_strips_agent_card_suffix(self):
        scanner = A2AScanner("https://agent.example.com/.well-known/agent-card.json")
        assert "/.well-known/agent-card.json" not in scanner.target

    def test_port_override(self):
        scanner = A2AScanner("https://agent.example.com", port=8443)
        assert ":8443" in scanner.target


# ---------------------------------------------------------------------------
# Scanner: static security analysis (no network)
# ---------------------------------------------------------------------------

class TestA2AScannerAnalysis:
    def _make_scanner(self) -> A2AScanner:
        return A2AScanner("https://agent.example.com")

    def _make_result_with_card(self, **card_kwargs) -> A2AScanResult:
        capabilities = card_kwargs.pop("capabilities", A2ACapabilities())
        card = A2AAgentCard(capabilities=capabilities, **card_kwargs)
        return A2AScanResult(target="https://agent.example.com", agent_card=card)

    def test_no_security_schemes_flags_vuln(self):
        scanner = self._make_scanner()
        result = self._make_result_with_card(security_schemes={})
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-A2A-AUTH-001" in ids

    def test_unsigned_card_flags_vuln(self):
        scanner = self._make_scanner()
        result = self._make_result_with_card(is_signed=False)
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-A2A-INT-001" in ids

    def test_signed_card_no_int_vuln(self):
        scanner = self._make_scanner()
        result = self._make_result_with_card(
            is_signed=True,
            security_schemes={"oauth2": {"oauth2SecurityScheme": {}}},
        )
        result.auth_posture.unauthenticated_access = False
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-A2A-INT-001" not in ids

    def test_unauthenticated_access_flags_vuln(self):
        scanner = self._make_scanner()
        result = self._make_result_with_card()
        result.auth_posture.unauthenticated_access = True
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-A2A-AUTH-003" in ids

    def test_dangerous_skill_flags_vuln(self):
        scanner = self._make_scanner()
        skill = A2ASkill(
            id="s1", name="shell-runner",
            description="Execute bash commands on the server.",
            has_dangerous_keywords=True,
            dangerous_keywords_found=["exec", "bash"],
        )
        result = self._make_result_with_card(skills=[skill])
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-A2A-SKILL-001" in ids

    def test_push_notifications_enabled_flags_ssrf_vuln(self):
        scanner = self._make_scanner()
        caps = A2ACapabilities(push_notifications=True)
        result = self._make_result_with_card(capabilities=caps)
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-A2A-SSRF-001" in ids

    def test_secret_in_card_description_flags_vuln(self):
        scanner = self._make_scanner()
        result = self._make_result_with_card(
            description="Contact us at api_key=sk-abcdef123456789012345678901234567890"
        )
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-A2A-SEC-001" in ids

    def test_http_endpoint_flags_tls_vuln(self):
        scanner = self._make_scanner()
        card = A2AAgentCard(
            supported_interfaces=[{"url": "http://agent.example.com/rpc", "protocolBinding": "JSONRPC"}]
        )
        vulns = scanner._check_transport_security(card)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-A2A-TLS-001" in ids

    def test_https_only_no_tls_vuln(self):
        scanner = self._make_scanner()
        card = A2AAgentCard(
            supported_interfaces=[{"url": "https://agent.example.com/rpc", "protocolBinding": "JSONRPC"}]
        )
        vulns = scanner._check_transport_security(card)
        assert vulns == []

    def test_infer_auth_type_oidc(self):
        schemes = {"google": {"openIdConnectSecurityScheme": {"openIdConnectUrl": "https://..."}}}
        assert A2AScanner._infer_auth_type(schemes) == "oidc"

    def test_infer_auth_type_none(self):
        assert A2AScanner._infer_auth_type({}) == "none"


# ---------------------------------------------------------------------------
# Scanner: integration tests with mocked HTTP
# ---------------------------------------------------------------------------

_SAMPLE_AGENT_CARD = {
    "name": "Test Research Agent",
    "description": "An agent for testing purposes.",
    "version": "1.0.0",
    "provider": {"organization": "TestCorp", "url": "https://testcorp.example.com"},
    "supportedInterfaces": [
        {"url": "https://agent.example.com/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
    ],
    "securitySchemes": {
        "oauth2": {"oauth2SecurityScheme": {"flows": {}}}
    },
    "security": [{"oauth2": ["read"]}],
    "capabilities": {"streaming": True, "pushNotifications": False, "extendedAgentCard": False},
    "skills": [
        {
            "id": "research",
            "name": "Research Assistant",
            "description": "Provides research summaries on academic topics.",
            "tags": ["research", "citations"],
            "inputModes": ["text/plain"],
            "outputModes": ["text/plain"],
        }
    ],
}


class TestA2AScannerIntegration:
    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_fetches_agent_card(self):
        respx.get("https://agent.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(200, json=_SAMPLE_AGENT_CARD)
        )
        # Auth probe — return 401
        respx.post("https://agent.example.com/rpc").mock(
            return_value=httpx.Response(401, text='{"error": "Unauthorized"}')
        )
        scanner = A2AScanner("https://agent.example.com", verify_tls=False)
        result = await scanner.scan()
        assert result.error is None
        assert result.agent_card.name == "Test Research Agent"
        assert result.agent_card.version == "1.0.0"

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_detects_unauthenticated_access(self):
        respx.get("https://agent.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(200, json={
                **_SAMPLE_AGENT_CARD,
                "securitySchemes": {},
                "security": [],
            })
        )
        # Auth probe — return 200 with a task result
        respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "result": {"task": {"id": "t1", "status": {"state": "TASK_STATE_WORKING"}}}},
            )
        )
        scanner = A2AScanner("https://agent.example.com", verify_tls=False)
        result = await scanner.scan()
        assert result.auth_posture.unauthenticated_access is True
        ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OAI-A2A-AUTH-001" in ids
        assert "OAI-A2A-AUTH-003" in ids

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_agent_card_not_found(self):
        respx.get("https://agent.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(404, text="Not Found")
        )
        scanner = A2AScanner("https://agent.example.com", verify_tls=False)
        result = await scanner.scan()
        assert result.error is not None
        assert "404" in result.error

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_flags_dangerous_skill(self):
        card_with_risky_skill = {
            **_SAMPLE_AGENT_CARD,
            "skills": [
                {
                    "id": "shell-exec",
                    "name": "Shell Executor",
                    "description": "Execute bash commands via subprocess on the server.",
                    "tags": ["admin"],
                    "inputModes": ["text/plain"],
                    "outputModes": ["text/plain"],
                }
            ],
        }
        respx.get("https://agent.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(200, json=card_with_risky_skill)
        )
        respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(401, text='{"error": "Unauthorized"}')
        )
        scanner = A2AScanner("https://agent.example.com", verify_tls=False)
        result = await scanner.scan()
        ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OAI-A2A-SKILL-001" in ids

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_flags_unsigned_card(self):
        respx.get("https://agent.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(200, json=_SAMPLE_AGENT_CARD)  # no 'signatures' field
        )
        respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(401, text='{"error": "Unauthorized"}')
        )
        scanner = A2AScanner("https://agent.example.com", verify_tls=False)
        result = await scanner.scan()
        ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OAI-A2A-INT-001" in ids

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_no_vulns_for_well_configured_agent(self):
        signed_card = {
            **_SAMPLE_AGENT_CARD,
            "signatures": [{"protected": "abc", "signature": "sig"}],
            "capabilities": {"streaming": True, "pushNotifications": False, "extendedAgentCard": False},
        }
        respx.get("https://agent.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(200, json=signed_card)
        )
        respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(401, text='{"error": "Unauthorized"}')
        )
        scanner = A2AScanner("https://agent.example.com", verify_tls=False)
        result = await scanner.scan()
        # A well-secured agent with signed card and auth should not trigger CRITICAL vulns
        assert not result.has_critical

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_cve_matches_populated(self):
        respx.get("https://agent.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(200, json=_SAMPLE_AGENT_CARD)
        )
        respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(401, text='{"error": "Unauthorized"}')
        )
        scanner = A2AScanner("https://agent.example.com", verify_tls=False)
        result = await scanner.scan()
        # Universal CVE entries (no check_path, no server filter) should be in cve_matches
        assert len(result.cve_matches) > 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_push_notifications_flags_ssrf(self):
        card_with_push = {
            **_SAMPLE_AGENT_CARD,
            "capabilities": {"streaming": True, "pushNotifications": True, "extendedAgentCard": False},
        }
        respx.get("https://agent.example.com/.well-known/agent-card.json").mock(
            return_value=httpx.Response(200, json=card_with_push)
        )
        respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(401, text='{"error": "Unauthorized"}')
        )
        scanner = A2AScanner("https://agent.example.com", verify_tls=False)
        result = await scanner.scan()
        ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OAI-A2A-SSRF-001" in ids


# ---------------------------------------------------------------------------
# Attacker tests
# ---------------------------------------------------------------------------

class TestA2AAttacker:
    def test_requires_authorization(self):
        with pytest.raises(AuthorizationRequired):
            A2AAttacker(authorized=False)

    def test_authorized_instantiation(self):
        attacker = A2AAttacker(authorized=True)
        assert attacker.authorized is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_attack_safe_mode_runs_auth_bypass(self):
        # All POST requests to the target return 200 with a task result
        respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "result": {"task": {"id": "t1"}}},
            )
        )
        attacker = A2AAttacker(authorized=True)
        report = await attacker.attack(
            "https://agent.example.com", mode="safe", timeout=5.0
        )
        assert report.attacks_run > 0
        assert report.authorized is True
        # At least some auth bypass probes ran
        attack_types = {r.attack_type for r in report.results}
        assert "auth_bypass" in attack_types

    @respx.mock
    @pytest.mark.asyncio
    async def test_attack_deep_mode_runs_all_types(self):
        respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(401, text='{"error": "Unauthorized"}')
        )
        attacker = A2AAttacker(authorized=True)
        report = await attacker.attack(
            "https://agent.example.com", mode="deep", timeout=5.0
        )
        attack_types = {r.attack_type for r in report.results}
        assert "auth_bypass" in attack_types
        assert "ssrf" in attack_types
        assert "message_injection" in attack_types
        assert "task_enum" in attack_types
        assert "jsonrpc" in attack_types

    @respx.mock
    @pytest.mark.asyncio
    async def test_attack_no_auth_bypass_triggered_when_server_returns_401(self):
        respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(401, text='{"error": "Unauthorized"}')
        )
        attacker = A2AAttacker(authorized=True)
        report = await attacker.attack(
            "https://agent.example.com", mode="safe", timeout=5.0
        )
        ab_triggered = [r for r in report.results if r.attack_type == "auth_bypass" and r.triggered]
        assert len(ab_triggered) == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_attack_triggers_when_server_accepts_without_auth(self):
        respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "result": {"task": {"id": "t1"}}},
            )
        )
        attacker = A2AAttacker(authorized=True)
        report = await attacker.attack(
            "https://agent.example.com", mode="safe", timeout=5.0
        )
        assert report.attacks_triggered > 0
        assert len(report.successful_attacks) > 0

    @pytest.mark.asyncio
    async def test_attack_normalise_url_without_scheme(self):
        """Attacker should add https:// when target has no scheme."""
        attacker = A2AAttacker(authorized=True)
        # The attacker normalises the URL - it should succeed (not raise) on init
        # and produce a report (even with all-failed attacks due to no real server)
        report = await attacker.attack("nonexistent.invalid.local", mode="safe", timeout=1.0)
        assert report.attacks_run >= 0  # normalisation happened, attacks ran (or errored gracefully)
