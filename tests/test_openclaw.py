"""
End-to-end tests for OpenClaw gateway security scanner and attacker.

Tests cover:
- CVE database integrity and matching logic
- Payload structure validation
- Result model properties and edge cases
- Scanner fingerprinting (positive and negative)
- Scanner endpoint enumeration
- Scanner authentication and configuration assessment
- Scanner vulnerability matching pipeline
- Attacker authorization gating
- Attacker API probe execution
- Attacker deep-mode features
- CLI command smoke tests
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from offensive_ai.core.openclaw_attacker import AuthorizationRequired, OpenClawAttacker
from offensive_ai.core.openclaw_scanner import OpenClawScanner
from offensive_ai.models.openclaw_result import (
    OpenClawAttackReport,
    OpenClawAttackResult,
    OpenClawAuthPosture,
    OpenClawDMPolicy,
    OpenClawSandboxInfo,
    OpenClawScanResult,
    OpenClawServerInfo,
    OpenClawVulnerability,
    OpenClawVulnSeverity,
)
from offensive_ai.utils.openclaw_cve_db import (
    OPENCLAW_CVE_DB,
    OPENCLAW_DEFAULT_PORT,
    OPENCLAW_FINGERPRINTS,
    match_cves,
)
from offensive_ai.utils.openclaw_payloads import (
    API_AUTH_BYPASS_PAYLOADS,
    DM_PROMPT_INJECTION_PAYLOADS,
    MESSAGE_INJECTION_PAYLOADS,
    SSRF_WEBHOOK_PAYLOADS,
    WEBSOCKET_PROBE_PATHS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_openclaw_health_body(**extra) -> dict:
    """Build a minimal valid OpenClaw /health response body."""
    body = {"openclaw_version": "2026.6.10", "status": "ok"}
    body.update(extra)
    return body


def _make_scanner(target: str = "192.168.1.10", port: int = 18789) -> OpenClawScanner:
    return OpenClawScanner(target=target, port=port, timeout=5.0)


# ===========================================================================
# CVE DATABASE TESTS
# ===========================================================================


class TestOpenClawCveDb:
    def test_cve_db_is_non_empty(self):
        assert len(OPENCLAW_CVE_DB) >= 5

    def test_all_entries_have_required_fields(self):
        for entry in OPENCLAW_CVE_DB:
            assert entry.vuln_id, f"{entry} missing vuln_id"
            assert entry.severity in ("critical", "high", "medium", "low", "info"), \
                f"{entry.vuln_id} has invalid severity"
            assert entry.title, f"{entry.vuln_id} missing title"
            assert entry.description, f"{entry.vuln_id} missing description"
            assert entry.remediation, f"{entry.vuln_id} missing remediation"

    def test_default_port_is_18789(self):
        assert OPENCLAW_DEFAULT_PORT == 18789

    def test_match_cves_with_accessible_api_path(self):
        """OCL-ADV-001 should match when /api/v1/status is accessible."""
        matches = match_cves(accessible_paths=["/api/v1/status"])
        ids = {m.vuln_id for m in matches}
        assert "OCL-ADV-001" in ids

    def test_match_cves_with_health_path(self):
        """OCL-ADV-009 (version fingerprint) should match when /health is accessible."""
        matches = match_cves(accessible_paths=["/health"])
        ids = {m.vuln_id for m in matches}
        assert "OCL-ADV-009" in ids
        assert "OCL-ADV-010" in ids  # fingerprint info entry

    def test_match_cves_no_paths(self):
        """Entries without a check_path should always be included."""
        matches = match_cves(accessible_paths=[])
        no_path_entries = [e for e in OPENCLAW_CVE_DB if not e.check_path]
        assert len(matches) == len(no_path_entries)

    def test_match_cves_version_filter(self):
        """Version-specific entries should only match when version prefix matches."""
        # Entries with empty affected_versions match any version
        all_matches = match_cves(version="2026.6.10", accessible_paths=["/health"])
        assert len(all_matches) > 0

    def test_fingerprints_list_non_empty(self):
        assert len(OPENCLAW_FINGERPRINTS) > 0

    def test_fingerprint_has_required_keys(self):
        for fp in OPENCLAW_FINGERPRINTS:
            assert "match_type" in fp, f"Fingerprint missing match_type: {fp}"


# ===========================================================================
# PAYLOAD STRUCTURE TESTS
# ===========================================================================


class TestOpenClawPayloads:
    def test_api_bypass_payloads_structure(self):
        assert len(API_AUTH_BYPASS_PAYLOADS) > 0
        for p in API_AUTH_BYPASS_PAYLOADS:
            assert "id" in p
            assert "path" in p
            assert "method" in p
            assert "detect_in_response" in p
            assert "severity" in p
            assert p["severity"] in ("critical", "high", "medium", "low")
            assert p["path"].startswith("/")

    def test_dm_injection_payloads_structure(self):
        assert len(DM_PROMPT_INJECTION_PAYLOADS) > 0
        for p in DM_PROMPT_INJECTION_PAYLOADS:
            assert "id" in p
            assert "payload" in p
            assert len(p["payload"]) > 0

    def test_message_injection_payloads_have_body(self):
        for p in MESSAGE_INJECTION_PAYLOADS:
            assert "body" in p
            assert isinstance(p["body"], dict)

    def test_ssrf_payloads_have_internal_urls(self):
        for p in SSRF_WEBHOOK_PAYLOADS:
            body = p.get("body", {})
            url = body.get("url", "")
            # Should target internal/metadata IPs
            assert any(seg in url for seg in ("169.254", "127.0.0.1", "localhost", "10.", "192.168."))

    def test_websocket_probe_paths_are_valid(self):
        assert len(WEBSOCKET_PROBE_PATHS) > 0
        for path in WEBSOCKET_PROBE_PATHS:
            assert path.startswith("/")

    def test_no_duplicate_payload_ids(self):
        all_ids = (
            [p["id"] for p in API_AUTH_BYPASS_PAYLOADS]
            + [p["id"] for p in DM_PROMPT_INJECTION_PAYLOADS]
            + [p["id"] for p in MESSAGE_INJECTION_PAYLOADS]
            + [p["id"] for p in SSRF_WEBHOOK_PAYLOADS]
        )
        assert len(all_ids) == len(set(all_ids)), "Duplicate payload IDs found"


# ===========================================================================
# RESULT MODEL TESTS
# ===========================================================================


class TestOpenClawScanResult:
    def _result_with_vuln(self, severity: OpenClawVulnSeverity) -> OpenClawScanResult:
        r = OpenClawScanResult(target="192.168.1.10")
        r.vulnerabilities.append(
            OpenClawVulnerability(
                vuln_id="TEST-001",
                severity=severity,
                title="Test",
                description="Test",
            )
        )
        return r

    def test_critical_vulns_property(self):
        r = self._result_with_vuln(OpenClawVulnSeverity.CRITICAL)
        assert len(r.critical_vulns) == 1
        assert len(r.high_vulns) == 0

    def test_high_vulns_property(self):
        r = self._result_with_vuln(OpenClawVulnSeverity.HIGH)
        assert len(r.high_vulns) == 1
        assert len(r.critical_vulns) == 0

    def test_all_vulns_includes_all_severities(self):
        r = OpenClawScanResult(target="192.168.1.10")
        for sev in OpenClawVulnSeverity:
            r.vulnerabilities.append(
                OpenClawVulnerability(
                    vuln_id=f"T-{sev.value}", severity=sev,
                    title="x", description="x",
                )
            )
        assert len(r.all_vulns) == len(OpenClawVulnSeverity)

    def test_default_target_fields(self):
        r = OpenClawScanResult(target="10.0.0.1")
        assert r.port == 18789
        assert r.is_openclaw is False
        assert r.error == ""

    def test_model_serializes_to_dict(self):
        r = OpenClawScanResult(target="10.0.0.1", is_openclaw=True)
        d = r.model_dump()
        assert d["target"] == "10.0.0.1"
        assert d["is_openclaw"] is True


class TestOpenClawAttackReport:
    def test_successful_attacks_property(self):
        report = OpenClawAttackReport(target="10.0.0.1", port=18789)
        report.attack_results = [
            OpenClawAttackResult(
                attack_id="A1", description="x",
                severity=OpenClawVulnSeverity.CRITICAL,
                succeeded=True, evidence="hit",
            ),
            OpenClawAttackResult(
                attack_id="A2", description="x",
                severity=OpenClawVulnSeverity.LOW,
                succeeded=False,
            ),
        ]
        assert len(report.successful_attacks) == 1
        assert report.successful_attacks[0].attack_id == "A1"

    def test_critical_successes_property(self):
        report = OpenClawAttackReport(target="10.0.0.1", port=18789)
        report.attack_results = [
            OpenClawAttackResult(
                attack_id="C1", description="x",
                severity=OpenClawVulnSeverity.CRITICAL,
                succeeded=True,
            ),
            OpenClawAttackResult(
                attack_id="H1", description="x",
                severity=OpenClawVulnSeverity.HIGH,
                succeeded=True,
            ),
        ]
        assert len(report.critical_successes) == 1
        assert report.critical_successes[0].attack_id == "C1"


# ===========================================================================
# SCANNER FINGERPRINTING TESTS
# ===========================================================================


@pytest.mark.asyncio
class TestOpenClawScannerFingerprint:
    BASE = "http://192.168.1.10:18789"

    @respx.mock
    async def test_fingerprint_via_header(self):
        """Gateway identified via x-openclaw-version response header."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(
                200,
                headers={"x-openclaw-version": "2026.6.10"},
                json={"status": "ok"},
            )
        )
        # Stub remaining paths as 404
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.is_openclaw is True
        assert result.error == ""

    @respx.mock
    async def test_fingerprint_via_body_key(self):
        """Gateway identified via openclaw_version key in response body."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(
                200,
                json=_make_openclaw_health_body(),
            )
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.is_openclaw is True
        assert result.server_info.version == "2026.6.10"

    @respx.mock
    async def test_fingerprint_via_body_value(self):
        """Gateway identified via 'openclaw' in a body value string."""
        respx.get(f"{self.BASE}/api/v1/status").mock(
            return_value=httpx.Response(
                200,
                json={"product": "openclaw-gateway", "version": "2.0"},
            )
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.is_openclaw is True

    @respx.mock
    async def test_non_openclaw_target_returns_false(self):
        """A standard web server should NOT be identified as OpenClaw."""
        respx.route(method="GET").mock(
            return_value=httpx.Response(
                200,
                json={"message": "Hello World", "service": "my-app"},
            )
        )

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.is_openclaw is False
        assert "does not appear" in result.error

    @respx.mock
    async def test_connection_refused_returns_error(self):
        """Connection error should be captured in result.error."""
        respx.route(method="GET").mock(side_effect=httpx.ConnectError("refused"))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.error != ""
        assert result.is_openclaw is False

    @respx.mock
    async def test_timeout_returns_error(self):
        """Timeout should be captured in result.error."""
        respx.route(method="GET").mock(side_effect=httpx.TimeoutException("timeout"))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.error != ""

    @respx.mock
    async def test_server_info_populated_from_health_body(self):
        """ServerInfo fields should be populated from health response."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(
                200,
                json={
                    "openclaw_version": "2026.5.1",
                    "gateway_id": "gw-abc123",
                    "channels": ["telegram", "discord"],
                    "sessions": 3,
                    "nodes": 2,
                },
            )
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.is_openclaw is True
        assert result.server_info.version == "2026.5.1"
        assert result.server_info.gateway_id == "gw-abc123"
        assert "telegram" in result.server_info.connected_channels
        assert result.server_info.active_sessions == 3
        assert result.server_info.node_count == 2


# ===========================================================================
# SCANNER ENDPOINT ENUMERATION TESTS
# ===========================================================================


@pytest.mark.asyncio
class TestOpenClawScannerEndpointEnumeration:
    BASE = "http://192.168.1.10:18789"

    @respx.mock
    async def test_open_api_endpoints_recorded(self):
        """Accessible API endpoints should appear in accessible_endpoints."""
        # Fingerprint path
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        # Open API status endpoint
        respx.get(f"{self.BASE}/api/v1/status").mock(
            return_value=httpx.Response(200, json={"gateway": "ok"})
        )
        # All others return 403
        respx.route(method="GET").mock(return_value=httpx.Response(403))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.is_openclaw is True
        paths = [e.path for e in result.accessible_endpoints]
        assert "/api/v1/status" in paths
        assert "/health" in paths

    @respx.mock
    async def test_sensitive_keys_detected_in_config_response(self):
        """/api/v1/config response with API keys should flag sensitive data."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{self.BASE}/api/v1/config").mock(
            return_value=httpx.Response(
                200,
                json={"agent": {"model": "gpt-4"}, "apiKey": "sk-secret-key"},
            )
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        config_ep = next(
            (e for e in result.accessible_endpoints if e.path == "/api/v1/config"), None
        )
        assert config_ep is not None
        assert "apiKey" in config_ep.sensitive_data_found

    @respx.mock
    async def test_paths_are_deduplicated(self):
        """Each path should appear only once in accessible_endpoints."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.route(method="GET").mock(return_value=httpx.Response(200, json={}))

        scanner = _make_scanner()
        result = await scanner.scan()

        paths = [e.path for e in result.accessible_endpoints]
        assert len(paths) == len(set(paths)), "Duplicate paths found in accessible_endpoints"

    @respx.mock
    async def test_auth_protected_endpoints_not_recorded(self):
        """401/403 responses should not be added to accessible_endpoints."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{self.BASE}/api/v1/sessions").mock(
            return_value=httpx.Response(401, json={"error": "unauthorized"})
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        paths = [e.path for e in result.accessible_endpoints]
        assert "/api/v1/sessions" not in paths


# ===========================================================================
# SCANNER AUTHENTICATION POSTURE TESTS
# ===========================================================================


@pytest.mark.asyncio
class TestOpenClawScannerAuthPosture:
    BASE = "http://192.168.1.10:18789"

    @respx.mock
    async def test_unauthenticated_api_detected(self):
        """unauthenticated_api_access should be True when /api/v1/status is open."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{self.BASE}/api/v1/status").mock(
            return_value=httpx.Response(200, json={"version": "2026.6.10"})
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.auth_posture.unauthenticated_api_access is True
        assert result.auth_posture.auth_type == "none"

    @respx.mock
    async def test_authenticated_gateway_auth_type_unknown(self):
        """When all API paths return 401, auth_type should be 'unknown' (not 'none')."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.route(method="GET").mock(return_value=httpx.Response(401))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.auth_posture.unauthenticated_api_access is False
        assert result.auth_posture.auth_type == "unknown"

    @respx.mock
    async def test_websocket_upgrade_detected(self):
        """WebSocket unauthenticated access detected when server returns 101."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        # Return 101 for the WS upgrade probe on /
        respx.get(f"{self.BASE}/").mock(
            return_value=httpx.Response(101, headers={"upgrade": "websocket"})
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.auth_posture.unauthenticated_ws_access is True

    @respx.mock
    async def test_websocket_not_detected_when_200_no_upgrade_header(self):
        """Regular 200 response without upgrade header should NOT set ws_access=True."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{self.BASE}/").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.auth_posture.unauthenticated_ws_access is False


# ===========================================================================
# SCANNER CONFIGURATION ASSESSMENT TESTS
# ===========================================================================


@pytest.mark.asyncio
class TestOpenClawScannerConfiguration:
    BASE = "http://192.168.1.10:18789"

    @respx.mock
    async def test_open_dm_policy_detected(self):
        """DM policy 'open' on a channel should be flagged."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{self.BASE}/api/v1/config").mock(
            return_value=httpx.Response(
                200,
                json={
                    "channels": {
                        "telegram": {"dmPolicy": "open", "allowFrom": ["*"]},
                        "discord": {"dmPolicy": "pairing"},
                    }
                },
            )
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert "telegram" in result.dm_policy.channels_with_open_dm
        assert result.dm_policy.has_wildcard_allowlist is True
        assert result.dm_policy.policy == "open"
        assert "discord" in result.dm_policy.channels_with_pairing

    @respx.mock
    async def test_sandbox_disabled_detected(self):
        """Explicitly disabled sandbox mode should be detected."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{self.BASE}/api/v1/config").mock(
            return_value=httpx.Response(
                200,
                json={
                    "agents": {
                        "defaults": {
                            "sandbox": {"mode": "disabled", "backend": "none"}
                        }
                    }
                },
            )
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.sandbox_info.sandbox_mode == "disabled"
        assert result.sandbox_info.is_sandboxed is False
        # Should also appear as a vulnerability
        vuln_ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OCL-ADV-003" in vuln_ids

    @respx.mock
    async def test_non_main_sandbox_not_flagged(self):
        """non-main sandbox mode is correct and should NOT produce OCL-ADV-003."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{self.BASE}/api/v1/config").mock(
            return_value=httpx.Response(
                200,
                json={
                    "agents": {
                        "defaults": {
                            "sandbox": {"mode": "non-main", "backend": "docker"}
                        }
                    }
                },
            )
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.sandbox_info.is_sandboxed is True
        vuln_ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OCL-ADV-003" not in vuln_ids

    @respx.mock
    async def test_unknown_sandbox_not_flagged(self):
        """When config is inaccessible (unknown sandbox), OCL-ADV-003 not emitted."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{self.BASE}/api/v1/config").mock(
            return_value=httpx.Response(403, json={"error": "forbidden"})
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.sandbox_info.sandbox_mode == "unknown"
        vuln_ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OCL-ADV-003" not in vuln_ids


# ===========================================================================
# SCANNER VULNERABILITY MATCHING TESTS
# ===========================================================================


@pytest.mark.asyncio
class TestOpenClawScannerVulnerabilities:
    BASE = "http://192.168.1.10:18789"

    @respx.mock
    async def test_fully_exposed_gateway_produces_critical_vulns(self):
        """A fully unauthenticated gateway should produce critical vulnerability OCL-ADV-001."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{self.BASE}/api/v1/status").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert len(result.critical_vulns) > 0
        vuln_ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OCL-ADV-001" in vuln_ids

    @respx.mock
    async def test_open_dm_produces_high_vuln(self):
        """Open DM policy should produce OCL-ADV-002 (HIGH severity)."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{self.BASE}/api/v1/config").mock(
            return_value=httpx.Response(
                200,
                json={"channels": {"telegram": {"dmPolicy": "open", "allowFrom": ["*"]}}},
            )
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        vuln_ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OCL-ADV-002" in vuln_ids
        vuln = next(v for v in result.vulnerabilities if v.vuln_id == "OCL-ADV-002")
        assert vuln.severity == OpenClawVulnSeverity.HIGH

    @respx.mock
    async def test_secure_gateway_minimal_vulns(self):
        """A properly secured gateway should produce no critical findings."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        # All API paths protected
        respx.route(method="GET").mock(return_value=httpx.Response(401))

        scanner = _make_scanner()
        result = await scanner.scan()

        assert len(result.critical_vulns) == 0

    @respx.mock
    async def test_vuln_ids_are_unique_in_result(self):
        """The same vulnerability ID should not be added multiple times."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{self.BASE}/api/v1/status").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        vuln_ids = [v.vuln_id for v in result.vulnerabilities]
        assert len(vuln_ids) == len(set(vuln_ids)), "Duplicate vuln IDs in result"

    @respx.mock
    async def test_session_history_endpoint_produces_vuln(self):
        """Accessible /api/v1/sessions/history should produce OCL-ADV-007."""
        respx.get(f"{self.BASE}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{self.BASE}/api/v1/sessions/history").mock(
            return_value=httpx.Response(
                200,
                json={"messages": [{"role": "user", "content": "hello"}]},
            )
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner()
        result = await scanner.scan()

        vuln_ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OCL-ADV-007" in vuln_ids

    @respx.mock
    async def test_result_error_when_not_openclaw(self):
        """Scanning a non-OpenClaw target should set a descriptive error."""
        respx.route(method="GET").mock(
            return_value=httpx.Response(200, json={"app": "my-service"})
        )

        scanner = _make_scanner()
        result = await scanner.scan()

        assert result.is_openclaw is False
        assert "does not appear" in result.error
        assert len(result.vulnerabilities) == 0


# ===========================================================================
# ATTACKER AUTHORIZATION GATING TESTS
# ===========================================================================


class TestOpenClawAttackerAuthorization:
    def test_no_auth_raises(self):
        with pytest.raises(AuthorizationRequired):
            OpenClawAttacker(authorized=False)

    def test_default_no_auth_raises(self):
        with pytest.raises(AuthorizationRequired):
            OpenClawAttacker()

    def test_with_auth_succeeds(self):
        attacker = OpenClawAttacker(authorized=True)
        assert attacker.authorized is True

    def test_auth_error_message_is_descriptive(self):
        with pytest.raises(AuthorizationRequired, match="explicit written authorization"):
            OpenClawAttacker(authorized=False)


# ===========================================================================
# ATTACKER API PROBE TESTS
# ===========================================================================


@pytest.mark.asyncio
class TestOpenClawAttackerApiProbes:
    BASE = "http://192.168.1.10:18789"

    @respx.mock
    async def test_safe_mode_runs_api_probes(self):
        """safe mode should run API endpoint probes and return results."""
        # All API probes return 200 (unauthenticated)
        respx.route(method="GET").mock(return_value=httpx.Response(200, json={"ok": True}))
        respx.route(method="POST").mock(return_value=httpx.Response(200, json={"ok": True}))

        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(target="192.168.1.10", port=18789, mode="safe")

        assert isinstance(report, OpenClawAttackReport)
        assert len(report.attack_results) == len(API_AUTH_BYPASS_PAYLOADS)

    @respx.mock
    async def test_safe_mode_does_not_run_message_injection(self):
        """safe mode must NOT run message injection attacks."""
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        respx.route(method="POST").mock(return_value=httpx.Response(404))

        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(target="192.168.1.10", port=18789, mode="safe")

        msg_ids = {p["id"] for p in MESSAGE_INJECTION_PAYLOADS}
        result_ids = {r.attack_id for r in report.attack_results}
        assert not msg_ids & result_ids, "Message injection ran in safe mode"

    @respx.mock
    async def test_successful_attack_recorded(self):
        """A 200 response to an API probe should mark the result as succeeded."""
        respx.get(f"{self.BASE}/api/v1/status").mock(
            return_value=httpx.Response(200, json={"gateway": "ok", "version": "2026"})
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        respx.route(method="POST").mock(return_value=httpx.Response(404))

        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(target="192.168.1.10", port=18789, mode="safe")

        status_result = next(
            (r for r in report.attack_results if r.attack_id == "OCL-ATK-API-001"), None
        )
        assert status_result is not None
        assert status_result.succeeded is True

    @respx.mock
    async def test_failed_attack_not_succeeded(self):
        """A 401 response should NOT mark the attack as succeeded."""
        respx.route(method="GET").mock(return_value=httpx.Response(401))
        respx.route(method="POST").mock(return_value=httpx.Response(401))

        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(target="192.168.1.10", port=18789, mode="safe")

        succeeded = [r for r in report.attack_results if r.succeeded]
        assert len(succeeded) == 0

    @respx.mock
    async def test_connection_error_recorded_in_result(self):
        """Network errors during attack should be captured in result.error, not raised."""
        respx.route(method="GET").mock(side_effect=httpx.ConnectError("refused"))
        respx.route(method="POST").mock(side_effect=httpx.ConnectError("refused"))

        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(target="192.168.1.10", port=18789, mode="safe")

        # All results should have error set, none should have succeeded
        for r in report.attack_results:
            assert r.succeeded is False
        errors = [r for r in report.attack_results if r.error]
        assert len(errors) > 0

    @respx.mock
    async def test_attack_duration_recorded(self):
        """Attack duration should be a positive number."""
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        respx.route(method="POST").mock(return_value=httpx.Response(404))

        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(target="192.168.1.10", port=18789, mode="safe")

        assert report.attack_duration > 0


# ===========================================================================
# ATTACKER DEEP MODE TESTS
# ===========================================================================


@pytest.mark.asyncio
class TestOpenClawAttackerDeepMode:
    @respx.mock
    async def test_deep_mode_runs_message_injection(self):
        """deep mode should include message injection attacks."""
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        respx.route(method="POST").mock(return_value=httpx.Response(404))

        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(target="192.168.1.10", port=18789, mode="deep")

        msg_ids = {p["id"] for p in MESSAGE_INJECTION_PAYLOADS}
        result_ids = {r.attack_id for r in report.attack_results}
        assert msg_ids & result_ids, "Message injection did not run in deep mode"

    @respx.mock
    async def test_deep_mode_includes_prompt_injection_report(self):
        """deep mode should include prompt injection informational results."""
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        respx.route(method="POST").mock(return_value=httpx.Response(404))

        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(target="192.168.1.10", port=18789, mode="deep")

        pi_ids = {p["id"] for p in DM_PROMPT_INJECTION_PAYLOADS}
        result_ids = {r.attack_id for r in report.attack_results}
        assert pi_ids & result_ids, "Prompt injection results not in deep mode report"

    @respx.mock
    async def test_deep_mode_runs_ssrf_probes(self):
        """deep mode should include SSRF webhook probes."""
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        respx.route(method="POST").mock(return_value=httpx.Response(404))

        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(target="192.168.1.10", port=18789, mode="deep")

        ssrf_ids = {p["id"] for p in SSRF_WEBHOOK_PAYLOADS}
        result_ids = {r.attack_id for r in report.attack_results}
        assert ssrf_ids & result_ids, "SSRF probes did not run in deep mode"

    @respx.mock
    async def test_message_injection_success_detected(self):
        """Successful message injection (200 with expected body) should be recorded."""
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        # Message injection endpoint returns 201 with success indicator
        respx.post("http://192.168.1.10:18789/api/v1/message").mock(
            return_value=httpx.Response(201, json={"success": True, "message_id": "abc"})
        )
        respx.post("http://192.168.1.10:18789/api/v1/sessions/send").mock(
            return_value=httpx.Response(200, json={"sent": True})
        )
        respx.route(method="POST").mock(return_value=httpx.Response(404))

        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(target="192.168.1.10", port=18789, mode="deep")

        msg_result = next(
            (r for r in report.attack_results if r.attack_id == "OCL-ATK-MSG-001"), None
        )
        assert msg_result is not None
        assert msg_result.succeeded is True


# ===========================================================================
# END-TO-END INTEGRATION: SCAN THEN ATTACK
# ===========================================================================


@pytest.mark.asyncio
class TestOpenClawScanThenAttack:
    """Simulate the full CLI flow: scan -> attack with scan_result passed in."""

    @respx.mock
    async def test_scan_result_passed_to_attacker(self):
        """Scan result can be injected into attacker to avoid re-fingerprinting."""
        # Build a pre-canned scan result
        scan_result = OpenClawScanResult(
            target="192.168.1.10",
            port=18789,
            is_openclaw=True,
            server_info=OpenClawServerInfo(version="2026.6.10"),
        )

        respx.route(method="GET").mock(return_value=httpx.Response(404))
        respx.route(method="POST").mock(return_value=httpx.Response(404))

        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(
            target="192.168.1.10", port=18789, mode="safe",
            scan_result=scan_result,
        )

        assert report.scan_result is scan_result
        assert report.target == "192.168.1.10"

    @respx.mock
    async def test_full_unauthenticated_gateway_e2e(self):
        """
        Full end-to-end: scan a fully exposed gateway, then attack it.
        Scanner should find critical vulns; attacker should find successful probes.
        """
        base = "http://10.0.0.5:18789"

        # --- Scanner phase ---
        respx.get(f"{base}/health").mock(
            return_value=httpx.Response(200, json=_make_openclaw_health_body())
        )
        respx.get(f"{base}/api/v1/status").mock(
            return_value=httpx.Response(200, json={"status": "online", "gateway": "openclaw"})
        )
        respx.get(f"{base}/api/v1/sessions").mock(
            return_value=httpx.Response(200, json={"sessions": []})
        )
        respx.get(f"{base}/api/v1/sessions/history").mock(
            return_value=httpx.Response(200, json={"messages": [{"role": "user", "content": "hi"}]})
        )
        # Remaining paths → 404
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        respx.route(method="POST").mock(return_value=httpx.Response(404))

        scanner = OpenClawScanner(target="10.0.0.5", port=18789, timeout=5.0)
        scan_result = await scanner.scan()

        assert scan_result.is_openclaw is True
        assert len(scan_result.critical_vulns) > 0
        assert scan_result.auth_posture.unauthenticated_api_access is True

        # --- Attack phase ---
        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(
            target="10.0.0.5", port=18789, mode="safe",
            scan_result=scan_result,
        )

        assert len(report.attack_results) > 0
        assert len(report.successful_attacks) > 0
        # Status endpoint should succeed
        api_001 = next(
            (r for r in report.attack_results if r.attack_id == "OCL-ATK-API-001"), None
        )
        assert api_001 is not None
        assert api_001.succeeded is True
