"""Tests for Postman collection parser, scanner, attacker, and result models."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from offsec_ai.exceptions import AuthorizationRequired
from offsec_ai.models.postman_result import (
    PostmanAttackReport,
    PostmanAttackResult,
    PostmanEndpoint,
    PostmanEndpointResult,
    PostmanScanResult,
    PostmanVulnerability,
    PostmanVulnSeverity,
)
from offsec_ai.utils.postman_parser import (
    apply_target_override,
    flatten_items,
    load_collection,
    load_environment,
    parse_collection,
)
from offsec_ai.utils.postman_findings import scan_for_secrets, SENSITIVE_ENDPOINT_KEYWORDS
from offsec_ai.utils.postman_payloads import (
    AUTH_BYPASS_PAYLOADS,
    BOLA_ID_MUTATIONS,
    INJECTION_PAYLOADS,
    MASS_ASSIGNMENT_FIELDS,
    SSRF_PAYLOADS,
    SSRF_CANDIDATE_FIELD_NAMES,
)
from offsec_ai.core.postman_scanner import PostmanScanner
from offsec_ai.core.postman_attacker import PostmanAttacker


# ---------------------------------------------------------------------------
# Minimal Postman Collection fixture
# ---------------------------------------------------------------------------

_SAMPLE_COLLECTION = {
    "info": {
        "name": "Test API",
        "_postman_id": "test-id",
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    "variable": [
        {"key": "baseUrl", "value": "https://api.example.com"},
        {"key": "userId", "value": "42"},
    ],
    "item": [
        {
            "name": "Users",
            "item": [
                {
                    "name": "Get User",
                    "request": {
                        "method": "GET",
                        "header": [{"key": "X-Api-Version", "value": "1"}],
                        "url": {
                            "raw": "{{baseUrl}}/users/{{userId}}",
                            "host": ["{{baseUrl}}"],
                            "path": ["users", "{{userId}}"],
                        },
                        "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "tok"}]},
                    },
                },
                {
                    "name": "List Users",
                    "request": {
                        "method": "GET",
                        "header": [],
                        "url": {
                            "raw": "{{baseUrl}}/users",
                            "host": ["{{baseUrl}}"],
                            "path": ["users"],
                            "query": [{"key": "search", "value": "alice"}],
                        },
                    },
                },
                {
                    "name": "Create User",
                    "request": {
                        "method": "POST",
                        "header": [{"key": "Content-Type", "value": "application/json"}],
                        "body": {
                            "mode": "raw",
                            "raw": '{"name": "alice", "email": "alice@example.com"}',
                        },
                        "url": {"raw": "{{baseUrl}}/users"},
                    },
                },
            ],
        },
        {
            "name": "Admin Panel",
            "request": {
                "method": "GET",
                "header": [],
                "url": {"raw": "{{baseUrl}}/admin"},
            },
        },
        {
            "name": "Unresolved Var Request",
            "request": {
                "method": "GET",
                "header": [],
                "url": {"raw": "{{baseUrl}}/items/{{unknownVar}}"},
            },
        },
        {
            "name": "SSRF Candidate",
            "request": {
                "method": "POST",
                "header": [{"key": "Content-Type", "value": "application/json"}],
                "body": {
                    "mode": "raw",
                    "raw": '{"url": "https://trusted.example.com/image.png"}',
                },
                "url": {"raw": "{{baseUrl}}/fetch"},
            },
        },
    ],
}

_SAMPLE_ENV = {
    "values": [
        {"key": "baseUrl", "value": "https://env.example.com", "enabled": True},
        {"key": "userId", "value": "99", "enabled": True},
    ]
}


def _write_collection(tmp_path: Path, data: dict | None = None) -> Path:
    p = tmp_path / "collection.json"
    p.write_text(json.dumps(data or _SAMPLE_COLLECTION))
    return p


def _write_environment(tmp_path: Path) -> Path:
    p = tmp_path / "env.json"
    p.write_text(json.dumps(_SAMPLE_ENV))
    return p


# ---------------------------------------------------------------------------
# Payload validation
# ---------------------------------------------------------------------------

class TestPostmanPayloads:
    def _check_ids_unique(self, payloads: list[dict], id_key: str = "id"):
        ids = [p[id_key] for p in payloads]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

    def test_auth_bypass_ids_unique(self):
        self._check_ids_unique(AUTH_BYPASS_PAYLOADS)

    def test_bola_ids_unique(self):
        self._check_ids_unique(BOLA_ID_MUTATIONS)

    def test_mass_assignment_ids_unique(self):
        self._check_ids_unique(MASS_ASSIGNMENT_FIELDS)

    def test_injection_ids_unique(self):
        self._check_ids_unique(INJECTION_PAYLOADS)

    def test_ssrf_ids_unique(self):
        self._check_ids_unique(SSRF_PAYLOADS)

    def test_auth_bypass_has_mutation(self):
        for p in AUTH_BYPASS_PAYLOADS:
            assert "mutation" in p

    def test_injection_payloads_have_detect_in_response(self):
        for p in INJECTION_PAYLOADS:
            assert "detect_in_response" in p
            assert len(p["detect_in_response"]) > 0

    def test_ssrf_payloads_have_url(self):
        for p in SSRF_PAYLOADS:
            assert "url" in p

    def test_mass_assignment_fields_have_field_and_value(self):
        for p in MASS_ASSIGNMENT_FIELDS:
            assert "field" in p
            assert "value" in p

    def test_all_severities_are_valid(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for payload_list in [AUTH_BYPASS_PAYLOADS, BOLA_ID_MUTATIONS, INJECTION_PAYLOADS,
                              MASS_ASSIGNMENT_FIELDS, SSRF_PAYLOADS]:
            for p in payload_list:
                assert p["severity"] in valid, f"Invalid severity in {p}"

    def test_ssrf_candidate_field_names_non_empty(self):
        assert len(SSRF_CANDIDATE_FIELD_NAMES) > 0
        assert "url" in SSRF_CANDIDATE_FIELD_NAMES


# ---------------------------------------------------------------------------
# Findings utilities
# ---------------------------------------------------------------------------

class TestPostmanFindings:
    def test_scan_for_secrets_detects_api_key(self):
        text = 'Authorization: "api_key: sk-abc123xyz456abc123xyz456abc123xyz456"'
        result = scan_for_secrets(text)
        assert len(result) > 0

    def test_scan_for_secrets_detects_jwt(self):
        text = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc"
        result = scan_for_secrets(text)
        assert len(result) > 0

    def test_scan_for_secrets_returns_empty_for_clean_text(self):
        result = scan_for_secrets("Hello, world! Nothing sensitive here.")
        assert result == []

    def test_scan_for_secrets_empty_string(self):
        assert scan_for_secrets("") == []

    def test_sensitive_endpoint_keywords_non_empty(self):
        assert "admin" in SENSITIVE_ENDPOINT_KEYWORDS
        assert "user" in SENSITIVE_ENDPOINT_KEYWORDS
        assert "payment" in SENSITIVE_ENDPOINT_KEYWORDS


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestPostmanParser:
    def test_load_collection_valid(self, tmp_path):
        p = _write_collection(tmp_path)
        data = load_collection(p)
        assert data["info"]["name"] == "Test API"

    def test_load_collection_invalid_raises(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text('{"foo": "bar"}')
        with pytest.raises(ValueError, match="Postman Collection"):
            load_collection(p)

    def test_load_environment(self, tmp_path):
        env_path = _write_environment(tmp_path)
        env = load_environment(env_path)
        assert env["baseUrl"] == "https://env.example.com"
        assert env["userId"] == "99"

    def test_load_environment_none_returns_empty(self):
        assert load_environment(None) == {}

    def test_flatten_items_resolves_variables(self, tmp_path):
        col = _write_collection(tmp_path)
        name, endpoints = parse_collection(col)
        get_user = next(ep for ep in endpoints if ep.name == "Get User")
        assert "{{" not in get_user.url
        assert "42" in get_user.url or "users" in get_user.url

    def test_flatten_items_unresolved_variable_flagged(self, tmp_path):
        col = _write_collection(tmp_path)
        name, endpoints = parse_collection(col)
        unresolved_ep = next(ep for ep in endpoints if ep.name == "Unresolved Var Request")
        assert "unknownVar" in unresolved_ep.unresolved_variables

    def test_parse_collection_returns_name(self, tmp_path):
        col = _write_collection(tmp_path)
        name, endpoints = parse_collection(col)
        assert name == "Test API"

    def test_parse_collection_flattens_folders(self, tmp_path):
        col = _write_collection(tmp_path)
        name, endpoints = parse_collection(col)
        # Should have more than the top-level items (nested Users folder is flattened)
        assert len(endpoints) >= 4

    def test_parse_collection_methods_correct(self, tmp_path):
        col = _write_collection(tmp_path)
        name, endpoints = parse_collection(col)
        methods = {ep.name: ep.method for ep in endpoints}
        assert methods["Get User"] == "GET"
        assert methods["Create User"] == "POST"

    def test_parse_collection_with_environment_overrides_vars(self, tmp_path):
        col = _write_collection(tmp_path)
        env = _write_environment(tmp_path)
        name, endpoints = parse_collection(col, environment_path=env)
        get_user = next(ep for ep in endpoints if ep.name == "Get User")
        # Environment has userId=99, overriding collection's 42
        assert "99" in get_user.url

    def test_parse_collection_folder_path_set(self, tmp_path):
        col = _write_collection(tmp_path)
        name, endpoints = parse_collection(col)
        get_user = next(ep for ep in endpoints if ep.name == "Get User")
        assert get_user.folder_path == "Users"

    def test_target_override_replaces_host(self, tmp_path):
        col = _write_collection(tmp_path)
        name, endpoints = parse_collection(col, target_override="https://staging.example.com")
        for ep in endpoints:
            if ep.url.startswith("http"):
                assert "staging.example.com" in ep.url

    def test_apply_target_override_no_scheme(self):
        ep = PostmanEndpoint(url="https://api.example.com/users", raw_url="{{baseUrl}}/users")
        updated = apply_target_override(ep, "staging.example.com")
        assert "staging.example.com" in updated.url
        assert "/users" in updated.url

    def test_parse_collection_body_extracted(self, tmp_path):
        col = _write_collection(tmp_path)
        name, endpoints = parse_collection(col)
        create = next(ep for ep in endpoints if ep.name == "Create User")
        assert "alice" in create.body

    def test_parse_collection_query_params_extracted(self, tmp_path):
        col = _write_collection(tmp_path)
        name, endpoints = parse_collection(col)
        list_ep = next(ep for ep in endpoints if ep.name == "List Users")
        assert list_ep.query_params.get("search") == "alice"


# ---------------------------------------------------------------------------
# Result model tests
# ---------------------------------------------------------------------------

class TestPostmanResultModels:
    def _make_scan_result(self, vulns: list | None = None) -> PostmanScanResult:
        return PostmanScanResult(
            collection_name="Test API",
            vulnerabilities=vulns or [],
        )

    def test_scan_result_creation(self):
        r = self._make_scan_result()
        assert r.collection_name == "Test API"
        assert r.error is None

    def test_critical_vulns_property(self):
        vulns = [
            PostmanVulnerability(vuln_id="PM-001", severity=PostmanVulnSeverity.CRITICAL, title="c", description="d"),
            PostmanVulnerability(vuln_id="PM-002", severity=PostmanVulnSeverity.HIGH, title="h", description="d"),
        ]
        r = self._make_scan_result(vulns)
        assert len(r.critical_vulns) == 1
        assert r.has_critical

    def test_high_vulns_property(self):
        vulns = [
            PostmanVulnerability(vuln_id="PM-001", severity=PostmanVulnSeverity.HIGH, title="h", description="d"),
        ]
        r = self._make_scan_result(vulns)
        assert len(r.high_vulns) == 1
        assert not r.has_critical

    def test_attack_report_successful_attacks(self):
        results = [
            PostmanAttackResult(attack_id="PM-ATK-AB-001", triggered=True,
                                severity=PostmanVulnSeverity.HIGH, title="t", description="d"),
            PostmanAttackResult(attack_id="PM-ATK-AB-002", triggered=False,
                                severity=PostmanVulnSeverity.INFO, title="t2", description="d"),
        ]
        report = PostmanAttackReport(results=results, attacks_triggered=1)
        assert len(report.successful_attacks) == 1

    def test_endpoint_model_defaults(self):
        ep = PostmanEndpoint(url="https://api.example.com/users")
        assert ep.method == "GET"
        assert ep.body == ""
        assert ep.unresolved_variables == []

    def test_endpoint_result_model(self):
        ep = PostmanEndpoint(url="https://api.example.com/users")
        r = PostmanEndpointResult(endpoint=ep, status_code=200)
        assert r.status_code == 200
        assert r.error == ""


# ---------------------------------------------------------------------------
# Scanner tests (static analysis — no network)
# ---------------------------------------------------------------------------

class TestPostmanScannerStaticAnalysis:
    def _make_scanner(self, col_path: str) -> PostmanScanner:
        return PostmanScanner(collection_path=col_path, timeout=5.0, verify_tls=False)

    def _make_endpoint(self, name: str = "test", url: str = "https://api.example.com/users",
                       method: str = "GET", auth_type: str = "noauth",
                       unresolved: list | None = None) -> PostmanEndpoint:
        from offsec_ai.models.postman_result import PostmanAuthInfo
        return PostmanEndpoint(
            name=name, url=url, method=method,
            auth=PostmanAuthInfo(type=auth_type),
            unresolved_variables=unresolved or [],
        )

    def _make_endpoint_result(self, endpoint: PostmanEndpoint, status: int = 200,
                               response: str = "", headers: dict | None = None) -> PostmanEndpointResult:
        return PostmanEndpointResult(
            endpoint=endpoint, status_code=status,
            response_snippet=response, response_headers=headers or {},
        )

    def test_sensitive_endpoint_no_auth_flagged(self, tmp_path):
        col = _write_collection(tmp_path)
        scanner = self._make_scanner(str(col))
        ep = self._make_endpoint(name="Admin Settings", url="https://api.example.com/admin/settings")
        result = self._make_endpoint_result(ep, status=200)
        vulns = scanner._analyze_endpoint(ep, result)
        ids = {v.vuln_id for v in vulns}
        assert "PM-ADV-AUTH-001" in ids

    def test_sensitive_endpoint_with_auth_not_flagged(self, tmp_path):
        col = _write_collection(tmp_path)
        scanner = self._make_scanner(str(col))
        ep = self._make_endpoint(name="Admin Settings", url="https://api.example.com/admin", auth_type="bearer")
        result = self._make_endpoint_result(ep, status=200)
        vulns = scanner._analyze_endpoint(ep, result)
        auth_vulns = [v for v in vulns if v.vuln_id == "PM-ADV-AUTH-001"]
        assert len(auth_vulns) == 0

    def test_sensitive_endpoint_4xx_not_flagged(self, tmp_path):
        col = _write_collection(tmp_path)
        scanner = self._make_scanner(str(col))
        ep = self._make_endpoint(name="Delete User", url="https://api.example.com/user/delete")
        result = self._make_endpoint_result(ep, status=401)
        vulns = scanner._analyze_endpoint(ep, result)
        auth_vulns = [v for v in vulns if v.vuln_id == "PM-ADV-AUTH-001"]
        assert len(auth_vulns) == 0

    def test_unresolved_variables_flagged(self, tmp_path):
        col = _write_collection(tmp_path)
        scanner = self._make_scanner(str(col))
        ep = self._make_endpoint(unresolved=["unknownVar"])
        result = self._make_endpoint_result(ep, status=200)
        vulns = scanner._analyze_endpoint(ep, result)
        ids = {v.vuln_id for v in vulns}
        assert "PM-ADV-CFG-001" in ids

    def test_verbose_error_disclosure_sql_flagged(self, tmp_path):
        col = _write_collection(tmp_path)
        scanner = self._make_scanner(str(col))
        ep = self._make_endpoint()
        result = self._make_endpoint_result(ep, status=500,
                                             response="You have an error in your SQL syntax near 'SELECT'")
        vulns = scanner._analyze_endpoint(ep, result)
        ids = {v.vuln_id for v in vulns}
        assert "PM-ADV-MISC-001" in ids

    def test_verbose_error_disclosure_python_traceback_flagged(self, tmp_path):
        col = _write_collection(tmp_path)
        scanner = self._make_scanner(str(col))
        ep = self._make_endpoint()
        result = self._make_endpoint_result(ep, status=500,
                                             response="Traceback (most recent call last):\n  File app.py")
        vulns = scanner._analyze_endpoint(ep, result)
        ids = {v.vuln_id for v in vulns}
        assert "PM-ADV-MISC-001" in ids

    def test_secret_in_response_flagged(self, tmp_path):
        col = _write_collection(tmp_path)
        scanner = self._make_scanner(str(col))
        ep = self._make_endpoint()
        result = self._make_endpoint_result(ep, status=200,
                                             response='{"api_key": "sk-abc123abc123abc123abc123abc123ab"}')
        vulns = scanner._analyze_endpoint(ep, result)
        ids = {v.vuln_id for v in vulns}
        assert "PM-ADV-SEC-001" in ids

    def test_wildcard_cors_flagged(self, tmp_path):
        col = _write_collection(tmp_path)
        scanner = self._make_scanner(str(col))
        ep = self._make_endpoint()
        result = self._make_endpoint_result(ep, status=200,
                                             headers={"access-control-allow-origin": "*"})
        vulns = scanner._analyze_endpoint(ep, result)
        ids = {v.vuln_id for v in vulns}
        assert "PM-ADV-MISC-002" in ids

    def test_clean_response_no_findings(self, tmp_path):
        col = _write_collection(tmp_path)
        scanner = self._make_scanner(str(col))
        ep = self._make_endpoint(auth_type="bearer")
        result = self._make_endpoint_result(ep, status=200, response='{"id": 1, "name": "alice"}')
        vulns = scanner._analyze_endpoint(ep, result)
        assert len(vulns) == 0


# ---------------------------------------------------------------------------
# Scanner integration tests (mocked HTTP)
# ---------------------------------------------------------------------------

class TestPostmanScannerIntegration:
    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_probes_endpoints(self, tmp_path):
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(201, json={"id": 1})
        )
        col = _write_collection(tmp_path)
        scanner = PostmanScanner(str(col), timeout=5.0, verify_tls=False)
        result = await scanner.scan()
        assert result.error is None
        assert result.endpoints_tested > 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_detects_wildcard_cors(self, tmp_path):
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(200, json={}, headers={"Access-Control-Allow-Origin": "*"})
        )
        respx.post(url__regex=r".*").mock(
            return_value=httpx.Response(200, json={})
        )
        col = _write_collection(tmp_path)
        scanner = PostmanScanner(str(col), timeout=5.0, verify_tls=False)
        result = await scanner.scan()
        ids = {v.vuln_id for v in result.vulnerabilities}
        assert "PM-ADV-MISC-002" in ids

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_handles_network_error_gracefully(self, tmp_path):
        respx.get(url__regex=r".*").mock(side_effect=httpx.ConnectError("refused"))
        respx.post(url__regex=r".*").mock(side_effect=httpx.ConnectError("refused"))
        col = _write_collection(tmp_path)
        scanner = PostmanScanner(str(col), timeout=5.0, verify_tls=False)
        result = await scanner.scan()
        # Should not raise; errors recorded in endpoint results
        assert result.error is None
        for ep_result in result.endpoint_results:
            if ep_result.error:
                assert "refused" in ep_result.error

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_with_target_override(self, tmp_path):
        respx.get(url__regex=r"https://override\.example\.com/.*").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        respx.post(url__regex=r"https://override\.example\.com/.*").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        col = _write_collection(tmp_path)
        scanner = PostmanScanner(str(col), target_override="https://override.example.com",
                                  timeout=5.0, verify_tls=False)
        result = await scanner.scan()
        assert result.target_override == "https://override.example.com"

    @pytest.mark.asyncio
    async def test_scan_bad_collection_path_returns_error(self):
        scanner = PostmanScanner("/nonexistent/path/collection.json", timeout=5.0)
        result = await scanner.scan()
        assert result.error is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_max_endpoints_limits_requests(self, tmp_path):
        respx.get(url__regex=r".*").mock(return_value=httpx.Response(200, json={}))
        respx.post(url__regex=r".*").mock(return_value=httpx.Response(200, json={}))
        col = _write_collection(tmp_path)
        scanner = PostmanScanner(str(col), max_endpoints=1, timeout=5.0, verify_tls=False)
        result = await scanner.scan()
        assert result.endpoints_tested <= 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_collection_name_in_result(self, tmp_path):
        respx.get(url__regex=r".*").mock(return_value=httpx.Response(200, json={}))
        respx.post(url__regex=r".*").mock(return_value=httpx.Response(200, json={}))
        col = _write_collection(tmp_path)
        scanner = PostmanScanner(str(col), timeout=5.0, verify_tls=False)
        result = await scanner.scan()
        assert result.collection_name == "Test API"


# ---------------------------------------------------------------------------
# Attacker tests
# ---------------------------------------------------------------------------

class TestPostmanAttacker:
    def test_requires_authorization(self):
        with pytest.raises(AuthorizationRequired):
            PostmanAttacker(authorized=False)

    def test_authorized_instantiation(self):
        attacker = PostmanAttacker(authorized=True)
        assert attacker.authorized is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_attack_safe_mode_runs_auth_bypass(self, tmp_path):
        respx.get(url__regex=r".*").mock(return_value=httpx.Response(200, json={}))
        respx.post(url__regex=r".*").mock(return_value=httpx.Response(200, json={}))
        col = _write_collection(tmp_path)
        attacker = PostmanAttacker(authorized=True)
        report = await attacker.attack(str(col), mode="safe", timeout=5.0, verify_tls=False)
        assert report.authorized is True
        attack_types = {r.attack_type for r in report.results}
        assert "auth_bypass" in attack_types

    @respx.mock
    @pytest.mark.asyncio
    async def test_attack_deep_mode_runs_all_types(self, tmp_path):
        respx.get(url__regex=r".*").mock(return_value=httpx.Response(200, json={}))
        respx.post(url__regex=r".*").mock(return_value=httpx.Response(200, json={}))
        col = _write_collection(tmp_path)
        attacker = PostmanAttacker(authorized=True)
        report = await attacker.attack(str(col), mode="deep", timeout=5.0, verify_tls=False)
        attack_types = {r.attack_type for r in report.results}
        assert "auth_bypass" in attack_types
        # deep mode adds injection, ssrf, etc. (some may not run if no candidate params found)
        assert report.attacks_run > 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_attack_bola_triggered_on_200(self, tmp_path):
        # Endpoint with numeric ID in URL — BOLA should mutate and get 200
        col_data = {**_SAMPLE_COLLECTION}
        col_data["item"] = [
            {
                "name": "Get Order",
                "request": {
                    "method": "GET",
                    "header": [{"key": "Authorization", "value": "Bearer tok"}],
                    "url": {"raw": "https://api.example.com/orders/100"},
                    "auth": {"type": "bearer"},
                },
            }
        ]
        respx.get(url__regex=r".*").mock(return_value=httpx.Response(200, json={"order": "data"}))
        col = tmp_path / "bola_col.json"
        col.write_text(json.dumps(col_data))
        attacker = PostmanAttacker(authorized=True)
        report = await attacker.attack(str(col), mode="deep", timeout=5.0, verify_tls=False)
        bola = [r for r in report.results if r.attack_type == "bola"]
        triggered = [r for r in bola if r.triggered]
        assert len(bola) > 0
        assert len(triggered) > 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_attack_handles_parse_error(self):
        attacker = PostmanAttacker(authorized=True)
        report = await attacker.attack("/nonexistent/collection.json", timeout=5.0)
        assert "Failed to parse" in report.exploit_chain_summary or report.attacks_run == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_attack_with_target_override(self, tmp_path):
        respx.get(url__regex=r"https://target\.example\.com/.*").mock(
            return_value=httpx.Response(200, json={})
        )
        respx.post(url__regex=r"https://target\.example\.com/.*").mock(
            return_value=httpx.Response(200, json={})
        )
        col = _write_collection(tmp_path)
        attacker = PostmanAttacker(authorized=True)
        report = await attacker.attack(
            str(col), target_override="https://target.example.com",
            mode="safe", timeout=5.0, verify_tls=False,
        )
        assert report.target_override == "https://target.example.com"

    @respx.mock
    @pytest.mark.asyncio
    async def test_attack_max_endpoints(self, tmp_path):
        respx.get(url__regex=r".*").mock(return_value=httpx.Response(401, json={}))
        respx.post(url__regex=r".*").mock(return_value=httpx.Response(401, json={}))
        col = _write_collection(tmp_path)
        attacker = PostmanAttacker(authorized=True)
        report = await attacker.attack(str(col), mode="safe", max_endpoints=1, timeout=5.0, verify_tls=False)
        # Only 1 endpoint × auth_bypass payloads run
        assert report.attacks_run <= len(AUTH_BYPASS_PAYLOADS)

    def test_attacker_llm_judge_enrich(self, tmp_path):
        """_enrich_with_llm fills exploit_chain_summary when judge available."""
        mock_judge = MagicMock()
        mock_judge.provider = "openai"
        mock_judge.evaluate.return_value = {"vulnerable": True, "confidence": 0.9, "reason": "chained exploit"}
        attacker = PostmanAttacker(authorized=True, judge=mock_judge)
        report = PostmanAttackReport(
            collection_name="Test",
            results=[
                PostmanAttackResult(attack_id="PM-ATK-AB-001", triggered=True,
                                    attack_type="auth_bypass", endpoint="GET /users",
                                    severity=PostmanVulnSeverity.HIGH, title="bypass", description="d"),
            ],
            attacks_triggered=1,
        )
        attacker._enrich_with_llm(report)
        assert "chained exploit" in report.exploit_chain_summary

    def test_attacker_llm_judge_no_triggered_skips(self):
        mock_judge = MagicMock()
        attacker = PostmanAttacker(authorized=True, judge=mock_judge)
        report = PostmanAttackReport(results=[], attacks_triggered=0)
        attacker._enrich_with_llm(report)
        mock_judge.evaluate.assert_not_called()
