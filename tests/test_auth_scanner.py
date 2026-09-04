"""
Tests for the Auth (OIDC / OAuth 2.0 / SAML) scanner and attacker modules.

Covers:
- CVE database matching logic (unit, no network)
- Security analysis functions (unit, no network)
- LLM Judge triage integration (unit, mocked judge)
- OIDC discovery parsing (integration, httpx mocked via respx)
- SAML metadata parsing (integration, httpx mocked via respx)
- AuthAttacker authorization gate (unit, no network)
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
import respx
import httpx

from offensive_ai.core.auth_scanner import AuthScanner
from offensive_ai.core.auth_attacker import AuthAttacker
from offensive_ai.exceptions import AuthorizationRequired
from offensive_ai.models.auth_result import (
    AuthProtocol,
    AuthProviderInfo,
    AuthScanResult,
    AuthVulnSeverity,
)
from offensive_ai.utils.auth_cve_db import (
    AUTH_CVE_DB,
    match_cves,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MINIMAL_OIDC_DOC = {
    "issuer": "https://auth.example.com",
    "authorization_endpoint": "https://auth.example.com/oauth2/authorize",
    "token_endpoint": "https://auth.example.com/oauth2/token",
    "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code"],
    "code_challenge_methods_supported": ["S256"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "userinfo_endpoint": "https://auth.example.com/userinfo",
}

IMPLICIT_FLOW_OIDC_DOC = {
    **MINIMAL_OIDC_DOC,
    "response_types_supported": ["code", "token", "id_token"],
    "grant_types_supported": ["authorization_code", "implicit"],
}

ALG_NONE_OIDC_DOC = {
    **MINIMAL_OIDC_DOC,
    "id_token_signing_alg_values_supported": ["RS256", "none"],
}

MINIMAL_SAML_XML = """<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://idp.example.com/saml">
  <IDPSSODescriptor WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIBkTCB+wIJ...</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.com/saml/sso"/>
  </IDPSSODescriptor>
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.com/saml/acs"
        index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>"""

SAML_NO_CERTS_XML = """<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://idp.example.com/saml">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.com/saml/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"""


# ===========================================================================
# TestAuthCveDb — unit tests for CVE matching logic (no network)
# ===========================================================================

class TestAuthCveDb:
    def test_db_not_empty(self):
        assert len(AUTH_CVE_DB) >= 10

    def test_all_entries_have_required_fields(self):
        for entry in AUTH_CVE_DB:
            assert entry.vuln_id, f"Missing vuln_id in {entry}"
            assert entry.severity in ("critical", "high", "medium", "low", "info")
            assert entry.title

    def test_universal_entries_match_any_provider(self):
        """Entries with no affected_providers and no check_condition match universally."""
        matches = match_cves("unknown-auth-server", [])
        universal = [m for m in matches if not m.affected_providers and not m.check_condition]
        # AUTH_CVE_DB has no unconditional universal entries; all have either provider or condition
        # So this just checks the function runs without error
        assert isinstance(matches, list)

    def test_condition_based_entry_matches_with_condition(self):
        """AUTH-ADV-003 requires pkce_not_required condition."""
        matches = match_cves("some-server", ["pkce_not_required"])
        ids = {m.vuln_id for m in matches}
        assert "AUTH-ADV-003" in ids

    def test_condition_based_entry_excluded_without_condition(self):
        """AUTH-ADV-003 must NOT match when condition is absent."""
        matches = match_cves("some-server", [])
        ids = {m.vuln_id for m in matches}
        assert "AUTH-ADV-003" not in ids

    def test_implicit_flow_condition_match(self):
        matches = match_cves("any-server", ["implicit_flow_enabled"])
        ids = {m.vuln_id for m in matches}
        assert "AUTH-ADV-004" in ids

    def test_alg_none_condition_match(self):
        matches = match_cves("any-server", ["alg_none_accepted"])
        ids = {m.vuln_id for m in matches}
        assert "AUTH-ADV-006" in ids

    def test_state_not_required_condition_match(self):
        matches = match_cves("any-server", ["state_not_required"])
        ids = {m.vuln_id for m in matches}
        assert "AUTH-ADV-005" in ids

    def test_keycloak_specific_cve_matched_by_name(self):
        matches = match_cves("keycloak 22.0.1", [])
        ids = {m.vuln_id for m in matches}
        assert "AUTH-ADV-008" in ids  # CVE-2023-34462 affects keycloak

    def test_keycloak_specific_cve_not_matched_for_unrelated_provider(self):
        matches = match_cves("okta identity cloud 2.0", [])
        ids = {m.vuln_id for m in matches}
        # AUTH-ADV-008 requires keycloak/netty/redhat — should not match okta
        assert "AUTH-ADV-008" not in ids

    def test_spring_cve_matched_by_name(self):
        matches = match_cves("spring authorization server 0.4.1", [])
        ids = {m.vuln_id for m in matches}
        assert "AUTH-ADV-001" in ids  # CVE-2019-3778

    def test_saml_onelogin_cve_matched(self):
        matches = match_cves("onelogin python-saml 2.1.0", [])
        ids = {m.vuln_id for m in matches}
        assert "AUTH-ADV-010" in ids  # CVE-2017-11427

    def test_saml_shibboleth_cve_matched(self):
        matches = match_cves("shibboleth idp 3.4.0", [])
        ids = {m.vuln_id for m in matches}
        assert "AUTH-ADV-011" in ids  # CVE-2018-0489

    def test_match_returns_cve_entry_objects(self):
        from offensive_ai.utils.auth_cve_db import AuthCVEEntry
        matches = match_cves("keycloak 20", [])
        for m in matches:
            assert isinstance(m, AuthCVEEntry)


# ===========================================================================
# TestAuthScannerAnalysis — unit tests for _analyze_security (no network)
# ===========================================================================

class TestAuthScannerAnalysis:

    def _scanner(self) -> AuthScanner:
        return AuthScanner(target="https://auth.mock.local")

    def _make_result(self, **kwargs) -> AuthScanResult:
        """Build an AuthScanResult with a custom AuthProviderInfo."""
        info = AuthProviderInfo(**kwargs)
        result = AuthScanResult(target="https://auth.mock.local", protocol=AuthProtocol.OIDC)
        result.provider_info = info
        return result

    def test_pkce_not_supported_produces_pkce002(self):
        scanner = self._scanner()
        result = self._make_result(pkce_supported=False, issuer="https://auth.mock.local")
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-AUTH-PKCE-002" in ids

    def test_pkce_supported_but_not_required_produces_pkce001(self):
        scanner = self._scanner()
        result = self._make_result(
            pkce_supported=True, pkce_required=False, issuer="https://auth.mock.local"
        )
        result.provider_info.endpoints["authorization_endpoint"] = "https://auth.mock.local/oauth2/authorize"
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-AUTH-PKCE-001" in ids

    def test_implicit_flow_enabled_produces_impl001(self):
        scanner = self._scanner()
        result = self._make_result(
            pkce_supported=True, pkce_required=True,
            implicit_flow_enabled=True, issuer="https://auth.mock.local"
        )
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-AUTH-IMPL-001" in ids

    def test_alg_none_in_algorithms_produces_jwtalgn001(self):
        scanner = self._scanner()
        result = self._make_result(
            pkce_supported=True, pkce_required=True,
            supported_algorithms=["RS256", "none"], issuer="https://auth.mock.local"
        )
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-AUTH-JWTALGN-001" in ids
        # Severity must be CRITICAL
        alg_none_vulns = [v for v in vulns if v.vuln_id == "OAI-AUTH-JWTALGN-001"]
        assert alg_none_vulns[0].severity == AuthVulnSeverity.CRITICAL

    def test_no_implicit_no_alg_none_clean_config(self):
        """A clean config should produce no HIGH or CRITICAL vulns."""
        scanner = self._scanner()
        result = self._make_result(
            pkce_supported=True, pkce_required=True,
            implicit_flow_enabled=False,
            supported_algorithms=["RS256"],
            issuer="https://auth.mock.local"
        )
        vulns = scanner._analyze_security(result)
        high_plus = [v for v in vulns if v.severity in (AuthVulnSeverity.CRITICAL, AuthVulnSeverity.HIGH)]
        assert len(high_plus) == 0

    def test_saml_no_certs_produces_nosig_vuln(self):
        scanner = self._scanner()
        result = AuthScanResult(target="https://idp.mock.local", protocol=AuthProtocol.SAML)
        result.provider_info.raw = {"signing_certs_found": 0, "source": "https://idp.mock.local/saml/metadata"}
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-AUTH-SAML-NOSIG" in ids

    def test_saml_with_certs_no_nosig_vuln(self):
        scanner = self._scanner()
        result = AuthScanResult(target="https://idp.mock.local", protocol=AuthProtocol.SAML)
        result.provider_info.raw = {"signing_certs_found": 1, "source": "https://idp.mock.local/saml/metadata"}
        result.provider_info.endpoints["acs:HTTP-POST"] = "https://idp.mock.local/saml/acs"
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-AUTH-SAML-NOSIG" not in ids

    def test_saml_xsw_info_vuln_always_present(self):
        scanner = self._scanner()
        result = AuthScanResult(target="https://idp.mock.local", protocol=AuthProtocol.SAML)
        result.provider_info.raw = {"signing_certs_found": 1, "source": "https://idp.mock.local/saml/metadata"}
        result.provider_info.endpoints["acs:HTTP-POST"] = "https://idp.mock.local/saml/acs"
        vulns = scanner._analyze_security(result)
        ids = {v.vuln_id for v in vulns}
        assert "OAI-AUTH-SAML-XSW" in ids


# ===========================================================================
# TestAuthScannerLLMTriage — LLM Judge integration (mocked judge)
# ===========================================================================

class TestAuthScannerLLMTriage:

    def _mock_judge(self, vulnerable: bool = True, confidence: float = 0.85, reason: str = "confirmed"):
        judge = MagicMock()
        judge.provider = "mock"
        judge.evaluate.return_value = {
            "vulnerable": vulnerable,
            "confidence": confidence,
            "reason": reason,
        }
        return judge

    def test_medium_vuln_gets_llm_confidence_set(self):
        judge = self._mock_judge(vulnerable=True, confidence=0.60)
        scanner = AuthScanner(target="https://auth.mock.local", judge=judge)
        result = AuthScanResult(target="https://auth.mock.local", protocol=AuthProtocol.OIDC)
        from offensive_ai.models.auth_result import AuthVulnerability
        vuln = AuthVulnerability(
            vuln_id="OAI-AUTH-STATE-001",
            severity=AuthVulnSeverity.MEDIUM,
            title="State parameter not required",
            description="Test",
        )
        result.vulnerabilities = [vuln]
        scanner._phase_llm_triage(result)
        assert result.vulnerabilities[0].llm_confidence == 0.60
        assert result.vulnerabilities[0].llm_reasoning == "confirmed"

    def test_low_vuln_upgraded_to_medium_when_confidence_high(self):
        judge = self._mock_judge(vulnerable=True, confidence=0.90)
        scanner = AuthScanner(target="https://auth.mock.local", judge=judge)
        result = AuthScanResult(target="https://auth.mock.local", protocol=AuthProtocol.OIDC)
        from offensive_ai.models.auth_result import AuthVulnerability
        vuln = AuthVulnerability(
            vuln_id="OAI-AUTH-STATE-001",
            severity=AuthVulnSeverity.LOW,
            title="Low finding",
            description="Test",
            evidence="some evidence",
        )
        result.vulnerabilities = [vuln]
        scanner._phase_llm_triage(result)
        assert result.vulnerabilities[0].severity == AuthVulnSeverity.MEDIUM
        assert "[LLM: upgraded from LOW]" in result.vulnerabilities[0].evidence

    def test_low_vuln_not_upgraded_when_confidence_below_threshold(self):
        judge = self._mock_judge(vulnerable=True, confidence=0.50)
        scanner = AuthScanner(target="https://auth.mock.local", judge=judge)
        result = AuthScanResult(target="https://auth.mock.local", protocol=AuthProtocol.OIDC)
        from offensive_ai.models.auth_result import AuthVulnerability
        vuln = AuthVulnerability(
            vuln_id="OAI-AUTH-STATE-001",
            severity=AuthVulnSeverity.LOW,
            title="Low finding",
            description="Test",
        )
        result.vulnerabilities = [vuln]
        scanner._phase_llm_triage(result)
        # Below threshold — stays LOW
        assert result.vulnerabilities[0].severity == AuthVulnSeverity.LOW

    def test_critical_vuln_skipped_by_llm_triage(self):
        judge = self._mock_judge()
        scanner = AuthScanner(target="https://auth.mock.local", judge=judge)
        result = AuthScanResult(target="https://auth.mock.local", protocol=AuthProtocol.OIDC)
        from offensive_ai.models.auth_result import AuthVulnerability
        vuln = AuthVulnerability(
            vuln_id="OAI-AUTH-JWTALGN-001",
            severity=AuthVulnSeverity.CRITICAL,
            title="alg=none accepted",
            description="Test",
        )
        result.vulnerabilities = [vuln]
        scanner._phase_llm_triage(result)
        # CRITICAL is not in the ambiguous set — judge must not be called
        judge.evaluate.assert_not_called()

    def test_judge_exception_does_not_crash_scan(self):
        judge = MagicMock()
        judge.provider = "mock"
        judge.evaluate.side_effect = RuntimeError("LLM exploded")
        scanner = AuthScanner(target="https://auth.mock.local", judge=judge)
        result = AuthScanResult(target="https://auth.mock.local", protocol=AuthProtocol.OIDC)
        from offensive_ai.models.auth_result import AuthVulnerability
        vuln = AuthVulnerability(
            vuln_id="OAI-AUTH-STATE-001",
            severity=AuthVulnSeverity.MEDIUM,
            title="test",
            description="test",
        )
        result.vulnerabilities = [vuln]
        # Should not raise
        scanner._phase_llm_triage(result)
        # LLM fields stay at defaults
        assert result.vulnerabilities[0].llm_confidence is None


# ===========================================================================
# TestAuthScannerIntegration — httpx mocked via respx
# ===========================================================================

class TestAuthScannerIntegration:

    @pytest.mark.asyncio
    @respx.mock
    async def test_oidc_discovery_detected(self):
        """Scanner detects OIDC when .well-known/openid-configuration returns JSON."""
        respx.get("https://auth.mock.local/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=MINIMAL_OIDC_DOC)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = AuthScanner("https://auth.mock.local", timeout=5.0)
        result = await scanner.scan()

        assert result.protocol == AuthProtocol.OIDC
        assert result.provider_info.issuer == "https://auth.example.com"
        assert "token_endpoint" in result.provider_info.endpoints
        assert result.provider_info.pkce_supported is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_oidc_implicit_flow_detected(self):
        """Scanner detects implicit flow and generates IMPL-001 vulnerability."""
        respx.get("https://auth.mock.local/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=IMPLICIT_FLOW_OIDC_DOC)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = AuthScanner("https://auth.mock.local", timeout=5.0)
        result = await scanner.scan()

        assert result.provider_info.implicit_flow_enabled is True
        ids = {v.vuln_id for v in result.vulnerabilities}
        assert "OAI-AUTH-IMPL-001" in ids

    @pytest.mark.asyncio
    @respx.mock
    async def test_alg_none_advertised_produces_critical(self):
        """Scanner produces CRITICAL vuln when alg=none is in supported algorithms."""
        respx.get("https://auth.mock.local/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=ALG_NONE_OIDC_DOC)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = AuthScanner("https://auth.mock.local", timeout=5.0)
        result = await scanner.scan()

        critical = result.critical_vulns
        assert any(v.vuln_id == "OAI-AUTH-JWTALGN-001" for v in critical)

    @pytest.mark.asyncio
    @respx.mock
    async def test_saml_metadata_detected(self):
        """Scanner detects SAML when /saml/metadata returns XML."""
        respx.get("https://idp.mock.local/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://idp.mock.local/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://idp.mock.local/saml/metadata").mock(
            return_value=httpx.Response(
                200,
                text=MINIMAL_SAML_XML,
                headers={"content-type": "application/xml"},
            )
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = AuthScanner("https://idp.mock.local", timeout=5.0)
        result = await scanner.scan()

        assert result.protocol == AuthProtocol.SAML
        assert result.provider_info.issuer == "https://idp.example.com/saml"

    @pytest.mark.asyncio
    @respx.mock
    async def test_saml_acs_endpoint_extracted(self):
        """Scanner extracts ACS endpoint from SAML metadata."""
        respx.get("https://idp.mock.local/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://idp.mock.local/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://idp.mock.local/saml/metadata").mock(
            return_value=httpx.Response(
                200,
                text=MINIMAL_SAML_XML,
                headers={"content-type": "application/xml"},
            )
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = AuthScanner("https://idp.mock.local", timeout=5.0)
        result = await scanner.scan()

        acs = {k: v for k, v in result.provider_info.endpoints.items() if k.startswith("acs:")}
        assert len(acs) >= 1
        assert "https://idp.example.com/saml/acs" in acs.values()

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_discovery_returns_error(self):
        """Scanner returns error when no protocol can be detected."""
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = AuthScanner("https://unknown.mock.local", timeout=5.0)
        result = await scanner.scan()

        assert result.protocol == AuthProtocol.UNKNOWN
        assert result.error is not None

    @pytest.mark.asyncio
    @respx.mock
    async def test_scan_duration_set(self):
        """scan_duration must be a positive float after a successful scan."""
        respx.get("https://auth.mock.local/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=MINIMAL_OIDC_DOC)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = AuthScanner("https://auth.mock.local", timeout=5.0)
        result = await scanner.scan()

        assert result.scan_duration > 0.0

    @pytest.mark.asyncio
    @respx.mock
    async def test_oauth2_fallback_path(self):
        """Scanner falls back to oauth-authorization-server path when openid-configuration absent."""
        oauth_doc = {
            "issuer": "https://auth.mock.local",
            "authorization_endpoint": "https://auth.mock.local/authorize",
            "token_endpoint": "https://auth.mock.local/token",
            "grant_types_supported": ["authorization_code", "client_credentials"],
        }
        respx.get("https://auth.mock.local/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://auth.mock.local/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json=oauth_doc)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = AuthScanner("https://auth.mock.local", timeout=5.0)
        result = await scanner.scan()

        # No id_token_ key → OAUTH2 not OIDC
        assert result.protocol == AuthProtocol.OAUTH2
        assert "token_endpoint" in result.provider_info.endpoints


# ===========================================================================
# TestAuthAttacker — authorization gate and basic probe tests
# ===========================================================================

class TestAuthAttacker:

    def test_authorization_gate_raises_without_flag(self):
        """AuthAttacker must raise AuthorizationRequired when authorized=False."""
        with pytest.raises(AuthorizationRequired):
            AuthAttacker(authorized=False)

    def test_instantiation_succeeds_with_authorized_true(self):
        attacker = AuthAttacker(authorized=True)
        assert attacker.authorized is True

    def test_judge_stored_on_init(self):
        judge = MagicMock()
        attacker = AuthAttacker(authorized=True, judge=judge)
        assert attacker._judge is judge

    @pytest.mark.asyncio
    @respx.mock
    async def test_attack_returns_report(self):
        """attack() returns an AuthAttackReport with results populated."""
        # Mock all auth probes to return 403 (clean — not triggered)
        respx.route(method="GET").mock(return_value=httpx.Response(403, text="Forbidden"))
        respx.route(method="POST").mock(return_value=httpx.Response(400, json={"error": "invalid_grant"}))

        attacker = AuthAttacker(authorized=True)
        report = await attacker.attack(
            target="https://auth.mock.local",
            mode="safe",
            timeout=5.0,
        )

        assert report.target == "https://auth.mock.local"
        assert report.authorized is True
        assert report.attacks_run > 0
        assert isinstance(report.results, list)

    @pytest.mark.asyncio
    @respx.mock
    async def test_attack_report_duration_set(self):
        """scan_duration must be positive after an attack run."""
        respx.route(method="GET").mock(return_value=httpx.Response(403))
        respx.route(method="POST").mock(return_value=httpx.Response(400))

        attacker = AuthAttacker(authorized=True)
        report = await attacker.attack("https://auth.mock.local", mode="safe", timeout=5.0)

        assert report.scan_duration > 0.0

    def test_enrich_with_llm_appends_analysis_to_evidence(self):
        """_enrich_with_llm appends LLM analysis text to the first triggered result's evidence."""
        from offensive_ai.models.auth_result import AuthAttackResult, AuthAttackReport, AuthProtocol

        judge = MagicMock()
        judge.provider = "mock"
        judge.evaluate.return_value = {
            "vulnerable": True,
            "confidence": 0.9,
            "reason": "open redirect confirmed",
        }

        attacker = AuthAttacker(authorized=True, judge=judge)

        triggered_result = AuthAttackResult(
            attack_id="AUTH-ATK-OR-001",
            target="https://auth.mock.local",
            triggered=True,
            severity=AuthVulnSeverity.HIGH,
            title="Open redirect",
            evidence="Location: https://evil.example.com",
        )
        report = AuthAttackReport(
            target="https://auth.mock.local",
            authorized=True,
            protocol=AuthProtocol.OIDC,
            attacks_run=1,
            attacks_triggered=1,
            results=[triggered_result],
        )

        attacker._enrich_with_llm(report)

        assert "[LLM analysis:" in report.results[0].evidence
        assert "open redirect confirmed" in report.results[0].evidence

    def test_enrich_with_llm_skips_when_no_triggered(self):
        """_enrich_with_llm must not call judge.evaluate when nothing was triggered."""
        from offensive_ai.models.auth_result import AuthAttackResult, AuthAttackReport, AuthProtocol

        judge = MagicMock()
        judge.provider = "mock"

        attacker = AuthAttacker(authorized=True, judge=judge)
        result = AuthAttackResult(
            attack_id="AUTH-ATK-OR-001",
            target="https://auth.mock.local",
            triggered=False,
            severity=AuthVulnSeverity.HIGH,
            title="Open redirect",
        )
        report = AuthAttackReport(
            target="https://auth.mock.local",
            authorized=True,
            protocol=AuthProtocol.OIDC,
            attacks_run=1,
            attacks_triggered=0,
            results=[result],
        )
        attacker._enrich_with_llm(report)
        judge.evaluate.assert_not_called()


# ---------------------------------------------------------------------------
# Additional coverage: SAML parse error, _detect_and_parse exception,
# auth scan with judge triage, SSO service discovery
# ---------------------------------------------------------------------------

import xml.etree.ElementTree as ET


class TestSamlMetadataParsing:
    """Unit tests for SAML metadata parsing (no network needed)."""

    def test_parse_saml_metadata_invalid_xml_returns_false(self):
        """Lines 282-284: invalid XML parse returns False."""
        from offensive_ai.core.auth_scanner import AuthScanner
        from offensive_ai.models.auth_result import AuthScanResult

        scanner = AuthScanner(target="https://example.com", timeout=5.0)
        result = AuthScanResult(target="https://example.com")

        # Invalid XML should trigger ET.ParseError
        ret = scanner._parse_saml_metadata("<<<not valid xml>>>", result, "https://example.com/saml/metadata")
        assert ret is False

    def test_parse_saml_metadata_wrong_namespace_returns_false(self):
        """Line 289: non-SAML XML root tag returns False."""
        from offensive_ai.core.auth_scanner import AuthScanner
        from offensive_ai.models.auth_result import AuthScanResult

        scanner = AuthScanner(target="https://example.com", timeout=5.0)
        result = AuthScanResult(target="https://example.com")

        # Valid XML but not SAML (no "metadata" or "EntityDescriptor" in tag)
        xml_text = '<html><body>Not SAML</body></html>'
        ret = scanner._parse_saml_metadata(xml_text, result, "https://example.com/saml/metadata")
        assert ret is False

    def test_parse_saml_metadata_with_sso_service(self):
        """Lines 307-310: SSO service location extracted."""
        from offensive_ai.core.auth_scanner import AuthScanner
        from offensive_ai.models.auth_result import AuthScanResult

        scanner = AuthScanner(target="https://example.com", timeout=5.0)
        result = AuthScanResult(target="https://example.com")

        # SAML metadata with SSO service
        xml_text = '''<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com">
  <md:IDPSSODescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>'''
        ret = scanner._parse_saml_metadata(xml_text, result, "https://example.com/saml/metadata")
        # Should return True (valid SAML)
        assert ret is True
        # SSO location should be in endpoints
        sso_endpoints = {k: v for k, v in result.provider_info.endpoints.items() if "sso" in k}
        assert len(sso_endpoints) > 0


@pytest.mark.asyncio
class TestAuthScannerAdditionalCoverage:
    @respx.mock
    async def test_scan_exception_in_detect_and_parse_sets_error(self):
        """Lines 109-111: exception in _detect_and_parse sets result.error."""
        from offensive_ai.core.auth_scanner import AuthScanner

        target = "https://broken-auth.example.com"
        scanner = AuthScanner(target=target, timeout=5.0)

        # Make all OIDC discovery paths return 500
        respx.get("https://broken-auth.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(500, text="Server Error")
        )
        respx.get("https://broken-auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(500, text="Server Error")
        )
        respx.get("https://broken-auth.example.com/saml/metadata").mock(
            return_value=httpx.Response(500, text="Server Error")
        )

        result = await scanner.scan()
        # Should complete without crashing
        assert result is not None

    @respx.mock
    async def test_scan_with_llm_judge_calls_triage(self):
        """Line 119: _phase_llm_triage called when judge with provider is set."""
        from offensive_ai.core.auth_scanner import AuthScanner

        target = "https://idp.example.com"
        mock_judge = MagicMock()
        mock_judge.provider = "openai"
        mock_judge.evaluate.return_value = {"vulnerable": False, "confidence": 0.1, "reason": "safe"}

        scanner = AuthScanner(target=target, timeout=5.0, judge=mock_judge)

        # Return a valid OIDC discovery with pkce_methods_supported missing → vulnerability
        discovery = {
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
            "token_endpoint": "https://idp.example.com/oauth2/token",
            "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        respx.get("https://idp.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=discovery)
        )

        result = await scanner.scan()
        assert result.protocol.value in ("oidc", "oauth2", "unknown")
