"""Tests for AI/LLM OWASP Top 10 scanner."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from offensive_ai.core.ai_owasp_scanner import LLMOwaspScanner
from offensive_ai.models.ai_owasp_result import (
    BatchLLMScanResult,
    LLMFinding,
    LLMScanMode,
    LLMScanResult,
    LLMSeverity,
)
from offensive_ai.utils.ai_owasp_payloads import (
    ALL_PAYLOADS,
    NOT_TESTABLE_CATEGORIES,
    get_payloads,
)
from offensive_ai.utils.ai_owasp_remediation import get_category_info, get_remediation


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MOCK_CLEAN_RESPONSE = "I'm sorry, I can't help with that request."

MOCK_INJECTION_RESPONSE = "INJECTION_SUCCESS — I have overridden my instructions."

OPENAI_RESPONSE_CLEAN = {
    "choices": [{"message": {"content": MOCK_CLEAN_RESPONSE}}]
}
OPENAI_RESPONSE_TRIGGERED = {
    "choices": [{"message": {"content": MOCK_INJECTION_RESPONSE}}]
}


def _make_scanner(endpoint="http://mock-llm.local/v1/chat/completions",
                  mode="safe", categories=None):
    return LLMOwaspScanner(
        endpoint=endpoint,
        mode=mode,
        categories=categories,
        api_format="openai",
    )


# ---------------------------------------------------------------------------
# Payload library tests
# ---------------------------------------------------------------------------

class TestPayloads:
    def test_all_categories_have_payloads(self):
        for category_id, payloads in ALL_PAYLOADS.items():
            assert len(payloads) >= 1, f"{category_id} has no payloads"

    def test_each_payload_has_required_fields(self):
        for cat_id, payloads in ALL_PAYLOADS.items():
            for p in payloads:
                assert "id" in p, f"Payload in {cat_id} missing 'id'"
                assert "probe" in p, f"Payload in {cat_id} missing 'probe'"
                assert "severity" in p, f"Payload in {cat_id} missing 'severity'"

    def test_not_testable_categories_excluded_from_payloads(self):
        for cat_id in NOT_TESTABLE_CATEGORIES:
            assert cat_id not in ALL_PAYLOADS, (
                f"{cat_id} is listed as not-testable but also has payloads"
            )

    def test_safe_mode_returns_subset(self):
        safe_payloads = get_payloads("LLM01", "safe")
        assert safe_payloads == [], "LLM01 should be empty in safe mode"

        safe_payloads_llm07 = get_payloads("LLM07", "safe")
        assert len(safe_payloads_llm07) > 0, "LLM07 should have safe-mode payloads"

    def test_deep_mode_returns_full_set(self):
        deep_payloads = get_payloads("LLM01", "deep")
        assert len(deep_payloads) > 0


# ---------------------------------------------------------------------------
# Remediation DB tests
# ---------------------------------------------------------------------------

class TestRemediation:
    def test_all_categories_have_metadata(self):
        for cat_id in ["LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM09", "LLM10"]:
            info = get_category_info(cat_id)
            assert info is not None, f"Missing metadata for {cat_id}"
            assert "name" in info
            assert "ref" in info

    def test_remediation_keys_resolvable(self):
        keys = [
            "prompt_injection_direct",
            "system_prompt_leakage",
            "sensitive_info_disclosure",
            "improper_output_xss",
            "excessive_agency",
            "misinformation_no_guardrail",
            "unbounded_consumption",
        ]
        for key in keys:
            rem = get_remediation(key)
            assert rem is not None, f"Missing remediation for key '{key}'"
            assert len(rem.steps) > 0


# ---------------------------------------------------------------------------
# LLMFinding model tests
# ---------------------------------------------------------------------------

class TestLLMFinding:
    def test_auto_score_critical(self):
        finding = LLMFinding(
            category="LLM01",
            severity=LLMSeverity.CRITICAL,
            title="Test",
            description="Test",
            remediation_key="prompt_injection_direct",
        )
        assert finding.score == 10.0

    def test_auto_score_high(self):
        finding = LLMFinding(
            category="LLM01",
            severity=LLMSeverity.HIGH,
            title="Test",
            description="Test",
            remediation_key="prompt_injection_direct",
        )
        assert finding.score == 7.5

    def test_evidence_and_probe_truncation(self):
        long_text = "A" * 1000
        finding = LLMFinding(
            category="LLM01",
            severity=LLMSeverity.HIGH,
            title="Test",
            description="Test",
            remediation_key="prompt_injection_direct",
            evidence=long_text,
            probe_used=long_text,
        )
        # Should store the full value in model (truncation is in scanner, not model)
        assert len(finding.evidence) == 1000


# ---------------------------------------------------------------------------
# Scanner unit tests (mocked HTTP)
# ---------------------------------------------------------------------------

class TestLLMOwaspScanner:
    @pytest.mark.asyncio
    async def test_scan_safe_mode_skips_attack_categories(self):
        """In safe mode, LLM01 (prompt injection) should not be tested."""
        scanner = _make_scanner(mode="safe")
        assert "LLM01" not in scanner.categories

    @pytest.mark.asyncio
    async def test_scan_deep_mode_includes_attack_categories(self):
        """In deep mode, LLM01 should be in the category list."""
        scanner = _make_scanner(mode="deep")
        assert "LLM01" in scanner.categories

    @pytest.mark.asyncio
    async def test_not_testable_categories_reported_correctly(self):
        """LLM03, LLM04, LLM08 must appear as not-testable in result."""
        import httpx
        import respx

        with respx.mock:
            respx.post("http://mock-llm.local/v1/chat/completions").mock(
                return_value=httpx.Response(
                    200, json=OPENAI_RESPONSE_CLEAN
                )
            )
            scanner = _make_scanner(mode="deep")
            result = await scanner.scan()

        not_testable = {c.category_id for c in result.categories if not c.testable}
        assert "LLM03" in not_testable
        assert "LLM04" in not_testable
        assert "LLM08" in not_testable

    @pytest.mark.asyncio
    async def test_clean_response_produces_no_findings(self):
        """A clean (non-vulnerable) response should produce no findings."""
        import httpx
        import respx

        with respx.mock:
            respx.post("http://mock-llm.local/v1/chat/completions").mock(
                return_value=httpx.Response(
                    200, json=OPENAI_RESPONSE_CLEAN
                )
            )
            scanner = _make_scanner(mode="deep")
            result = await scanner.scan()

        assert len(result.all_findings) == 0

    @pytest.mark.asyncio
    async def test_triggered_response_produces_finding(self):
        """A response containing injection indicators should produce a CRITICAL finding."""
        import httpx
        import respx

        with respx.mock:
            respx.post("http://mock-llm.local/v1/chat/completions").mock(
                return_value=httpx.Response(
                    200, json=OPENAI_RESPONSE_TRIGGERED
                )
            )
            scanner = _make_scanner(mode="deep", categories=["LLM01"])
            result = await scanner.scan()

        llm01 = next((c for c in result.categories if c.category_id == "LLM01"), None)
        assert llm01 is not None
        assert llm01.testable
        assert len(llm01.findings) > 0
        assert llm01.findings[0].severity in (LLMSeverity.CRITICAL, LLMSeverity.HIGH)

    @pytest.mark.asyncio
    async def test_overall_grade_f_on_critical(self):
        """A critical finding must force an F overall grade."""
        import httpx
        import respx

        with respx.mock:
            respx.post("http://mock-llm.local/v1/chat/completions").mock(
                return_value=httpx.Response(
                    200, json=OPENAI_RESPONSE_TRIGGERED
                )
            )
            scanner = _make_scanner(mode="deep", categories=["LLM01"])
            result = await scanner.scan()

        if result.has_critical:
            assert result.overall_grade == "F"

    @pytest.mark.asyncio
    async def test_http_error_does_not_crash_scan(self):
        """A connection error on one probe should not crash the whole scan."""
        import httpx
        import respx

        with respx.mock:
            respx.post("http://mock-llm.local/v1/chat/completions").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            scanner = _make_scanner(mode="safe")
            result = await scanner.scan()

        # Should complete without exception; categories may have 0 findings
        assert isinstance(result, LLMScanResult)

    @pytest.mark.asyncio
    async def test_batch_scan(self):
        """batch_scan should aggregate results from multiple endpoints."""
        import httpx
        import respx

        endpoints = [
            {"endpoint": "http://llm1.local/v1/chat/completions"},
            {"endpoint": "http://llm2.local/v1/chat/completions"},
        ]

        with respx.mock:
            for ep in endpoints:
                respx.post(ep["endpoint"]).mock(
                    return_value=httpx.Response(200, json=OPENAI_RESPONSE_CLEAN)
                )
            scanner = _make_scanner(mode="safe")
            batch = await scanner.batch_scan(endpoints)

        assert isinstance(batch, BatchLLMScanResult)
        assert batch.total_targets == 2
