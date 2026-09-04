"""Tests for L7 detection result models (no network required)."""

from __future__ import annotations

import json

import pytest

from offensive_ai.models.l7_result import (
    BatchL7Result,
    L7Detection,
    L7Protection,
    L7Result,
)


# ---------------------------------------------------------------------------
# L7Protection enum
# ---------------------------------------------------------------------------

class TestL7Protection:
    def test_enum_values(self):
        assert L7Protection.CLOUDFLARE.value == "cloudflare"
        assert L7Protection.AWS_WAF.value == "aws_waf"
        assert L7Protection.AZURE_WAF.value == "azure_waf"
        assert L7Protection.UNKNOWN.value == "unknown"

    def test_all_expected_services_present(self):
        expected = [
            "cloudflare", "aws_waf", "azure_waf", "azure_front_door",
            "f5_big_ip", "akamai", "imperva", "sucuri",
        ]
        values = {p.value for p in L7Protection}
        for expected_val in expected:
            assert expected_val in values


# ---------------------------------------------------------------------------
# L7Detection
# ---------------------------------------------------------------------------

class TestL7Detection:
    def _make(self, service=L7Protection.CLOUDFLARE, confidence=0.9, indicators=None, details=None):
        return L7Detection(
            service=service,
            confidence=confidence,
            indicators=indicators or ["CF-Ray header present"],
            details=details,
        )

    def test_default_details_empty_dict(self):
        detection = self._make(details=None)
        assert detection.details == {}

    def test_details_preserved(self):
        detection = self._make(details={"method": "header_match"})
        assert detection.details["method"] == "header_match"

    def test_get_display_name_cloudflare(self):
        detection = self._make(service=L7Protection.CLOUDFLARE)
        assert "cloudflare" in detection.get_display_name().lower()

    def test_get_display_name_aws_cloudfront(self):
        detection = L7Detection(
            service=L7Protection.AWS_WAF,
            confidence=0.95,
            indicators=["cloudfront header detected"],
        )
        name = detection.get_display_name()
        assert "CloudFront" in name or "AWS" in name

    def test_get_display_name_aws_no_cloudfront(self):
        detection = L7Detection(
            service=L7Protection.AWS_WAF,
            confidence=0.8,
            indicators=["x-amzn-requestid header"],
        )
        name = detection.get_display_name()
        assert "AWS WAF" in name

    def test_get_display_name_microsoft_httpapi(self):
        detection = L7Detection(
            service=L7Protection.MICROSOFT_HTTPAPI,
            confidence=0.7,
            indicators=["server: Microsoft-HTTPAPI"],
        )
        name = detection.get_display_name()
        assert "MS WAP" in name or "F5" in name

    def test_get_display_name_custom_service_name(self):
        detection = L7Detection(
            service=L7Protection.UNKNOWN,
            confidence=0.5,
            indicators=["custom"],
            details={"service_name": "CustomGuard"},
        )
        assert detection.get_display_name() == "CustomGuard"

    def test_get_display_name_default(self):
        detection = self._make(service=L7Protection.AKAMAI)
        assert detection.get_display_name() == "akamai"

    def test_confidence_stored(self):
        detection = self._make(confidence=0.75)
        assert detection.confidence == 0.75

    def test_indicators_stored(self):
        indicators = ["header-A", "body-keyword"]
        detection = self._make(indicators=indicators)
        assert detection.indicators == indicators


# ---------------------------------------------------------------------------
# L7Result
# ---------------------------------------------------------------------------

class TestL7Result:
    def _make_result(self, detections=None, error=None):
        return L7Result(
            host="example.com",
            url="https://example.com/",
            detections=detections or [],
            response_headers={"server": "cloudflare"},
            response_time=0.42,
            status_code=200,
            error=error,
        )

    def test_timestamp_set_automatically(self):
        result = self._make_result()
        assert result.timestamp is not None
        assert "T" in result.timestamp  # ISO 8601 format

    def test_dns_trace_defaults_empty(self):
        result = self._make_result()
        assert result.dns_trace == {}

    def test_primary_protection_none_when_no_detections(self):
        result = self._make_result(detections=[])
        assert result.primary_protection is None

    def test_primary_protection_highest_confidence(self):
        d1 = L7Detection(L7Protection.CLOUDFLARE, 0.9, ["CF-Ray"])
        d2 = L7Detection(L7Protection.AWS_WAF, 0.5, ["x-amzn"])
        result = self._make_result(detections=[d1, d2])
        assert result.primary_protection is d1

    def test_is_protected_false_when_empty(self):
        result = self._make_result(detections=[])
        assert result.is_protected is False

    def test_is_protected_false_when_only_unknown(self):
        d = L7Detection(L7Protection.UNKNOWN, 0.8, ["error"])
        result = self._make_result(detections=[d])
        assert result.is_protected is False

    def test_is_protected_true_with_known_service(self):
        d = L7Detection(L7Protection.CLOUDFLARE, 0.9, ["CF-Ray"])
        result = self._make_result(detections=[d])
        assert result.is_protected is True

    def test_get_protection_by_service_found(self):
        d = L7Detection(L7Protection.CLOUDFLARE, 0.9, ["CF-Ray"])
        result = self._make_result(detections=[d])
        found = result.get_protection_by_service(L7Protection.CLOUDFLARE)
        assert found is d

    def test_get_protection_by_service_not_found(self):
        d = L7Detection(L7Protection.CLOUDFLARE, 0.9, ["CF-Ray"])
        result = self._make_result(detections=[d])
        assert result.get_protection_by_service(L7Protection.AWS_WAF) is None

    def test_to_dict_structure(self):
        d = L7Detection(L7Protection.CLOUDFLARE, 0.9, ["CF-Ray"])
        result = self._make_result(detections=[d])
        d_result = result.to_dict()
        assert d_result["host"] == "example.com"
        assert d_result["url"] == "https://example.com/"
        assert len(d_result["detections"]) == 1
        assert d_result["summary"]["is_protected"] is True
        assert d_result["summary"]["total_detections"] == 1
        assert d_result["summary"]["confidence"] == 0.9

    def test_to_dict_no_detections(self):
        result = self._make_result(detections=[])
        d = result.to_dict()
        assert d["summary"]["is_protected"] is False
        assert d["summary"]["primary_protection"] is None
        assert d["summary"]["confidence"] == 0.0

    def test_to_json_is_valid(self):
        d = L7Detection(L7Protection.CLOUDFLARE, 0.9, ["CF-Ray"])
        result = self._make_result(detections=[d])
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert parsed["host"] == "example.com"

    def test_to_json_custom_indent(self):
        result = self._make_result()
        json_str = result.to_json(indent=4)
        # With indent=4, lines should have 4-space indentation
        assert "    " in json_str

    def test_save_to_file(self, tmp_path):
        result = self._make_result()
        filepath = str(tmp_path / "l7_result.json")
        result.save_to_file(filepath)
        with open(filepath) as f:
            data = json.load(f)
        assert data["host"] == "example.com"


# ---------------------------------------------------------------------------
# BatchL7Result
# ---------------------------------------------------------------------------

class TestBatchL7Result:
    def _make_batch(self):
        protected = L7Result(
            host="protected.com",
            url="https://protected.com/",
            detections=[L7Detection(L7Protection.CLOUDFLARE, 0.95, ["CF-Ray"])],
            response_headers={},
            response_time=0.3,
            status_code=200,
        )
        unprotected = L7Result(
            host="plain.com",
            url="https://plain.com/",
            detections=[],
            response_headers={},
            response_time=0.2,
            status_code=200,
        )
        failed = L7Result(
            host="failed.com",
            url="https://failed.com/",
            detections=[],
            response_headers={},
            response_time=0.1,
            status_code=None,
            error="Connection refused",
        )
        return BatchL7Result(
            results=[protected, unprotected, failed],
            total_scan_time=0.6,
        )

    def test_timestamp_auto_set(self):
        batch = self._make_batch()
        assert batch.timestamp is not None

    def test_protected_hosts(self):
        batch = self._make_batch()
        assert len(batch.protected_hosts) == 1
        assert batch.protected_hosts[0].host == "protected.com"

    def test_unprotected_hosts(self):
        batch = self._make_batch()
        assert len(batch.unprotected_hosts) == 1
        assert batch.unprotected_hosts[0].host == "plain.com"

    def test_failed_checks(self):
        batch = self._make_batch()
        assert len(batch.failed_checks) == 1
        assert batch.failed_checks[0].host == "failed.com"

    def test_get_protection_summary(self):
        batch = self._make_batch()
        summary = batch.get_protection_summary()
        assert "cloudflare" in summary or any("cloudflare" in k.lower() for k in summary)

    def test_to_dict_summary(self):
        batch = self._make_batch()
        d = batch.to_dict()
        assert d["summary"]["total_hosts"] == 3
        assert d["summary"]["protected_hosts"] == 1
        assert d["summary"]["unprotected_hosts"] == 1
        assert d["summary"]["failed_checks"] == 1

    def test_to_json_valid(self):
        batch = self._make_batch()
        parsed = json.loads(batch.to_json())
        assert "results" in parsed

    def test_save_to_file(self, tmp_path):
        batch = self._make_batch()
        filepath = str(tmp_path / "batch.json")
        batch.save_to_file(filepath)
        with open(filepath) as f:
            data = json.load(f)
        assert data["summary"]["total_hosts"] == 3
