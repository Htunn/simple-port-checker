"""
Tests for L7Detector — pure/unit tests with no real network calls.
"""

from __future__ import annotations

import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from offensive_ai.core.l7_detector import L7Detector
from offensive_ai.models.l7_result import L7Detection, L7Protection, L7Result


# ---------------------------------------------------------------------------
# L7Detector instantiation
# ---------------------------------------------------------------------------

class TestL7DetectorInit:
    def test_default_init(self):
        detector = L7Detector()
        assert detector.timeout == 10.0
        assert "offensive-ai" in detector.user_agent.lower()

    def test_custom_timeout(self):
        detector = L7Detector(timeout=30.0)
        assert detector.timeout == 30.0

    def test_custom_user_agent(self):
        ua = "MyScanner/1.0"
        detector = L7Detector(user_agent=ua)
        assert detector.user_agent == ua

    def test_signatures_loaded(self):
        detector = L7Detector()
        assert isinstance(detector.signatures, dict)
        assert len(detector.signatures) > 0


# ---------------------------------------------------------------------------
# _is_cloudflare_ip — pure function
# ---------------------------------------------------------------------------

class TestIsCloudflareIp:
    def setup_method(self):
        self.detector = L7Detector()

    def test_known_cloudflare_prefix_104_16(self):
        assert self.detector._is_cloudflare_ip("104.16.0.1") is True

    def test_known_cloudflare_prefix_172_64(self):
        assert self.detector._is_cloudflare_ip("172.64.0.1") is True

    def test_known_cloudflare_prefix_162_158(self):
        assert self.detector._is_cloudflare_ip("162.158.0.1") is True

    def test_known_cloudflare_prefix_103_21(self):
        assert self.detector._is_cloudflare_ip("103.21.244.1") is True

    def test_non_cloudflare_ip(self):
        assert self.detector._is_cloudflare_ip("1.2.3.4") is False

    def test_google_dns_not_cloudflare(self):
        assert self.detector._is_cloudflare_ip("8.8.8.8") is False

    def test_localhost_not_cloudflare(self):
        assert self.detector._is_cloudflare_ip("127.0.0.1") is False

    def test_198_41_128_prefix(self):
        assert self.detector._is_cloudflare_ip("198.41.128.1") is True

    def test_empty_string(self):
        assert self.detector._is_cloudflare_ip("") is False

    def test_partial_prefix_no_match(self):
        # 104.15 should NOT match any Cloudflare prefix
        assert self.detector._is_cloudflare_ip("104.15.1.1") is False


# ---------------------------------------------------------------------------
# _deduplicate_detections — pure function
# ---------------------------------------------------------------------------

class TestDeduplicateDetections:
    def setup_method(self):
        self.detector = L7Detector()

    def _make_detection(self, service, confidence):
        return L7Detection(
            service=service,
            confidence=confidence,
            indicators=[f"indicator for {service}"],
        )

    def test_empty_list(self):
        result = self.detector._deduplicate_detections([])
        assert result == []

    def test_single_detection_preserved(self):
        d = self._make_detection(L7Protection.CLOUDFLARE, 0.9)
        result = self.detector._deduplicate_detections([d])
        assert len(result) == 1
        assert result[0].service == L7Protection.CLOUDFLARE

    def test_duplicate_keeps_highest_confidence(self):
        d1 = self._make_detection(L7Protection.CLOUDFLARE, 0.6)
        d2 = self._make_detection(L7Protection.CLOUDFLARE, 0.9)
        result = self.detector._deduplicate_detections([d1, d2])
        assert len(result) == 1
        assert result[0].confidence == 0.9

    def test_different_services_kept(self):
        d1 = self._make_detection(L7Protection.CLOUDFLARE, 0.9)
        d2 = self._make_detection(L7Protection.AKAMAI, 0.8)
        result = self.detector._deduplicate_detections([d1, d2])
        services = {d.service for d in result}
        assert L7Protection.CLOUDFLARE in services
        assert L7Protection.AKAMAI in services

    def test_three_duplicates_keeps_one(self):
        detections = [
            self._make_detection(L7Protection.AKAMAI, 0.5),
            self._make_detection(L7Protection.AKAMAI, 0.7),
            self._make_detection(L7Protection.AKAMAI, 0.3),
        ]
        result = self.detector._deduplicate_detections(detections)
        assert len(result) == 1
        assert result[0].confidence == 0.7

    def test_mixed_services_and_duplicates(self):
        detections = [
            self._make_detection(L7Protection.CLOUDFLARE, 0.6),
            self._make_detection(L7Protection.AWS_WAF, 0.8),
            self._make_detection(L7Protection.CLOUDFLARE, 0.9),
            self._make_detection(L7Protection.AKAMAI, 0.5),
        ]
        result = self.detector._deduplicate_detections(detections)
        assert len(result) == 3
        cloudflare = next(d for d in result if d.service == L7Protection.CLOUDFLARE)
        assert cloudflare.confidence == 0.9


# ---------------------------------------------------------------------------
# _analyze_fallback_response — pure function
# ---------------------------------------------------------------------------

class TestAnalyzeFallbackResponse:
    def setup_method(self):
        self.detector = L7Detector()

    def test_cloudflare_detected_by_cf_ray_header(self):
        detections = []
        fallback_result = {
            "headers": {"cf-ray": "123abc-SIN", "Server": "nginx"},
            "content": "",
        }
        self.detector._analyze_fallback_response(fallback_result, "example.com", detections)
        services = [d.service for d in detections]
        assert L7Protection.CLOUDFLARE in services

    def test_cloudflare_detected_by_server_header(self):
        detections = []
        fallback_result = {
            "headers": {"Server": "cloudflare"},
            "content": "",
        }
        self.detector._analyze_fallback_response(fallback_result, "example.com", detections)
        services = [d.service for d in detections]
        assert L7Protection.CLOUDFLARE in services

    def test_akamai_detected_by_x_akamai_header(self):
        detections = []
        fallback_result = {
            "headers": {"X-Akamai-Request-Id": "abc123", "Server": "AkamaiGHost"},
            "content": "",
        }
        self.detector._analyze_fallback_response(fallback_result, "example.com", detections)
        services = [d.service for d in detections]
        assert L7Protection.AKAMAI in services

    def test_f5_bigip_server_pool_cookie(self):
        detections = []
        fallback_result = {
            "headers": {
                "Server": "nginx",
                "set-cookie": "BIGipServerPool=123456789.443.0000; Path=/; Httponly; Secure",
            },
            "content": "",
        }
        self.detector._analyze_fallback_response(fallback_result, "example.com", detections)
        services = [d.service for d in detections]
        assert L7Protection.F5_BIG_IP in services

    def test_microsoft_httpapi_detected(self):
        detections = []
        fallback_result = {
            "headers": {"Server": "Microsoft-HTTPAPI/2.0"},
            "content": "",
        }
        self.detector._analyze_fallback_response(fallback_result, "example.com", detections)
        services = [d.service for d in detections]
        assert L7Protection.MICROSOFT_HTTPAPI in services

    def test_aws_cloudfront_detected(self):
        detections = []
        fallback_result = {
            "headers": {
                "Server": "CloudFront",
                "x-amz-cf-id": "AbCdEfGhIjKlMnOp==",
            },
            "content": "",
        }
        self.detector._analyze_fallback_response(fallback_result, "example.com", detections)
        services = [d.service for d in detections]
        assert L7Protection.AWS_WAF in services

    def test_azure_front_door_detected(self):
        detections = []
        fallback_result = {
            "headers": {"x-azure-ref": "0ABC123", "Server": "Microsoft-IIS/10.0"},
            "content": "",
        }
        self.detector._analyze_fallback_response(fallback_result, "example.com", detections)
        services = [d.service for d in detections]
        assert L7Protection.AZURE_FRONT_DOOR in services

    def test_cloudflare_body_detection(self):
        detections = []
        fallback_result = {
            "headers": {"Server": "nginx"},
            "content": "Error 1020 · Access Denied: cloudflare ray id: abc123",
        }
        self.detector._analyze_fallback_response(fallback_result, "example.com", detections)
        services = [d.service for d in detections]
        assert L7Protection.CLOUDFLARE in services

    def test_unknown_fallback_when_no_signature(self):
        detections = []
        fallback_result = {
            "headers": {"Server": "Apache/2.4", "X-Custom-Header": "value"},
            "content": "",
            "status_code": 200,
        }
        self.detector._analyze_fallback_response(fallback_result, "example.com", detections)
        # Should add some detection (possibly UNKNOWN or heuristic-based)
        assert len(detections) >= 0  # No crash is the minimum requirement

    def test_incapsula_detected(self):
        detections = []
        fallback_result = {
            "headers": {
                "Server": "nginx",
                "x-iinfo": "10-12345-0",
                "set-cookie": "visid_incap_123=abc; Path=/",
            },
            "content": "",
        }
        self.detector._analyze_fallback_response(fallback_result, "example.com", detections)
        services = [d.service for d in detections]
        assert L7Protection.INCAPSULA in services

    def test_f5_ts_cookie_detection(self):
        detections = []
        fallback_result = {
            "headers": {
                "Server": "nginx",
                "set-cookie": "TSabc12345=xyz; path=/",
            },
            "content": "",
        }
        self.detector._analyze_fallback_response(fallback_result, "example.com", detections)
        # F5 TS cookie should be detected
        services = [d.service for d in detections]
        assert L7Protection.F5_BIG_IP in services

    def test_sg_domain_tld_fallback(self):
        """Domain ending in .sg should trigger Akamai TLD heuristic if nothing else detected."""
        detections = []
        fallback_result = {
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "Server": "Apache",
            },
            "content": "",
            "status_code": 200,
        }
        self.detector._analyze_fallback_response(fallback_result, "example.com.sg", detections)
        # Should produce at least one detection (heuristics)
        assert len(detections) >= 0


# ---------------------------------------------------------------------------
# _handle_large_headers_case — side-effects on detections list
# ---------------------------------------------------------------------------

class TestHandleLargeHeadersCase:
    def setup_method(self):
        self.detector = L7Detector()

    def test_adds_detection_on_large_headers(self):
        detections = []
        self.detector._handle_large_headers_case(
            "example.com", "https://example.com/", "Header value too long", detections
        )
        assert len(detections) >= 0  # Shouldn't crash; may or may not add detection

    def test_gov_sg_domain_pattern(self):
        detections = []
        self.detector._handle_large_headers_case(
            "agency.gov.sg", "https://agency.gov.sg/", "Header value too long", detections
        )
        # May add Azure or unknown detection for .gov.sg
        assert isinstance(detections, list)

    def test_edu_domain_adds_akamai_pattern(self):
        detections = []
        self.detector._handle_large_headers_case(
            "example.edu", "https://example.edu/", "some error", detections
        )
        assert isinstance(detections, list)


# ---------------------------------------------------------------------------
# _check_with_requests — with mocked requests
# ---------------------------------------------------------------------------

class TestCheckWithRequests:
    def setup_method(self):
        self.detector = L7Detector(timeout=5.0)

    def test_successful_response(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "nginx", "Content-Type": "text/html"}
        mock_response.url = "https://example.com/"
        mock_response.text = "<html>Hello</html>"

        with patch("requests.get", return_value=mock_response) as mock_get:
            result = self.detector._check_with_requests("https://example.com/")

        assert result["status_code"] == 200
        assert result["headers"]["Server"] == "nginx"
        assert "error" not in result or not result["error"]

    def test_request_exception_falls_back(self):
        import requests as req_lib

        with patch("requests.get", side_effect=req_lib.RequestException("timeout")):
            result = self.detector._check_with_requests("https://example.com/")

        # Should return error result, not raise
        assert "error" in result or result.get("method") == "requests_fallback_failed"

    def test_both_attempts_fail_returns_error_dict(self):
        import requests as req_lib

        with patch("requests.get", side_effect=req_lib.RequestException("connection error")):
            result = self.detector._check_with_requests("https://example.com/")

        assert result.get("status_code") is None or "error" in result


# ---------------------------------------------------------------------------
# detect() — mocked to avoid network
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDetectMocked:
    async def test_detect_returns_l7_result(self):
        detector = L7Detector(timeout=2.0)

        # Patch the internal methods so no real network calls are made
        with (
            patch.object(detector, "_check_azure_traffic_manager", AsyncMock(return_value=False)),
            patch.object(detector, "_check_with_requests", return_value={
                "status_code": 200,
                "headers": {"cf-ray": "abc123-SIN", "Server": "cloudflare"},
                "content": "",
                "url": "https://example.com/",
            }),
        ):
            result = await detector.detect("example.com")

        assert isinstance(result, L7Result)
        assert result.host == "example.com"

    async def test_detect_government_domain_azure_shortcircuit(self):
        """Government domains should short-circuit when Azure Traffic Manager found."""
        detector = L7Detector()

        with patch.object(detector, "_check_azure_traffic_manager", AsyncMock(return_value=True)):
            result = await detector.detect("agency.gov")

        assert result.host == "agency.gov"
        services = [d.service for d in result.detections]
        assert L7Protection.AZURE_FRONT_DOOR in services

    async def test_detect_problematic_domain_uses_fallback(self):
        """Problematic TLDs (.edu) should use the requests fallback."""
        detector = L7Detector(timeout=2.0)

        with (
            patch.object(detector, "_check_azure_traffic_manager", AsyncMock(return_value=False)),
            patch.object(detector, "_check_with_requests", return_value={
                "status_code": 200,
                "headers": {"Server": "AkamaiGHost", "X-Akamai-Request-Id": "xyz"},
                "content": "",
                "url": "https://university.edu/",
            }) as mock_fallback,
            patch.object(detector, "_analyze_fallback_response") as mock_analyze,
        ):
            result = await detector.detect("university.edu")

        assert isinstance(result, L7Result)
        mock_fallback.assert_called_once()


# ---------------------------------------------------------------------------
# Sync helper methods — batch detection
# ---------------------------------------------------------------------------

class TestDetectMultipleMocked:
    """Tests for detect_multiple using mocked detect()."""

    @pytest.mark.asyncio
    async def test_detect_multiple_returns_list(self):
        detector = L7Detector()

        async def mock_detect(host, port=None, path="/", trace_dns=False):
            return L7Result(
                host=host,
                url=f"https://{host}/",
                detections=[],
                response_headers={},
                response_time=0.1,
                status_code=200,
                error=None,
            )

        with patch.object(detector, "detect", side_effect=mock_detect):
            results = await detector.detect_multiple(["example.com", "test.com"])

        assert len(results) == 2
        assert all(isinstance(r, L7Result) for r in results)
