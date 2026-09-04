"""
Tests for HybridIdentityChecker and HybridIdentityResult (no network calls).
"""

from __future__ import annotations

import pytest

from offensive_ai.core.hybrid_identity_checker import HybridIdentityChecker, HybridIdentityResult


# ---------------------------------------------------------------------------
# HybridIdentityResult model tests
# ---------------------------------------------------------------------------

class TestHybridIdentityResult:
    def _make(self, **kwargs):
        defaults = dict(
            fqdn="corp.example.com",
            has_hybrid_identity=False,
            has_adfs=False,
            adfs_endpoint=None,
            adfs_status_code=None,
            federation_metadata_found=False,
            azure_ad_detected=False,
            openid_config_found=False,
            dns_records={},
            error=None,
            response_time=0.5,
        )
        defaults.update(kwargs)
        return HybridIdentityResult(**defaults)

    def test_basic_creation(self):
        result = self._make()
        assert result.fqdn == "corp.example.com"
        assert result.has_hybrid_identity is False

    def test_hybrid_detected_when_adfs_found(self):
        result = self._make(has_adfs=True, has_hybrid_identity=True)
        assert result.has_adfs is True
        assert result.has_hybrid_identity is True

    def test_adfs_endpoint_stored(self):
        result = self._make(
            has_adfs=True,
            has_hybrid_identity=True,
            adfs_endpoint="https://adfs.corp.example.com/adfs/ls",
            adfs_status_code=200,
        )
        assert result.adfs_endpoint == "https://adfs.corp.example.com/adfs/ls"
        assert result.adfs_status_code == 200

    def test_federation_metadata_flag(self):
        result = self._make(federation_metadata_found=True, has_hybrid_identity=True)
        assert result.federation_metadata_found is True

    def test_azure_ad_flag(self):
        result = self._make(azure_ad_detected=True, has_hybrid_identity=True)
        assert result.azure_ad_detected is True

    def test_openid_config_flag(self):
        result = self._make(openid_config_found=True, has_hybrid_identity=True)
        assert result.openid_config_found is True

    def test_error_stored(self):
        result = self._make(error="Connection refused")
        assert result.error == "Connection refused"

    def test_response_time_stored(self):
        result = self._make(response_time=1.234)
        assert result.response_time == 1.234

    def test_dns_records_stored(self):
        dns = {"A": ["10.0.0.1"], "MX": ["mail.example.com"]}
        result = self._make(dns_records=dns)
        assert result.dns_records == dns

    def test_dns_records_defaults_empty(self):
        result = self._make()
        assert result.dns_records == {}

    def test_to_dict_contains_all_keys(self):
        result = self._make()
        d = result.to_dict()
        expected_keys = [
            "fqdn", "has_hybrid_identity", "has_adfs", "adfs_endpoint",
            "adfs_status_code", "federation_metadata_found", "azure_ad_detected",
            "openid_config_found", "dns_records", "error", "response_time",
        ]
        for key in expected_keys:
            assert key in d, f"Missing key: {key}"

    def test_to_dict_values(self):
        result = self._make(
            fqdn="test.corp.com",
            has_adfs=True,
            has_hybrid_identity=True,
            adfs_endpoint="https://adfs.test.corp.com",
        )
        d = result.to_dict()
        assert d["fqdn"] == "test.corp.com"
        assert d["has_adfs"] is True
        assert d["has_hybrid_identity"] is True
        assert d["adfs_endpoint"] == "https://adfs.test.corp.com"


# ---------------------------------------------------------------------------
# HybridIdentityChecker constructor
# ---------------------------------------------------------------------------

class TestHybridIdentityCheckerInit:
    def test_default_timeout(self):
        checker = HybridIdentityChecker()
        assert checker.timeout == 10.0

    def test_custom_timeout(self):
        checker = HybridIdentityChecker(timeout=30.0)
        assert checker.timeout == 30.0

    def test_user_agent_set(self):
        checker = HybridIdentityChecker()
        assert "offensive-ai" in checker.user_agent


# ---------------------------------------------------------------------------
# HybridIdentityChecker.check (mocked network)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHybridIdentityCheckerCheck:
    async def test_check_strips_https_scheme(self):
        """check() should strip https:// from FQDN."""
        checker = HybridIdentityChecker(timeout=5.0)
        captured_fqdns = []

        # We'll patch the internal DNS check to capture what fqdn was passed
        async def mock_dns(fqdn):
            captured_fqdns.append(fqdn)
            return {}

        async def mock_adfs_azure(fqdn):
            return {"found": False, "endpoint": None, "status_code": None}

        async def mock_adfs_direct(fqdn):
            return {"found": False, "endpoint": None, "status_code": None}

        async def mock_federation(fqdn):
            return False

        async def mock_azure_ad(fqdn):
            return False

        async def mock_openid(fqdn):
            return False

        from unittest.mock import patch

        with patch.object(checker, "_check_dns_records", side_effect=mock_dns), \
             patch.object(checker, "_check_adfs_via_azure_login", side_effect=mock_adfs_azure), \
             patch.object(checker, "_check_adfs_endpoint", side_effect=mock_adfs_direct), \
             patch.object(checker, "_check_federation_metadata", side_effect=mock_federation), \
             patch.object(checker, "_check_azure_ad_integration", side_effect=mock_azure_ad), \
             patch.object(checker, "_check_openid_config", side_effect=mock_openid):
            result = await checker.check("https://corp.example.com")

        # The fqdn passed internally should not have https://
        assert "https://" not in captured_fqdns[0]

    async def test_check_strips_http_scheme(self):
        checker = HybridIdentityChecker(timeout=5.0)
        captured_fqdns = []

        async def mock_dns(fqdn):
            captured_fqdns.append(fqdn)
            return {}

        async def mock_adfs_azure(fqdn):
            return {"found": False, "endpoint": None, "status_code": None}

        async def mock_adfs_direct(fqdn):
            return {"found": False, "endpoint": None, "status_code": None}

        async def mock_false(fqdn):
            return False

        from unittest.mock import patch

        with patch.object(checker, "_check_dns_records", side_effect=mock_dns), \
             patch.object(checker, "_check_adfs_via_azure_login", side_effect=mock_adfs_azure), \
             patch.object(checker, "_check_adfs_endpoint", side_effect=mock_adfs_direct), \
             patch.object(checker, "_check_federation_metadata", side_effect=mock_false), \
             patch.object(checker, "_check_azure_ad_integration", side_effect=mock_false), \
             patch.object(checker, "_check_openid_config", side_effect=mock_false):
            result = await checker.check("http://corp.example.com/path/extra")

        assert "http://" not in captured_fqdns[0]
        assert "/" not in captured_fqdns[0]

    async def test_check_no_hybrid_identity(self):
        """All checks return False → has_hybrid_identity=False."""
        checker = HybridIdentityChecker(timeout=5.0)

        async def mock_dns(fqdn):
            return {"A": ["10.0.0.1"]}

        async def mock_adfs_azure(fqdn):
            return {"found": False, "endpoint": None, "status_code": None}

        async def mock_adfs_direct(fqdn):
            return {"found": False, "endpoint": None, "status_code": None}

        async def mock_false(fqdn):
            return False

        from unittest.mock import patch

        with patch.object(checker, "_check_dns_records", side_effect=mock_dns), \
             patch.object(checker, "_check_adfs_via_azure_login", side_effect=mock_adfs_azure), \
             patch.object(checker, "_check_adfs_endpoint", side_effect=mock_adfs_direct), \
             patch.object(checker, "_check_federation_metadata", side_effect=mock_false), \
             patch.object(checker, "_check_azure_ad_integration", side_effect=mock_false), \
             patch.object(checker, "_check_openid_config", side_effect=mock_false):
            result = await checker.check("corp.example.com")

        assert isinstance(result, HybridIdentityResult)
        assert result.has_hybrid_identity is False
        assert result.has_adfs is False
        assert result.fqdn == "corp.example.com"

    async def test_check_adfs_found_via_azure_flow(self):
        """ADFS found via Azure login flow sets has_hybrid_identity=True."""
        checker = HybridIdentityChecker(timeout=5.0)

        async def mock_dns(fqdn):
            return {}

        async def mock_adfs_azure(fqdn):
            return {
                "found": True,
                "endpoint": f"https://adfs.{fqdn}/adfs/ls",
                "status_code": 200,
            }

        async def mock_adfs_direct(fqdn):
            return {"found": False, "endpoint": None, "status_code": None}

        async def mock_false(fqdn):
            return False

        from unittest.mock import patch

        with patch.object(checker, "_check_dns_records", side_effect=mock_dns), \
             patch.object(checker, "_check_adfs_via_azure_login", side_effect=mock_adfs_azure), \
             patch.object(checker, "_check_adfs_endpoint", side_effect=mock_adfs_direct), \
             patch.object(checker, "_check_federation_metadata", side_effect=mock_false), \
             patch.object(checker, "_check_azure_ad_integration", side_effect=mock_false), \
             patch.object(checker, "_check_openid_config", side_effect=mock_false):
            result = await checker.check("corp.example.com")

        assert result.has_adfs is True
        assert result.has_hybrid_identity is True
        assert result.adfs_status_code == 200

    async def test_check_openid_config_exception_captured(self):
        """Exception during openid check is captured in result.error."""
        checker = HybridIdentityChecker(timeout=5.0)

        async def mock_dns(fqdn):
            return {}

        async def mock_adfs_no(fqdn):
            return {"found": False, "endpoint": None, "status_code": None}

        async def mock_false(fqdn):
            return False

        async def mock_openid_raises(fqdn):
            raise RuntimeError("OpenID check failed")

        from unittest.mock import patch

        with patch.object(checker, "_check_dns_records", side_effect=mock_dns), \
             patch.object(checker, "_check_adfs_via_azure_login", side_effect=mock_adfs_no), \
             patch.object(checker, "_check_adfs_endpoint", side_effect=mock_adfs_no), \
             patch.object(checker, "_check_federation_metadata", side_effect=mock_false), \
             patch.object(checker, "_check_azure_ad_integration", side_effect=mock_false), \
             patch.object(checker, "_check_openid_config", side_effect=mock_openid_raises):
            result = await checker.check("corp.example.com")

        # The exception is caught; error is stored in result
        assert result.error is not None
        assert "OpenID check failed" in result.error

    async def test_check_federation_metadata_sets_hybrid(self):
        """Federation metadata alone sets has_hybrid_identity=True."""
        checker = HybridIdentityChecker(timeout=5.0)

        async def mock_dns(fqdn):
            return {}

        async def mock_adfs_no(fqdn):
            return {"found": False, "endpoint": None, "status_code": None}

        async def mock_true(fqdn):
            return True

        async def mock_false(fqdn):
            return False

        from unittest.mock import patch

        with patch.object(checker, "_check_dns_records", side_effect=mock_dns), \
             patch.object(checker, "_check_adfs_via_azure_login", side_effect=mock_adfs_no), \
             patch.object(checker, "_check_adfs_endpoint", side_effect=mock_adfs_no), \
             patch.object(checker, "_check_federation_metadata", side_effect=mock_true), \
             patch.object(checker, "_check_azure_ad_integration", side_effect=mock_false), \
             patch.object(checker, "_check_openid_config", side_effect=mock_false):
            result = await checker.check("corp.example.com")

        assert result.federation_metadata_found is True
        assert result.has_hybrid_identity is True

    async def test_result_includes_response_time(self):
        checker = HybridIdentityChecker(timeout=5.0)

        async def mock_dns(fqdn):
            return {}

        async def mock_adfs_no(fqdn):
            return {"found": False, "endpoint": None, "status_code": None}

        async def mock_false(fqdn):
            return False

        from unittest.mock import patch

        with patch.object(checker, "_check_dns_records", side_effect=mock_dns), \
             patch.object(checker, "_check_adfs_via_azure_login", side_effect=mock_adfs_no), \
             patch.object(checker, "_check_adfs_endpoint", side_effect=mock_adfs_no), \
             patch.object(checker, "_check_federation_metadata", side_effect=mock_false), \
             patch.object(checker, "_check_azure_ad_integration", side_effect=mock_false), \
             patch.object(checker, "_check_openid_config", side_effect=mock_false):
            result = await checker.check("corp.example.com")

        assert result.response_time >= 0.0
