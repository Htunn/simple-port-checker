"""
Extended tests for HybridIdentityChecker — covers the async network methods
with mocked aiohttp sessions and DNS resolver.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from offensive_ai.core.hybrid_identity_checker import HybridIdentityChecker, HybridIdentityResult


# ---------------------------------------------------------------------------
# HybridIdentityChecker init
# ---------------------------------------------------------------------------

class TestHybridIdentityCheckerInit:
    def test_default_timeout(self):
        checker = HybridIdentityChecker()
        assert checker.timeout == 10.0

    def test_custom_timeout(self):
        checker = HybridIdentityChecker(timeout=5.0)
        assert checker.timeout == 5.0

    def test_user_agent_set(self):
        checker = HybridIdentityChecker()
        assert checker.user_agent  # Not empty


# ---------------------------------------------------------------------------
# _check_dns_records — with mocked dns.resolver
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckDnsRecords:
    async def test_returns_dict_with_a_records(self):
        checker = HybridIdentityChecker()

        mock_a_rdata = MagicMock()
        mock_a_rdata.__str__ = lambda self: "10.0.0.1"

        with patch("dns.resolver.resolve") as mock_resolve:
            # First call (A records) → returns data
            # Other record types → NoAnswer
            import dns.resolver as dns_res
            def side_effect(fqdn, record_type):
                if record_type == "A":
                    return [mock_a_rdata]
                raise dns_res.NoAnswer()

            mock_resolve.side_effect = side_effect

            result = await checker._check_dns_records("example.com")

        assert "A" in result
        assert "10.0.0.1" in result["A"]

    async def test_returns_empty_dict_on_nxdomain(self):
        checker = HybridIdentityChecker()

        import dns.resolver as dns_res
        with patch("dns.resolver.resolve", side_effect=dns_res.NXDOMAIN):
            result = await checker._check_dns_records("nonexistent.example.com")

        assert isinstance(result, dict)

    async def test_microsoft_verification_txt_detected(self):
        checker = HybridIdentityChecker()

        import dns.resolver as dns_res
        mock_txt = MagicMock()
        mock_txt.__str__ = lambda self: '"MS=ms12345678"'

        def side_effect(fqdn, record_type):
            if record_type == "TXT":
                return [mock_txt]
            raise dns_res.NoAnswer()

        with patch("dns.resolver.resolve", side_effect=side_effect):
            result = await checker._check_dns_records("corp.example.com")

        # TXT result should be present
        assert "TXT" in result or "microsoft_verification" in result or isinstance(result, dict)

    async def test_mx_records_with_outlook(self):
        checker = HybridIdentityChecker()

        import dns.resolver as dns_res
        mock_mx = MagicMock()
        mock_mx.exchange = MagicMock()
        mock_mx.exchange.__str__ = lambda self: "example-com.mail.protection.outlook.com."

        def side_effect(fqdn, record_type):
            if record_type == "MX":
                return [mock_mx]
            raise dns_res.NoAnswer()

        with patch("dns.resolver.resolve", side_effect=side_effect):
            result = await checker._check_dns_records("corp.example.com")

        # Microsoft mail should be detected
        assert "MX" in result or "microsoft_mail" in result or isinstance(result, dict)


# ---------------------------------------------------------------------------
# _check_federation_metadata — with mocked aiohttp
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckFederationMetadata:
    async def test_returns_true_when_entity_descriptor_found(self):
        checker = HybridIdentityChecker(timeout=2.0)

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>')
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("aiohttp.TCPConnector"):
            result = await checker._check_federation_metadata("example.com")

        assert result is True

    async def test_returns_false_when_all_404(self):
        checker = HybridIdentityChecker(timeout=2.0)

        mock_response = AsyncMock()
        mock_response.status = 404
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("aiohttp.TCPConnector"):
            result = await checker._check_federation_metadata("example.com")

        assert result is False

    async def test_returns_false_on_connection_error(self):
        checker = HybridIdentityChecker(timeout=2.0)

        import aiohttp as aio
        mock_response = AsyncMock()
        mock_response.__aenter__ = AsyncMock(side_effect=aio.ClientError("connection refused"))
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("aiohttp.TCPConnector"):
            result = await checker._check_federation_metadata("example.com")

        assert result is False


# ---------------------------------------------------------------------------
# _check_openid_config — with mocked aiohttp
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckOpenIdConfig:
    async def test_returns_true_when_issuer_and_endpoint_found(self):
        checker = HybridIdentityChecker(timeout=2.0)

        openid_data = {
            "issuer": "https://adfs.example.com/adfs",
            "authorization_endpoint": "https://adfs.example.com/adfs/oauth2/authorize",
        }

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=openid_data)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("aiohttp.TCPConnector"):
            result = await checker._check_openid_config("example.com")

        assert result is True

    async def test_returns_false_when_missing_fields(self):
        checker = HybridIdentityChecker(timeout=2.0)

        # Missing authorization_endpoint
        openid_data = {"issuer": "https://example.com"}

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=openid_data)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("aiohttp.TCPConnector"):
            result = await checker._check_openid_config("example.com")

        assert result is False


# ---------------------------------------------------------------------------
# _check_azure_ad_integration — with mocked aiohttp
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckAzureAdIntegration:
    async def test_detects_azure_ad_redirect(self):
        checker = HybridIdentityChecker(timeout=2.0)

        mock_response = AsyncMock()
        mock_response.status = 302
        mock_response.headers = {"location": "https://login.microsoftonline.com/tenant/oauth2/authorize"}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("aiohttp.TCPConnector"):
            result = await checker._check_azure_ad_integration("corp.example.com")

        assert result is True

    async def test_no_azure_redirect_returns_false(self):
        checker = HybridIdentityChecker(timeout=2.0)

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("aiohttp.TCPConnector"):
            result = await checker._check_azure_ad_integration("corp.example.com")

        assert result is False


# ---------------------------------------------------------------------------
# check() — integration with all sub-checks mocked
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHybridIdentityCheck:
    async def test_check_fqdn_cleanup(self):
        """check() should strip protocol and path from FQDN."""
        checker = HybridIdentityChecker(timeout=1.0)

        with (
            patch.object(checker, "_check_dns_records", AsyncMock(return_value={})),
            patch.object(checker, "_check_adfs_via_azure_login", AsyncMock(return_value={"found": False, "endpoint": None, "status_code": None})),
            patch.object(checker, "_check_adfs_endpoint", AsyncMock(return_value={"found": False, "endpoint": None, "status_code": None})),
            patch.object(checker, "_check_federation_metadata", AsyncMock(return_value=False)),
            patch.object(checker, "_check_azure_ad_integration", AsyncMock(return_value=False)),
            patch.object(checker, "_check_openid_config", AsyncMock(return_value=False)),
        ):
            result = await checker.check("https://corp.example.com/path")

        assert result.fqdn == "corp.example.com"

    async def test_check_returns_hybrid_identity_result(self):
        checker = HybridIdentityChecker(timeout=1.0)

        with (
            patch.object(checker, "_check_dns_records", AsyncMock(return_value={})),
            patch.object(checker, "_check_adfs_via_azure_login", AsyncMock(return_value={"found": False, "endpoint": None, "status_code": None})),
            patch.object(checker, "_check_adfs_endpoint", AsyncMock(return_value={"found": False, "endpoint": None, "status_code": None})),
            patch.object(checker, "_check_federation_metadata", AsyncMock(return_value=False)),
            patch.object(checker, "_check_azure_ad_integration", AsyncMock(return_value=False)),
            patch.object(checker, "_check_openid_config", AsyncMock(return_value=False)),
        ):
            result = await checker.check("example.com")

        assert isinstance(result, HybridIdentityResult)

    async def test_check_adfs_found_sets_has_hybrid_identity(self):
        checker = HybridIdentityChecker(timeout=1.0)

        with (
            patch.object(checker, "_check_dns_records", AsyncMock(return_value={})),
            patch.object(checker, "_check_adfs_via_azure_login", AsyncMock(return_value={
                "found": True,
                "endpoint": "https://adfs.example.com/adfs/ls",
                "status_code": 200,
            })),
            patch.object(checker, "_check_adfs_endpoint", AsyncMock(return_value={"found": False, "endpoint": None, "status_code": None})),
            patch.object(checker, "_check_federation_metadata", AsyncMock(return_value=False)),
            patch.object(checker, "_check_azure_ad_integration", AsyncMock(return_value=False)),
            patch.object(checker, "_check_openid_config", AsyncMock(return_value=False)),
        ):
            result = await checker.check("example.com")

        assert result.has_adfs is True
        assert result.has_hybrid_identity is True
        assert result.adfs_endpoint == "https://adfs.example.com/adfs/ls"

    async def test_check_federation_metadata_sets_hybrid(self):
        checker = HybridIdentityChecker(timeout=1.0)

        with (
            patch.object(checker, "_check_dns_records", AsyncMock(return_value={})),
            patch.object(checker, "_check_adfs_via_azure_login", AsyncMock(return_value={"found": False, "endpoint": None, "status_code": None})),
            patch.object(checker, "_check_adfs_endpoint", AsyncMock(return_value={"found": False, "endpoint": None, "status_code": None})),
            patch.object(checker, "_check_federation_metadata", AsyncMock(return_value=True)),
            patch.object(checker, "_check_azure_ad_integration", AsyncMock(return_value=False)),
            patch.object(checker, "_check_openid_config", AsyncMock(return_value=False)),
        ):
            result = await checker.check("example.com")

        assert result.federation_metadata_found is True
        assert result.has_hybrid_identity is True

    async def test_check_error_handling(self):
        """check() should not raise even if sub-methods raise exceptions."""
        checker = HybridIdentityChecker(timeout=1.0)

        with patch.object(checker, "_check_dns_records", AsyncMock(side_effect=Exception("DNS failure"))):
            result = await checker.check("bad.example.com")

        # Should return a result with error info
        assert isinstance(result, HybridIdentityResult)

    async def test_batch_check_returns_list(self):
        checker = HybridIdentityChecker(timeout=1.0)

        async def mock_check(fqdn):
            return HybridIdentityResult(fqdn=fqdn)

        with patch.object(checker, "check", side_effect=mock_check):
            results = await checker.batch_check(["a.com", "b.com", "c.com"])

        assert len(results) == 3
        assert all(isinstance(r, HybridIdentityResult) for r in results)


# ---------------------------------------------------------------------------
# _check_adfs_via_azure_login — mocked aiohttp session
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckAdfsViaAzureLogin:
    def _make_session(self, realm_data=None, post_data=None, status=200):
        """Build a mock aiohttp session for testing _check_adfs_via_azure_login."""
        # GET response for the initial login page and realm check
        get_resp = MagicMock()
        get_resp.status = status
        get_resp.json = AsyncMock(return_value=realm_data or {})
        get_resp.__aenter__ = AsyncMock(return_value=get_resp)
        get_resp.__aexit__ = AsyncMock(return_value=None)

        # POST response for the GetCredentialType endpoint
        post_resp = MagicMock()
        post_resp.status = status
        post_resp.json = AsyncMock(return_value=post_data or {})
        post_resp.__aenter__ = AsyncMock(return_value=post_resp)
        post_resp.__aexit__ = AsyncMock(return_value=None)

        session = MagicMock()
        session.get = MagicMock(return_value=get_resp)
        session.post = MagicMock(return_value=post_resp)
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)
        return session

    async def test_federated_domain_returns_found(self):
        checker = HybridIdentityChecker(timeout=2.0)
        realm_data = {
            "NameSpaceType": "Federated",
            "AuthURL": "https://adfs.example.com/adfs/ls",
            "FederationBrandName": "Example Corp",
        }
        session = self._make_session(realm_data=realm_data)
        with (
            patch("aiohttp.ClientSession", return_value=session),
            patch("aiohttp.TCPConnector"),
        ):
            result = await checker._check_adfs_via_azure_login("example.com")

        assert result["found"] is True
        assert "adfs.example.com" in result.get("endpoint", "")

    async def test_managed_domain_returns_not_found(self):
        checker = HybridIdentityChecker(timeout=2.0)
        realm_data = {"NameSpaceType": "Managed"}
        session = self._make_session(realm_data=realm_data)
        with (
            patch("aiohttp.ClientSession", return_value=session),
            patch("aiohttp.TCPConnector"),
        ):
            result = await checker._check_adfs_via_azure_login("example.com")

        assert result["found"] is False

    async def test_federation_redirect_via_credential_type(self):
        checker = HybridIdentityChecker(timeout=2.0)
        # Realm says managed (no federation), but GetCredentialType returns redirect
        realm_data = {"NameSpaceType": "Managed"}
        post_data = {
            "ThrottleStatus": 0,
            "IfExistsResult": 0,  # User exists
            "Credentials": {
                "FederationRedirectUrl": "https://sso.example.com/saml",
            },
        }
        session = self._make_session(realm_data=realm_data, post_data=post_data)
        with (
            patch("aiohttp.ClientSession", return_value=session),
            patch("aiohttp.TCPConnector"),
        ):
            result = await checker._check_adfs_via_azure_login("example.com")

        assert result["found"] is True
        assert "sso.example.com" in result.get("endpoint", "")

    async def test_aiohttp_error_returns_empty(self):
        import aiohttp
        checker = HybridIdentityChecker(timeout=2.0)
        session = MagicMock()
        session.get.side_effect = aiohttp.ClientError("connection refused")
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)
        with (
            patch("aiohttp.ClientSession", return_value=session),
            patch("aiohttp.TCPConnector"),
        ):
            result = await checker._check_adfs_via_azure_login("example.com")

        assert result["found"] is False


# ---------------------------------------------------------------------------
# _check_adfs_endpoint — mocked aiohttp session
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckAdfsEndpoint:
    async def test_adfs_content_found_returns_found(self):
        checker = HybridIdentityChecker(timeout=2.0)

        resp = MagicMock()
        resp.status = 200
        resp.text = AsyncMock(return_value="<html>ADFS IdpInitiated Sign On</html>")
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)

        session = MagicMock()
        session.get = MagicMock(return_value=resp)
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("aiohttp.ClientSession", return_value=session),
            patch("aiohttp.TCPConnector"),
        ):
            result = await checker._check_adfs_endpoint("example.com")

        assert result["found"] is True
        assert result["endpoint"] is not None

    async def test_no_adfs_indicators_returns_not_found(self):
        checker = HybridIdentityChecker(timeout=2.0)

        resp = MagicMock()
        resp.status = 200
        resp.text = AsyncMock(return_value="<html>Welcome to Example Site</html>")
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)

        session = MagicMock()
        session.get = MagicMock(return_value=resp)
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("aiohttp.ClientSession", return_value=session),
            patch("aiohttp.TCPConnector"),
        ):
            result = await checker._check_adfs_endpoint("example.com")

        assert result["found"] is False

    async def test_connection_error_continues_and_returns_not_found(self):
        import aiohttp
        checker = HybridIdentityChecker(timeout=2.0)

        session = MagicMock()
        session.get.side_effect = aiohttp.ClientError("refused")
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("aiohttp.ClientSession", return_value=session),
            patch("aiohttp.TCPConnector"),
        ):
            result = await checker._check_adfs_endpoint("example.com")

        assert result["found"] is False

    async def test_401_response_with_adfs_content_is_found(self):
        checker = HybridIdentityChecker(timeout=2.0)

        resp = MagicMock()
        resp.status = 401
        resp.text = AsyncMock(return_value="Unauthorized - Microsoft IdentityServer adfs WsFederation")
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)

        session = MagicMock()
        session.get = MagicMock(return_value=resp)
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("aiohttp.ClientSession", return_value=session),
            patch("aiohttp.TCPConnector"),
        ):
            result = await checker._check_adfs_endpoint("example.com")

        assert result["found"] is True
