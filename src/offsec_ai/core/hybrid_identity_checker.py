"""
Hybrid Identity and ADFS Checker module.

This module provides functionality to check if a domain has hybrid identity setup
and detect ADFS endpoints.
"""

import asyncio
import time
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse

import aiohttp
import dns.resolver
import warnings
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings('ignore', category=InsecureRequestWarning)


class HybridIdentityResult:
    """Result of hybrid identity check."""
    
    def __init__(
        self,
        fqdn: str,
        has_hybrid_identity: bool = False,
        has_adfs: bool = False,
        adfs_endpoint: Optional[str] = None,
        adfs_status_code: Optional[int] = None,
        federation_metadata_found: bool = False,
        azure_ad_detected: bool = False,
        openid_config_found: bool = False,
        dns_records: Optional[Dict[str, List[str]]] = None,
        error: Optional[str] = None,
        response_time: float = 0.0
    ):
        """
        Initialize hybrid identity result.
        
        Args:
            fqdn: Fully Qualified Domain Name checked
            has_hybrid_identity: Whether hybrid identity setup was detected
            has_adfs: Whether ADFS endpoint was found
            adfs_endpoint: Full ADFS endpoint URL if found
            adfs_status_code: HTTP status code from ADFS endpoint
            federation_metadata_found: Whether federation metadata was found
            azure_ad_detected: Whether Azure AD integration was detected
            openid_config_found: Whether OpenID Connect configuration was found
            dns_records: DNS records found for the domain
            error: Error message if check failed
            response_time: Total response time in seconds
        """
        self.fqdn = fqdn
        self.has_hybrid_identity = has_hybrid_identity
        self.has_adfs = has_adfs
        self.adfs_endpoint = adfs_endpoint
        self.adfs_status_code = adfs_status_code
        self.federation_metadata_found = federation_metadata_found
        self.azure_ad_detected = azure_ad_detected
        self.openid_config_found = openid_config_found
        self.dns_records = dns_records or {}
        self.error = error
        self.response_time = response_time
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "fqdn": self.fqdn,
            "has_hybrid_identity": self.has_hybrid_identity,
            "has_adfs": self.has_adfs,
            "adfs_endpoint": self.adfs_endpoint,
            "adfs_status_code": self.adfs_status_code,
            "federation_metadata_found": self.federation_metadata_found,
            "azure_ad_detected": self.azure_ad_detected,
            "openid_config_found": self.openid_config_found,
            "dns_records": self.dns_records,
            "error": self.error,
            "response_time": self.response_time
        }


class HybridIdentityChecker:
    """Checker for hybrid identity and ADFS endpoints."""
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize the hybrid identity checker.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.user_agent = "offsec-ai/2.0 (Hybrid Identity Scanner)"
    
    async def check(self, fqdn: str) -> HybridIdentityResult:
        """
        Check if FQDN has hybrid identity setup.
        
        This checks for:
        - ADFS endpoints via Azure AD login flow (most reliable method)
        - ADFS endpoints (/adfs/ls)
        - Federation metadata
        - Azure AD integration
        - OpenID Connect configuration
        
        Args:
            fqdn: Fully Qualified Domain Name to check
            
        Returns:
            HybridIdentityResult with detection results
        """
        start_time = time.time()
        
        # Clean FQDN (remove protocol if present)
        fqdn = fqdn.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        
        # Initialize result flags
        has_adfs = False
        adfs_endpoint = None
        adfs_status_code = None
        federation_metadata_found = False
        azure_ad_detected = False
        openid_config_found = False
        has_hybrid_identity = False
        error = None
        dns_records = {}
        
        try:
            # Check DNS records first
            dns_records = await self._check_dns_records(fqdn)
            
            # PRIORITY 1: Check ADFS via Azure AD login flow (most reliable method)
            # This simulates what happens when you try to login at portal.azure.com
            azure_flow_result = await self._check_adfs_via_azure_login(fqdn)
            if azure_flow_result["found"]:
                has_adfs = True
                adfs_endpoint = azure_flow_result["endpoint"]
                adfs_status_code = azure_flow_result["status_code"]
            
            # PRIORITY 2: If not found via Azure flow, check direct ADFS endpoints
            if not has_adfs:
                adfs_result = await self._check_adfs_endpoint(fqdn)
                has_adfs = adfs_result["found"]
                adfs_endpoint = adfs_result["endpoint"]
                adfs_status_code = adfs_result["status_code"]
            
            # Check for federation metadata
            federation_metadata_found = await self._check_federation_metadata(fqdn)
            
            # Check for Azure AD integration
            azure_ad_detected = await self._check_azure_ad_integration(fqdn)
            
            # Check for OpenID Connect configuration
            openid_config_found = await self._check_openid_config(fqdn)
            
            # Determine if hybrid identity is present
            has_hybrid_identity = (
                has_adfs or 
                federation_metadata_found or 
                azure_ad_detected or
                openid_config_found
            )
            
        except Exception as e:
            error = str(e)
        
        response_time = time.time() - start_time
        
        return HybridIdentityResult(
            fqdn=fqdn,
            has_hybrid_identity=has_hybrid_identity,
            has_adfs=has_adfs,
            adfs_endpoint=adfs_endpoint,
            adfs_status_code=adfs_status_code,
            federation_metadata_found=federation_metadata_found,
            azure_ad_detected=azure_ad_detected,
            openid_config_found=openid_config_found,
            dns_records=dns_records,
            error=error,
            response_time=response_time
        )
    
    async def _check_dns_records(self, fqdn: str) -> Dict[str, List[str]]:
        """
        Check DNS records for hybrid identity indicators.
        
        Args:
            fqdn: Domain to check
            
        Returns:
            Dictionary of DNS records
        """
        dns_records = {}
        
        try:
            # Check A records
            try:
                answers = dns.resolver.resolve(fqdn, 'A')
                dns_records['A'] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Check CNAME records
            try:
                answers = dns.resolver.resolve(fqdn, 'CNAME')
                dns_records['CNAME'] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Check TXT records (often contain MS verification)
            try:
                answers = dns.resolver.resolve(fqdn, 'TXT')
                txt_records = [str(rdata).strip('"') for rdata in answers]
                dns_records['TXT'] = txt_records
                
                # Check for Microsoft verification records
                for txt in txt_records:
                    if 'MS=' in txt or 'ms-domain-verification' in txt.lower():
                        dns_records['microsoft_verification'] = True
                        break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Check MX records (may indicate Microsoft 365)
            try:
                answers = dns.resolver.resolve(fqdn, 'MX')
                mx_records = [str(rdata.exchange) for rdata in answers]
                dns_records['MX'] = mx_records
                
                # Check for Microsoft mail servers
                for mx in mx_records:
                    if 'outlook.com' in mx.lower() or 'microsoft.com' in mx.lower():
                        dns_records['microsoft_mail'] = True
                        break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Check for common ADFS subdomains
            adfs_subdomains = ['adfs', 'sts', 'federation', 'fs']
            for subdomain in adfs_subdomains:
                try:
                    test_fqdn = f"{subdomain}.{fqdn}"
                    answers = dns.resolver.resolve(test_fqdn, 'A')
                    if not dns_records.get('adfs_subdomains'):
                        dns_records['adfs_subdomains'] = []
                    dns_records['adfs_subdomains'].append(subdomain)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
        
        except Exception as e:
            dns_records['error'] = str(e)
        
        return dns_records
    
    async def _check_adfs_via_azure_login(self, fqdn: str) -> Dict[str, Any]:
        """
        Check for ADFS endpoint by following Azure AD login flow.
        
        This simulates what happens when you try to login at Azure Portal:
        1. Navigate to login.microsoftonline.com
        2. Submit username like test@fqdn
        3. Azure AD checks if domain is federated
        4. If federated, redirects to ADFS endpoint
        
        Args:
            fqdn: Domain to check
            
        Returns:
            Dictionary with found status, endpoint, and status code
        """
        result = {
            "found": False,
            "endpoint": None,
            "status_code": None
        }
        
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            try:
                # Step 1: Get the Azure AD login page to obtain necessary tokens/cookies
                # This mimics the initial Azure Portal login flow
                login_url = "https://login.microsoftonline.com/common/oauth2/authorize"
                params = {
                    "client_id": "00000002-0000-0000-c000-000000000000",  # Azure Management Portal client ID
                    "response_type": "code",
                    "redirect_uri": "https://portal.azure.com/",
                    "resource": "https://management.core.windows.net/",
                }
                headers = {
                    "User-Agent": self.user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                }
                
                async with session.get(login_url, params=params, headers=headers, allow_redirects=True) as response:
                    # Get any cookies or context we need
                    pass
                
                # Step 2: Check user realm for the domain
                # This API tells us if a domain is managed or federated
                realm_url = f"https://login.microsoftonline.com/common/userrealm/test@{fqdn}"
                params_realm = {
                    "api-version": "2.0",
                    "checkForMicrosoftAccount": "false"
                }
                
                async with session.get(realm_url, params=params_realm, headers=headers) as response:
                    if response.status == 200:
                        try:
                            realm_data = await response.json()
                            
                            # Check if domain is federated
                            account_type = realm_data.get("NameSpaceType", "")
                            is_federated = account_type == "Federated"
                            
                            if is_federated:
                                # Extract ADFS endpoint from realm data
                                auth_url = realm_data.get("AuthURL", "")
                                federation_brand_name = realm_data.get("FederationBrandName", "")
                                
                                if auth_url:
                                    result["found"] = True
                                    result["endpoint"] = auth_url
                                    result["status_code"] = 200
                                    result["federation_brand"] = federation_brand_name
                                    
                                    # Try to verify the ADFS endpoint is actually accessible
                                    try:
                                        async with session.get(auth_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as adfs_response:
                                            result["status_code"] = adfs_response.status
                                    except:
                                        pass  # Endpoint found but might not be publicly accessible
                                    
                                    return result
                        
                        except Exception:
                            pass  # JSON parsing failed, continue to other methods
                
                # Step 3: Alternative method - check GetCredentialType API
                # This is used by the modern Azure AD login experience
                cred_type_url = "https://login.microsoftonline.com/common/GetCredentialType"
                cred_data = {
                    "username": f"test@{fqdn}",
                    "isOtherIdpSupported": True,
                    "checkPhones": False,
                    "isRemoteNGCSupported": True,
                    "isCookieBannerShown": False,
                    "isFidoSupported": False,
                    "originalRequest": "",
                    "flowToken": ""
                }
                headers["Content-Type"] = "application/json"
                
                async with session.post(cred_type_url, json=cred_data, headers=headers) as response:
                    if response.status == 200:
                        try:
                            cred_type_data = await response.json()
                            
                            # Check for federation information
                            if cred_type_data.get("ThrottleStatus") != 1:  # Not throttled
                                # Check if federated
                                if cred_type_data.get("IfExistsResult") == 0:  # User exists
                                    # Look for federation redirect URL
                                    federation_redirect = cred_type_data.get("Credentials", {}).get("FederationRedirectUrl")
                                    if federation_redirect:
                                        result["found"] = True
                                        result["endpoint"] = federation_redirect
                                        result["status_code"] = 200
                                        return result
                        
                        except Exception:
                            pass
            
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        
        return result
    
    async def _check_adfs_endpoint(self, fqdn: str) -> Dict[str, Any]:
        """
        Check for ADFS endpoint at /adfs/ls.
        
        Args:
            fqdn: Domain to check
            
        Returns:
            Dictionary with found status, endpoint, and status code
        """
        result = {
            "found": False,
            "endpoint": None,
            "status_code": None
        }
        
        # Common ADFS paths to check
        adfs_paths = [
            "/adfs/ls",
            "/adfs/ls/IdpInitiatedSignOn.aspx",
            "/adfs/ls/IdpInitiatedSignon.aspx",
        ]
        
        # Try with potential ADFS subdomains and the main domain
        hosts_to_check = [fqdn]
        adfs_subdomains = ['adfs', 'sts', 'federation', 'fs']
        for subdomain in adfs_subdomains:
            hosts_to_check.append(f"{subdomain}.{fqdn}")
        
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for host in hosts_to_check:
                for path in adfs_paths:
                    try:
                        url = f"https://{host}{path}"
                        headers = {"User-Agent": self.user_agent}
                        
                        async with session.get(url, headers=headers, allow_redirects=True) as response:
                            # ADFS typically returns 200, 302, or 401
                            if response.status in [200, 302, 401, 403]:
                                content = await response.text()
                                
                                # Check for ADFS indicators in response
                                adfs_indicators = [
                                    'adfs',
                                    'microsoft.identityserver',
                                    'idpinitiated',
                                    'federationmetadata',
                                    'claimsawareness',
                                    'ws-federation'
                                ]
                                
                                content_lower = content.lower()
                                if any(indicator in content_lower for indicator in adfs_indicators):
                                    result["found"] = True
                                    result["endpoint"] = url
                                    result["status_code"] = response.status
                                    return result
                    
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue
        
        return result
    
    async def _check_federation_metadata(self, fqdn: str) -> bool:
        """
        Check for WS-Federation metadata endpoint.
        
        Args:
            fqdn: Domain to check
            
        Returns:
            True if federation metadata found
        """
        metadata_paths = [
            "/FederationMetadata/2007-06/FederationMetadata.xml",
            "/adfs/services/trust/2005/windowstransport",
            "/adfs/services/trust/mex",
        ]
        
        hosts_to_check = [fqdn, f"adfs.{fqdn}", f"sts.{fqdn}", f"federation.{fqdn}"]
        
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for host in hosts_to_check:
                for path in metadata_paths:
                    try:
                        url = f"https://{host}{path}"
                        headers = {"User-Agent": self.user_agent}
                        
                        async with session.get(url, headers=headers) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Check for federation metadata indicators
                                if 'EntityDescriptor' in content or 'federationmetadata' in content.lower():
                                    return True
                    
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue
        
        return False
    
    async def _check_azure_ad_integration(self, fqdn: str) -> bool:
        """
        Check for Azure AD integration indicators.
        
        Args:
            fqdn: Domain to check
            
        Returns:
            True if Azure AD integration detected
        """
        # Check login endpoints that redirect to Azure AD
        azure_paths = [
            "/",
            "/login",
            "/signin",
            "/_login",
        ]
        
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for path in azure_paths:
                try:
                    url = f"https://{fqdn}{path}"
                    headers = {"User-Agent": self.user_agent}
                    
                    async with session.get(url, headers=headers, allow_redirects=False) as response:
                        # Check for Azure AD redirect
                        if 'location' in response.headers:
                            location = response.headers['location'].lower()
                            if 'login.microsoftonline.com' in location or 'login.windows.net' in location:
                                return True
                        
                        # Check response headers for Azure AD indicators
                        for header, value in response.headers.items():
                            if 'azure' in header.lower() or 'azure' in str(value).lower():
                                if 'ad' in str(value).lower() or 'activedirectory' in str(value).lower():
                                    return True
                
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue
        
        return False
    
    async def _check_openid_config(self, fqdn: str) -> bool:
        """
        Check for OpenID Connect configuration endpoint.
        
        Args:
            fqdn: Domain to check
            
        Returns:
            True if OpenID configuration found
        """
        openid_paths = [
            "/.well-known/openid-configuration",
            "/adfs/.well-known/openid-configuration",
        ]
        
        hosts_to_check = [fqdn, f"adfs.{fqdn}", f"sts.{fqdn}"]
        
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for host in hosts_to_check:
                for path in openid_paths:
                    try:
                        url = f"https://{host}{path}"
                        headers = {"User-Agent": self.user_agent}
                        
                        async with session.get(url, headers=headers) as response:
                            if response.status == 200:
                                try:
                                    data = await response.json()
                                    # Check for OpenID configuration fields
                                    if 'issuer' in data and 'authorization_endpoint' in data:
                                        return True
                                except:
                                    pass
                    
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue
        
        return False
    
    async def batch_check(self, fqdns: List[str], max_concurrent: int = 10) -> List[HybridIdentityResult]:
        """
        Check multiple FQDNs for hybrid identity.
        
        Args:
            fqdns: List of FQDNs to check
            max_concurrent: Maximum number of simultaneous identity checks
            
        Returns:
            List of HybridIdentityResult
        """
        results: List[HybridIdentityResult] = []
        # Process in chunks so pending-task count is bounded by max_concurrent
        for i in range(0, len(fqdns), max_concurrent):
            chunk = fqdns[i:i + max_concurrent]
            chunk_results = await asyncio.gather(*[self.check(fqdn) for fqdn in chunk])
            results.extend(chunk_results)
        return results
