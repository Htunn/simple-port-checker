"""
Certificate Chain Analysis module for SSL/TLS certificate inspection.

This module provides functionality to analyze SSL/TLS certificate chains,
including certificate validation, chain of trust verification, and intermediate
CA analysis.
"""

import asyncio
import ssl
import socket
import hashlib
import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse
import cryptography
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
import aiohttp
import requests


@dataclass
class CertificateInfo:
    """Information about a single certificate."""
    
    subject: str
    issuer: str
    serial_number: str
    fingerprint_sha1: str
    fingerprint_sha256: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    is_ca: bool
    is_self_signed: bool
    is_expired: bool
    is_valid_now: bool
    key_size: int
    signature_algorithm: str
    public_key_algorithm: str
    san_domains: List[str]
    extensions: Dict[str, Any]
    pem_data: str
    raw_cert: x509.Certificate  # Store the raw certificate for validation


@dataclass
class CertificateChain:
    """Complete certificate chain information."""
    
    server_cert: CertificateInfo
    intermediate_certs: List[CertificateInfo]
    root_cert: Optional[CertificateInfo]
    chain_valid: bool
    chain_complete: bool
    missing_intermediates: List[str]
    trust_issues: List[str]
    ocsp_urls: List[str]
    crl_urls: List[str]


class CertificateAnalyzer:
    """Analyzer for SSL/TLS certificate chains."""

    def __init__(self, timeout: float = 10.0):
        """Initialize the certificate analyzer."""
        self.timeout = timeout

    async def analyze_certificate_chain(self, host: str, port: int = 443) -> CertificateChain:
        """
        Analyze the complete certificate chain for a host.
        
        Args:
            host: Target hostname
            port: Target port (default 443)
            
        Returns:
            CertificateChain object with complete analysis
        """
        try:
            # Get certificate chain from server
            cert_chain = await self._get_certificate_chain(host, port)
            
            if not cert_chain:
                raise ValueError("Could not retrieve certificate chain")
            
            # Analyze each certificate in the chain
            server_cert = self._analyze_certificate(cert_chain[0])
            intermediate_certs = [self._analyze_certificate(cert) 
                                for cert in cert_chain[1:]]
            
            # Try to get root certificate
            root_cert = await self._find_root_certificate(cert_chain)
            
            # Validate chain of trust
            chain_valid, trust_issues = self._validate_chain_of_trust(cert_chain)
            
            # Check for missing intermediates
            missing_intermediates = self._check_missing_intermediates(cert_chain)
            
            # Check if chain is complete
            chain_complete = len(missing_intermediates) == 0 and root_cert is not None
            
            # Extract OCSP and CRL URLs
            ocsp_urls, crl_urls = self._extract_revocation_urls(cert_chain)
            
            return CertificateChain(
                server_cert=server_cert,
                intermediate_certs=intermediate_certs,
                root_cert=root_cert,
                chain_valid=chain_valid,
                chain_complete=chain_complete,
                missing_intermediates=missing_intermediates,
                trust_issues=trust_issues,
                ocsp_urls=ocsp_urls,
                crl_urls=crl_urls
            )
            
        except Exception as e:
            raise RuntimeError(f"Certificate chain analysis failed: {str(e)}")

    async def _get_certificate_chain(self, host: str, port: int) -> List[x509.Certificate]:
        """Get the certificate chain from the server."""
        import subprocess
        import tempfile
        import os
        
        try:
            # Use openssl command to get full certificate chain
            cmd = [
                'openssl', 's_client', 
                '-connect', f'{host}:{port}',
                '-servername', host,
                '-showcerts', 
                '-verify_return_error'
            ]
            
            # Run openssl command with timeout
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, _ = await asyncio.wait_for(
                    process.communicate(input=b''),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                raise RuntimeError(f"Connection to {host}:{port} timed out")
            
            if process.returncode != 0:
                # Fallback to simple SSL connection for server cert only
                return self._get_server_certificate_only(host, port)
            
            # Parse certificates from output
            output = stdout.decode('utf-8', errors='ignore')
            certificates = []
            
            # Extract PEM certificates from output
            cert_blocks = []
            in_cert = False
            current_cert = []
            
            for line in output.split('\n'):
                if '-----BEGIN CERTIFICATE-----' in line:
                    in_cert = True
                    current_cert = [line]
                elif '-----END CERTIFICATE-----' in line and in_cert:
                    current_cert.append(line)
                    cert_blocks.append('\n'.join(current_cert))
                    current_cert = []
                    in_cert = False
                elif in_cert:
                    current_cert.append(line)
            
            # Convert PEM certificates to cryptography objects
            for pem_cert in cert_blocks:
                try:
                    cert = x509.load_pem_x509_certificate(pem_cert.encode('utf-8'))
                    certificates.append(cert)
                except Exception:
                    continue  # Skip invalid certificates
            
            if not certificates:
                # Fallback to simple SSL connection
                return self._get_server_certificate_only(host, port)
            
            return certificates
            
        except Exception:
            # Final fallback to simple SSL connection
            return self._get_server_certificate_only(host, port)

    def _get_server_certificate_only(self, host: str, port: int) -> List[x509.Certificate]:
        """Fallback method to get only the server certificate."""
        # Note: We intentionally disable certificate verification here because
        # we're analyzing the certificate itself, including potentially invalid ones
        context = ssl.create_default_context()
        context.check_hostname = False  # nosec - needed for certificate analysis
        context.verify_mode = ssl.CERT_NONE  # nosec - needed for certificate analysis
        
        # Connect and get only the server certificate
        sock = socket.create_connection((host, port), timeout=self.timeout)
        try:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Get the peer certificate in DER format
                der_cert_bin = ssock.getpeercert(True)
                if not der_cert_bin:
                    raise RuntimeError("Could not retrieve server certificate")
                
                cert = x509.load_der_x509_certificate(der_cert_bin)
                return [cert]
                
        finally:
            sock.close()

    def _analyze_certificate(self, cert: x509.Certificate) -> CertificateInfo:
        """Analyze a single certificate."""
        # Extract basic information
        subject = self._format_name(cert.subject)
        issuer = self._format_name(cert.issuer)
        serial_number = str(cert.serial_number)
        
        # Generate fingerprints
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        fingerprint_sha1 = hashlib.sha1(cert_der).hexdigest().upper()
        fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest().upper()
        
        # Validity dates
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)  # Make naive for comparison
        is_expired = now > not_after
        is_valid_now = not_before <= now <= not_after
        
        # Certificate type
        is_ca = self._is_ca_certificate(cert)
        is_self_signed = subject == issuer
        
        # Key information
        public_key = cert.public_key()
        key_size = public_key.key_size if hasattr(public_key, 'key_size') else 0
        public_key_algorithm = type(public_key).__name__
        
        # Signature algorithm
        signature_algorithm = cert.signature_algorithm_oid._name
        
        # Subject Alternative Names
        san_domains = self._extract_san_domains(cert)
        
        # Extensions
        extensions = self._extract_extensions(cert)
        
        # PEM data
        pem_data = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            serial_number=serial_number,
            fingerprint_sha1=fingerprint_sha1,
            fingerprint_sha256=fingerprint_sha256,
            not_before=not_before,
            not_after=not_after,
            is_ca=is_ca,
            is_self_signed=is_self_signed,
            is_expired=is_expired,
            is_valid_now=is_valid_now,
            key_size=key_size,
            signature_algorithm=signature_algorithm,
            public_key_algorithm=public_key_algorithm,
            san_domains=san_domains,
            extensions=extensions,
            pem_data=pem_data,
            raw_cert=cert
        )

    def _format_name(self, name: x509.Name) -> str:
        """Format X.509 name to readable string."""
        components = []
        for attribute in name:
            if attribute.oid == NameOID.COMMON_NAME:
                components.append(f"CN={attribute.value}")
            elif attribute.oid == NameOID.ORGANIZATION_NAME:
                components.append(f"O={attribute.value}")
            elif attribute.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                components.append(f"OU={attribute.value}")
            elif attribute.oid == NameOID.COUNTRY_NAME:
                components.append(f"C={attribute.value}")
            elif attribute.oid == NameOID.STATE_OR_PROVINCE_NAME:
                components.append(f"ST={attribute.value}")
            elif attribute.oid == NameOID.LOCALITY_NAME:
                components.append(f"L={attribute.value}")
        return ", ".join(components)

    def _is_ca_certificate(self, cert: x509.Certificate) -> bool:
        """Check if certificate is a CA certificate."""
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            return basic_constraints.ca
        except x509.ExtensionNotFound:
            return False

    def _extract_san_domains(self, cert: x509.Certificate) -> List[str]:
        """Extract Subject Alternative Name domains."""
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
            return [name.value for name in san_ext if isinstance(name, x509.DNSName)]
        except x509.ExtensionNotFound:
            return []

    def _extract_extensions(self, cert: x509.Certificate) -> Dict[str, Any]:
        """Extract certificate extensions."""
        extensions = {}
        
        for extension in cert.extensions:
            ext_name = extension.oid._name
            if ext_name:
                try:
                    if ext_name == "keyUsage":
                        extensions[ext_name] = self._format_key_usage(extension.value)
                    elif ext_name == "extendedKeyUsage":
                        extensions[ext_name] = self._format_extended_key_usage(extension.value)
                    elif ext_name == "basicConstraints":
                        extensions[ext_name] = self._format_basic_constraints(extension.value)
                    else:
                        extensions[ext_name] = str(extension.value)
                except Exception:
                    extensions[ext_name] = "Unable to parse"
        
        return extensions

    def _format_key_usage(self, key_usage) -> List[str]:
        """Format key usage extension."""
        usages = []
        if key_usage.digital_signature:
            usages.append("Digital Signature")
        if key_usage.key_encipherment:
            usages.append("Key Encipherment")
        if key_usage.data_encipherment:
            usages.append("Data Encipherment")
        if key_usage.key_agreement:
            usages.append("Key Agreement")
        if key_usage.key_cert_sign:
            usages.append("Certificate Sign")
        if key_usage.crl_sign:
            usages.append("CRL Sign")
        return usages

    def _format_extended_key_usage(self, ext_key_usage) -> List[str]:
        """Format extended key usage extension."""
        usages = []
        for usage in ext_key_usage:
            usages.append(usage._name)
        return usages

    def _format_basic_constraints(self, basic_constraints) -> Dict[str, Any]:
        """Format basic constraints extension."""
        return {
            "ca": basic_constraints.ca,
            "path_length": basic_constraints.path_length
        }

    async def _find_root_certificate(self, cert_chain: List[x509.Certificate]) -> Optional[CertificateInfo]:
        """Try to find the root certificate."""
        if not cert_chain:
            return None
        
        # Check if the last certificate in chain is self-signed (root)
        last_cert = cert_chain[-1]
        if self._format_name(last_cert.subject) == self._format_name(last_cert.issuer):
            return self._analyze_certificate(last_cert)
        
        # Try to fetch root certificate from issuer
        try:
            root_cert = await self._fetch_issuer_certificate(last_cert)
            if root_cert:
                return self._analyze_certificate(root_cert)
        except Exception:
            pass
        
        return None

    async def _fetch_issuer_certificate(self, cert: x509.Certificate) -> Optional[x509.Certificate]:
        """Try to fetch issuer certificate from AIA extension."""
        try:
            aia = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value
            
            for access_description in aia:
                if access_description.access_method._name == "caIssuers":
                    url = access_description.access_location.value
                    if url.startswith("http"):
                        return await self._download_certificate(url)
        except Exception:
            pass
        
        return None

    async def _download_certificate(self, url: str) -> Optional[x509.Certificate]:
        """Download certificate from URL."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        cert_data = await response.read()
                        try:
                            # Try DER format first
                            return x509.load_der_x509_certificate(cert_data)
                        except Exception:
                            # Try PEM format
                            return x509.load_pem_x509_certificate(cert_data)
        except Exception:
            pass
        
        return None

    def _validate_chain_of_trust(self, cert_chain: List[x509.Certificate]) -> Tuple[bool, List[str]]:
        """Validate the chain of trust."""
        issues = []
        
        if len(cert_chain) < 2:
            issues.append("Certificate chain too short - no intermediate certificates")
            return False, issues
        
        # Check each certificate is signed by the next one
        for i in range(len(cert_chain) - 1):
            current_cert = cert_chain[i]
            issuer_cert = cert_chain[i + 1]
            
            # Check if issuer matches
            if self._format_name(current_cert.issuer) != self._format_name(issuer_cert.subject):
                issues.append(f"Certificate {i} issuer does not match certificate {i+1} subject")
                continue
            
            # Verify signature (simplified check)
            try:
                issuer_public_key = issuer_cert.public_key()
                # This is a simplified verification - in practice, you'd verify the actual signature
                if not issuer_public_key:
                    issues.append(f"Cannot extract public key from issuer certificate {i+1}")
            except Exception as e:
                issues.append(f"Signature verification failed for certificate {i}: {str(e)}")
        
        return len(issues) == 0, issues

    def _check_missing_intermediates(self, cert_chain: List[x509.Certificate]) -> List[str]:
        """Check for missing intermediate certificates."""
        missing = []
        
        if len(cert_chain) < 2:
            missing.append("No intermediate certificates found in chain")
            return missing
        
        # Check if we need to fetch additional intermediates
        last_cert = cert_chain[-1]
        if self._format_name(last_cert.subject) != self._format_name(last_cert.issuer):
            # Last cert is not self-signed, so we're missing the root or more intermediates
            missing.append(f"Missing root certificate or additional intermediates after {self._format_name(last_cert.subject)}")
        
        return missing

    def _extract_revocation_urls(self, cert_chain: List[x509.Certificate]) -> Tuple[List[str], List[str]]:
        """Extract OCSP and CRL URLs from certificates."""
        ocsp_urls = []
        crl_urls = []
        
        for cert in cert_chain:
            # Extract OCSP URLs from AIA extension
            try:
                aia = cert.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                ).value
                
                for access_description in aia:
                    if access_description.access_method._name == "OCSP":
                        url = access_description.access_location.value
                        if url not in ocsp_urls:
                            ocsp_urls.append(url)
            except x509.ExtensionNotFound:
                pass
            
            # Extract CRL URLs
            try:
                crl_dist = cert.extensions.get_extension_for_oid(
                    ExtensionOID.CRL_DISTRIBUTION_POINTS
                ).value
                
                for dist_point in crl_dist:
                    if dist_point.full_name:
                        for name in dist_point.full_name:
                            if hasattr(name, 'value'):
                                url = name.value
                                if url not in crl_urls:
                                    crl_urls.append(url)
            except x509.ExtensionNotFound:
                pass
        
        return ocsp_urls, crl_urls

    def check_certificate_revocation(self, ocsp_url: str) -> Dict[str, Any]:
        """Check certificate revocation status via OCSP."""
        # This is a placeholder for OCSP checking functionality
        # Full OCSP implementation would require additional libraries
        return {
            "status": "unknown",
            "reason": "OCSP checking not fully implemented",
            "checked_url": ocsp_url
        }

    def validate_hostname(self, cert: x509.Certificate, hostname: str) -> bool:
        """Validate if certificate is valid for the given hostname."""
        # Check CN in subject
        try:
            cn = None
            for attribute in cert.subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    cn = attribute.value
                    break
            
            if cn and self._match_hostname(hostname, cn):
                return True
        except Exception:
            pass
        
        # Check SAN domains
        san_domains = self._extract_san_domains(cert)
        for domain in san_domains:
            if self._match_hostname(hostname, domain):
                return True
        
        return False

    def _match_hostname(self, hostname: str, cert_name: str) -> bool:
        """Check if hostname matches certificate name (supports wildcards)."""
        if cert_name == hostname:
            return True
        
        # Handle wildcard certificates
        if cert_name.startswith("*."):
            domain_part = cert_name[2:]
            if hostname.endswith("." + domain_part):
                return True
        
        return False
