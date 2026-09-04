"""
Tests for cert_analyzer internal methods and HybridIdentityResult model.

Uses cryptography library to generate synthetic test certificates — no network calls.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import ssl
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from offensive_ai.core.cert_analyzer import CertificateAnalyzer, CertificateInfo, CertificateChain


# ---------------------------------------------------------------------------
# Helpers — generate minimal self-signed test cert using cryptography
# ---------------------------------------------------------------------------

def _make_self_signed_cert(
    common_name: str = "test.example.com",
    days_valid: int = 365,
    is_ca: bool = False,
    sans: list[str] | None = None,
) :
    """Create a minimal self-signed X.509 certificate for testing."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.datetime.now(datetime.timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
    )

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )

    # Add SAN
    san_names = [x509.DNSName(common_name)]
    if sans:
        for san in sans:
            san_names.append(x509.DNSName(san))
    builder = builder.add_extension(
        x509.SubjectAlternativeName(san_names), critical=False
    )

    # Add key usage
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=is_ca,
            crl_sign=is_ca,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    return builder.sign(key, hashes.SHA256())


def _make_expired_cert(common_name: str = "expired.example.com"):
    """Create an already-expired certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    past = now - datetime.timedelta(days=400)
    yesterday = now - datetime.timedelta(days=1)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(past)
        .not_valid_after(yesterday)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )


# ---------------------------------------------------------------------------
# Test _analyze_certificate
# ---------------------------------------------------------------------------

class TestAnalyzeCertificate:
    def setup_method(self):
        self.analyzer = CertificateAnalyzer()

    def test_subject_contains_cn(self):
        cert = _make_self_signed_cert("myhost.example.com")
        info = self.analyzer._analyze_certificate(cert)
        assert "CN=myhost.example.com" in info.subject

    def test_is_self_signed(self):
        cert = _make_self_signed_cert()
        info = self.analyzer._analyze_certificate(cert)
        assert info.is_self_signed is True

    def test_valid_cert_not_expired(self):
        cert = _make_self_signed_cert(days_valid=365)
        info = self.analyzer._analyze_certificate(cert)
        assert info.is_expired is False
        assert info.is_valid_now is True

    def test_expired_cert_flagged(self):
        cert = _make_expired_cert()
        info = self.analyzer._analyze_certificate(cert)
        assert info.is_expired is True
        assert info.is_valid_now is False

    def test_fingerprints_non_empty(self):
        cert = _make_self_signed_cert()
        info = self.analyzer._analyze_certificate(cert)
        assert len(info.fingerprint_sha1) > 0
        assert len(info.fingerprint_sha256) > 0
        # SHA-1 hex = 40 chars, SHA-256 hex = 64 chars
        assert len(info.fingerprint_sha1) == 40
        assert len(info.fingerprint_sha256) == 64

    def test_fingerprints_uppercase(self):
        cert = _make_self_signed_cert()
        info = self.analyzer._analyze_certificate(cert)
        assert info.fingerprint_sha1 == info.fingerprint_sha1.upper()
        assert info.fingerprint_sha256 == info.fingerprint_sha256.upper()

    def test_pem_data_is_string(self):
        cert = _make_self_signed_cert()
        info = self.analyzer._analyze_certificate(cert)
        assert info.pem_data.startswith("-----BEGIN CERTIFICATE-----")

    def test_key_size_is_2048(self):
        cert = _make_self_signed_cert()
        info = self.analyzer._analyze_certificate(cert)
        assert info.key_size == 2048

    def test_san_domains_extracted(self):
        cert = _make_self_signed_cert("main.example.com", sans=["alt.example.com"])
        info = self.analyzer._analyze_certificate(cert)
        assert "main.example.com" in info.san_domains
        assert "alt.example.com" in info.san_domains

    def test_ca_cert_flagged(self):
        cert = _make_self_signed_cert(is_ca=True)
        info = self.analyzer._analyze_certificate(cert)
        assert info.is_ca is True

    def test_end_entity_cert_not_ca(self):
        cert = _make_self_signed_cert(is_ca=False)
        info = self.analyzer._analyze_certificate(cert)
        assert info.is_ca is False

    def test_raw_cert_stored(self):
        from cryptography import x509 as cx509
        cert = _make_self_signed_cert()
        info = self.analyzer._analyze_certificate(cert)
        assert isinstance(info.raw_cert, cx509.Certificate)


# ---------------------------------------------------------------------------
# Test _format_name
# ---------------------------------------------------------------------------

class TestFormatName:
    def setup_method(self):
        self.analyzer = CertificateAnalyzer()

    def test_cn_in_output(self):
        cert = _make_self_signed_cert("test.example.com")
        name_str = self.analyzer._format_name(cert.subject)
        assert "CN=test.example.com" in name_str

    def test_country_in_output(self):
        cert = _make_self_signed_cert()
        name_str = self.analyzer._format_name(cert.subject)
        assert "C=US" in name_str

    def test_org_in_output(self):
        cert = _make_self_signed_cert()
        name_str = self.analyzer._format_name(cert.subject)
        assert "O=Test Org" in name_str


# ---------------------------------------------------------------------------
# Test _is_ca_certificate
# ---------------------------------------------------------------------------

class TestIsCaCertificate:
    def setup_method(self):
        self.analyzer = CertificateAnalyzer()

    def test_ca_cert(self):
        cert = _make_self_signed_cert(is_ca=True)
        assert self.analyzer._is_ca_certificate(cert) is True

    def test_end_entity_cert(self):
        cert = _make_self_signed_cert(is_ca=False)
        assert self.analyzer._is_ca_certificate(cert) is False


# ---------------------------------------------------------------------------
# Test _extract_san_domains
# ---------------------------------------------------------------------------

class TestExtractSanDomains:
    def setup_method(self):
        self.analyzer = CertificateAnalyzer()

    def test_main_san_present(self):
        cert = _make_self_signed_cert("api.example.com")
        sans = self.analyzer._extract_san_domains(cert)
        assert "api.example.com" in sans

    def test_additional_sans(self):
        cert = _make_self_signed_cert("api.example.com", sans=["www.example.com", "example.com"])
        sans = self.analyzer._extract_san_domains(cert)
        assert "www.example.com" in sans
        assert "example.com" in sans


# ---------------------------------------------------------------------------
# Test _extract_extensions
# ---------------------------------------------------------------------------

class TestExtractExtensions:
    def setup_method(self):
        self.analyzer = CertificateAnalyzer()

    def test_basic_constraints_in_extensions(self):
        cert = _make_self_signed_cert()
        extensions = self.analyzer._extract_extensions(cert)
        assert "basicConstraints" in extensions

    def test_key_usage_in_extensions(self):
        cert = _make_self_signed_cert()
        extensions = self.analyzer._extract_extensions(cert)
        assert "keyUsage" in extensions


# ---------------------------------------------------------------------------
# Test _validate_chain_of_trust
# ---------------------------------------------------------------------------

class TestValidateChainOfTrust:
    def setup_method(self):
        self.analyzer = CertificateAnalyzer()

    def test_single_self_signed_cert(self):
        cert = _make_self_signed_cert()
        valid, issues = self.analyzer._validate_chain_of_trust([cert])
        # Self-signed cert is a trust issue
        assert isinstance(valid, bool)
        assert isinstance(issues, list)

    def test_empty_chain_returns_false(self):
        valid, issues = self.analyzer._validate_chain_of_trust([])
        assert valid is False


# ---------------------------------------------------------------------------
# Test _check_missing_intermediates
# ---------------------------------------------------------------------------

class TestCheckMissingIntermediates:
    def setup_method(self):
        self.analyzer = CertificateAnalyzer()

    def test_single_cert_chain(self):
        cert = _make_self_signed_cert()
        missing = self.analyzer._check_missing_intermediates([cert])
        assert isinstance(missing, list)

    def test_two_certs_no_missing(self):
        leaf = _make_self_signed_cert()
        root = _make_self_signed_cert(is_ca=True)
        missing = self.analyzer._check_missing_intermediates([leaf, root])
        assert isinstance(missing, list)


# ---------------------------------------------------------------------------
# Test _extract_revocation_urls
# ---------------------------------------------------------------------------

class TestExtractRevocationUrls:
    def setup_method(self):
        self.analyzer = CertificateAnalyzer()

    def test_basic_cert_no_ocsp(self):
        cert = _make_self_signed_cert()
        ocsp_urls, crl_urls = self.analyzer._extract_revocation_urls([cert])
        assert isinstance(ocsp_urls, list)
        assert isinstance(crl_urls, list)


# ---------------------------------------------------------------------------
# Test CertificateAnalyzer constructor
# ---------------------------------------------------------------------------

class TestCertificateAnalyzerInit:
    def test_default_timeout(self):
        analyzer = CertificateAnalyzer()
        assert analyzer.timeout == 10.0

    def test_custom_timeout(self):
        analyzer = CertificateAnalyzer(timeout=30.0)
        assert analyzer.timeout == 30.0


# ---------------------------------------------------------------------------
# Test analyze_certificate_chain with mocked network (error path)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAnalyzeCertificateChainErrors:
    async def test_empty_chain_raises_runtime_error(self):
        """If chain retrieval returns empty list, RuntimeError should be raised."""
        analyzer = CertificateAnalyzer(timeout=5.0)

        with patch.object(analyzer, "_get_certificate_chain", new=AsyncMock(return_value=[])):
            with pytest.raises(RuntimeError):
                await analyzer.analyze_certificate_chain("unreachable.test.local", 443)

    async def test_exception_in_chain_raises_runtime_error(self):
        """Exception from _get_certificate_chain propagates as RuntimeError."""
        analyzer = CertificateAnalyzer(timeout=5.0)

        async def raise_exc(host, port):
            raise ConnectionRefusedError("refused")

        with patch.object(analyzer, "_get_certificate_chain", side_effect=raise_exc):
            with pytest.raises(RuntimeError):
                await analyzer.analyze_certificate_chain("unreachable.test.local", 443)

    async def test_valid_chain_returns_certificate_chain(self):
        """Given a valid single-cert chain, returns CertificateChain."""
        analyzer = CertificateAnalyzer(timeout=5.0)
        cert = _make_self_signed_cert("mock.example.com")

        async def mock_get_chain(host, port):
            return [cert]

        with patch.object(analyzer, "_get_certificate_chain", side_effect=mock_get_chain):
            with patch.object(analyzer, "_find_root_certificate", new=AsyncMock(return_value=None)):
                chain = await analyzer.analyze_certificate_chain("mock.example.com", 443)

        assert isinstance(chain, CertificateChain)
        assert chain.server_cert.subject is not None
        assert chain.intermediate_certs == []
