"""Tests for mTLS models and CLI commands."""

from datetime import datetime


def test_imports():
    """All mTLS modules import without error."""
    from offensive_ai.models.mtls_result import BatchMTLSResult, CertificateInfo, MTLSResult  # noqa: F401
    from offensive_ai.core.mtls_checker import MTLSChecker  # noqa: F401


def test_certificate_info_model():
    """CertificateInfo model fields are created correctly."""
    from offensive_ai.models.mtls_result import CertificateInfo

    cert = CertificateInfo(
        subject="CN=test.example.com",
        issuer="CN=Test CA",
        version=3,
        serial_number="12345",
        not_valid_before="2024-01-01T00:00:00",
        not_valid_after="2025-01-01T00:00:00",
        signature_algorithm="sha256WithRSAEncryption",
        key_algorithm="RSAPublicKey",
        key_size=2048,
        san_dns_names=["test.example.com", "*.example.com"],
        san_ip_addresses=["192.168.1.1"],
        is_ca=False,
        is_self_signed=False,
        fingerprint_sha256="abcd1234...",
    )
    assert cert.subject == "CN=test.example.com"
    assert cert.key_size == 2048
    assert "test.example.com" in cert.san_dns_names
    assert cert.is_ca is False


def test_mtls_result_model():
    """MTLSResult is created, fields are accessible, and serializes to JSON."""
    from offensive_ai.models.mtls_result import CertificateInfo, MTLSResult

    cert = CertificateInfo(
        subject="CN=test.example.com",
        issuer="CN=Test CA",
        version=3,
        serial_number="12345",
        not_valid_before="2024-01-01T00:00:00",
        not_valid_after="2025-01-01T00:00:00",
        signature_algorithm="sha256WithRSAEncryption",
        key_algorithm="RSAPublicKey",
        key_size=2048,
        san_dns_names=["test.example.com"],
        san_ip_addresses=[],
        is_ca=False,
        is_self_signed=False,
        fingerprint_sha256="abcd1234...",
    )
    result = MTLSResult(
        target="test.example.com",
        port=443,
        supports_mtls=True,
        requires_client_cert=False,
        server_cert_info=cert,
        client_cert_requested=True,
        handshake_successful=False,
        error_message=None,
        cipher_suite="TLS_AES_256_GCM_SHA384",
        tls_version="TLSv1.3",
        verification_mode="default",
        ca_bundle_path="/etc/ssl/certs/ca-certificates.crt",
        timestamp=datetime.now().isoformat(),
    )
    assert result.target == "test.example.com"
    assert result.port == 443
    assert result.supports_mtls is True
    assert result.server_cert_info.key_size == 2048

    json_str = result.model_dump_json()
    assert "test.example.com" in json_str
    assert "TLSv1.3" in json_str


def test_cli_mtls_commands_exist():
    """mTLS CLI commands are registered and return help text."""
    from click.testing import CliRunner

    from offensive_ai.cli import main

    runner = CliRunner()

    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "mtls-check" in result.output

    result = runner.invoke(main, ["mtls-check", "--help"])
    assert result.exit_code == 0

    result = runner.invoke(main, ["mtls-gen-cert", "--help"])
    assert result.exit_code == 0

    result = runner.invoke(main, ["mtls-validate-cert", "--help"])
    assert result.exit_code == 0
