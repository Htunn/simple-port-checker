"""Integration-level tests for mTLS: models, CLI structure, and documentation presence."""

import os
from datetime import datetime


def test_mtls_model_full_lifecycle():
    """MTLSResult supports full create → serialize → field-access lifecycle."""
    from offsec_ai.models.mtls_result import CertificateInfo, MTLSResult

    cert = CertificateInfo(
        subject="CN=test.example.com,O=Test Org,C=US",
        issuer="CN=Test CA,O=Test CA Org,C=US",
        version=3,
        serial_number="123456789",
        not_valid_before="2024-01-01T00:00:00Z",
        not_valid_after="2025-01-01T00:00:00Z",
        signature_algorithm="sha256WithRSAEncryption",
        key_algorithm="RSAPublicKey",
        key_size=2048,
        san_dns_names=["test.example.com", "www.test.example.com"],
        san_ip_addresses=["192.168.1.100"],
        is_ca=False,
        is_self_signed=False,
        fingerprint_sha256="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
    )
    mtls_result = MTLSResult(
        target="test.example.com",
        port=443,
        supports_mtls=True,
        requires_client_cert=True,
        server_cert_info=cert,
        client_cert_requested=True,
        handshake_successful=True,
        error_message=None,
        cipher_suite="TLS_AES_256_GCM_SHA384",
        tls_version="TLSv1.3",
        verification_mode="strict",
        ca_bundle_path="/etc/ssl/certs/ca-certificates.crt",
        timestamp=datetime.now().isoformat(),
    )

    assert mtls_result.target == "test.example.com"
    assert mtls_result.supports_mtls is True
    assert mtls_result.server_cert_info.subject == "CN=test.example.com,O=Test Org,C=US"

    json_str = mtls_result.model_dump_json(indent=2)
    assert len(json_str) > 100
    assert "TLSv1.3" in json_str


def test_cli_structure():
    """All expected mTLS commands are present in the CLI."""
    from offsec_ai.cli import main

    cli_source = main.__module__
    import inspect
    import offsec_ai.cli as cli_module

    src = inspect.getsource(cli_module)
    for symbol in ("mtls-check", "mtls-gen-cert", "mtls-validate-cert", "MTLSChecker"):
        assert symbol in src, f"Expected '{symbol}' in cli.py"


def test_documentation_presence():
    """Key documentation files for mTLS exist and contain expected content."""
    repo_root = os.path.join(os.path.dirname(__file__), "..")

    readme = os.path.join(repo_root, "README.md")
    assert os.path.isfile(readme)
    content = open(readme).read()
    assert "mTLS" in content
    assert "mutual TLS" in content

    api_doc = os.path.join(repo_root, "offsec-ai-docs", "api.md")
    assert os.path.isfile(api_doc)
    content = open(api_doc).read()
    assert "MTLSChecker" in content
    assert "MTLSResult" in content

    examples = os.path.join(repo_root, "examples", "mtls_examples.py")
    assert os.path.isfile(examples)
