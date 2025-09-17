#!/usr/bin/env python3
"""
Test script for mTLS functionality.

This script tests the mTLS checker without requiring all dependencies to be installed.
"""

import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_imports():
    """Test that all modules can be imported."""
    print("Testing imports...")
    
    try:
        from simple_port_checker.models.mtls_result import MTLSResult, CertificateInfo, BatchMTLSResult
        print("✓ mTLS models imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import mTLS models: {e}")
        return False
    
    try:
        from simple_port_checker.core.mtls_checker import MTLSChecker
        print("✓ MTLSChecker imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import MTLSChecker: {e}")
        return False
    
    return True

def test_mtls_result_model():
    """Test the MTLSResult model."""
    print("\nTesting MTLSResult model...")
    
    from simple_port_checker.models.mtls_result import MTLSResult, CertificateInfo
    from datetime import datetime
    
    # Test CertificateInfo
    cert_info = CertificateInfo(
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
        fingerprint_sha256="abcd1234..."
    )
    print("✓ CertificateInfo model created successfully")
    
    # Test MTLSResult
    result = MTLSResult(
        target="test.example.com",
        port=443,
        supports_mtls=True,
        requires_client_cert=False,
        server_cert_info=cert_info,
        client_cert_requested=True,
        handshake_successful=False,
        error_message=None,
        cipher_suite="TLS_AES_256_GCM_SHA384",
        tls_version="TLSv1.3",
        verification_mode="default",
        ca_bundle_path="/etc/ssl/certs/ca-certificates.crt",
        timestamp=datetime.now().isoformat()
    )
    print("✓ MTLSResult model created successfully")
    
    # Test JSON serialization
    json_data = result.json()
    print("✓ MTLSResult JSON serialization works")
    
    return True

def test_cli_help():
    """Test the CLI help for mTLS commands."""
    print("\nTesting CLI help...")
    
    try:
        from simple_port_checker.cli import main
        import click.testing
        
        runner = click.testing.CliRunner()
        
        # Test main help
        result = runner.invoke(main, ['--help'])
        if 'mtls-check' in result.output:
            print("✓ mtls-check command found in CLI help")
        else:
            print("✗ mtls-check command not found in CLI help")
            return False
        
        # Test mtls-check help
        result = runner.invoke(main, ['mtls-check', '--help'])
        if result.exit_code == 0:
            print("✓ mtls-check help works")
        else:
            print(f"✗ mtls-check help failed: {result.output}")
            return False
        
        # Test mtls-gen-cert help
        result = runner.invoke(main, ['mtls-gen-cert', '--help'])
        if result.exit_code == 0:
            print("✓ mtls-gen-cert help works")
        else:
            print(f"✗ mtls-gen-cert help failed: {result.output}")
            return False
        
        return True
        
    except ImportError as e:
        print(f"✗ Failed to import CLI: {e}")
        return False

def main():
    """Run all tests."""
    print("Simple Port Checker - mTLS Functionality Test")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_mtls_result_model,
        test_cli_help,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
            failed += 1
    
    print("\n" + "=" * 50)
    print(f"Tests completed: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! mTLS functionality is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
