#!/usr/bin/env python3
"""
Simple test for mTLS functionality without full installation.
"""

import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_mtls_model():
    """Test the MTLSResult model directly."""
    print("Testing mTLS models...")
    
    try:
        from simple_port_checker.models.mtls_result import MTLSResult, CertificateInfo
        from datetime import datetime
        
        # Create a test certificate info
        cert_info = CertificateInfo(
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
            fingerprint_sha256="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
        )
        print("✓ CertificateInfo created successfully")
        
        # Create a test mTLS result
        mtls_result = MTLSResult(
            target="test.example.com",
            port=443,
            supports_mtls=True,
            requires_client_cert=True,
            server_cert_info=cert_info,
            client_cert_requested=True,
            handshake_successful=True,
            error_message=None,
            cipher_suite="TLS_AES_256_GCM_SHA384",
            tls_version="TLSv1.3",
            verification_mode="strict",
            ca_bundle_path="/etc/ssl/certs/ca-certificates.crt",
            timestamp=datetime.now().isoformat()
        )
        print("✓ MTLSResult created successfully")
        
        # Test JSON serialization
        json_str = mtls_result.json(indent=2)
        print("✓ JSON serialization works")
        print(f"JSON length: {len(json_str)} characters")
        
        # Test field access
        print(f"✓ Target: {mtls_result.target}")
        print(f"✓ Supports mTLS: {mtls_result.supports_mtls}")
        print(f"✓ Server cert subject: {mtls_result.server_cert_info.subject}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_cli_structure():
    """Test if CLI structure includes mTLS commands."""
    print("\nTesting CLI structure...")
    
    try:
        # Read the CLI file to check for mTLS commands
        cli_file = os.path.join(os.path.dirname(__file__), 'src', 'simple_port_checker', 'cli.py')
        
        with open(cli_file, 'r') as f:
            cli_content = f.read()
        
        # Check for mTLS command definitions
        mtls_commands = [
            'mtls-check',
            'mtls-gen-cert', 
            'mtls-validate-cert',
            '_run_mtls_check',
            'MTLSChecker'
        ]
        
        found_commands = []
        for cmd in mtls_commands:
            if cmd in cli_content:
                found_commands.append(cmd)
                print(f"✓ Found {cmd} in CLI")
            else:
                print(f"✗ Missing {cmd} in CLI")
        
        if len(found_commands) == len(mtls_commands):
            print("✓ All mTLS commands found in CLI")
            return True
        else:
            print(f"✗ Only {len(found_commands)}/{len(mtls_commands)} commands found")
            return False
            
    except Exception as e:
        print(f"✗ Error checking CLI: {e}")
        return False

def test_documentation():
    """Test if documentation includes mTLS information."""
    print("\nTesting documentation...")
    
    try:
        # Check README
        readme_file = os.path.join(os.path.dirname(__file__), 'README.md')
        with open(readme_file, 'r') as f:
            readme_content = f.read()
        
        if 'mTLS' in readme_content and 'mutual TLS' in readme_content:
            print("✓ README includes mTLS documentation")
        else:
            print("✗ README missing mTLS documentation")
            return False
        
        # Check API docs
        api_docs_file = os.path.join(os.path.dirname(__file__), 'docs', 'api.md')
        with open(api_docs_file, 'r') as f:
            api_content = f.read()
        
        if 'MTLSChecker' in api_content and 'MTLSResult' in api_content:
            print("✓ API docs include mTLS documentation")
        else:
            print("✗ API docs missing mTLS documentation")
            return False
        
        # Check examples
        examples_file = os.path.join(os.path.dirname(__file__), 'examples', 'mtls_examples.py')
        if os.path.exists(examples_file):
            print("✓ mTLS examples file exists")
        else:
            print("✗ mTLS examples file missing")
            return False
        
        return True
        
    except Exception as e:
        print(f"✗ Error checking documentation: {e}")
        return False

def main():
    """Run all tests."""
    print("Simple Port Checker - mTLS Integration Test")
    print("=" * 50)
    
    tests = [
        test_mtls_model,
        test_cli_structure,
        test_documentation,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
            results.append(False)
    
    passed = sum(results)
    total = len(results)
    
    print("\n" + "=" * 50)
    print(f"Tests completed: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed! mTLS functionality has been successfully integrated.")
        print("\nNext steps:")
        print("1. Install dependencies: pip install cryptography certifi")
        print("2. Test CLI: port-checker mtls-check --help")
        print("3. Try example: python examples/mtls_examples.py")
        return 0
    else:
        print("❌ Some tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
