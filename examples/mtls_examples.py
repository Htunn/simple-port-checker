#!/usr/bin/env python3
"""
mTLS (Mutual TLS) Authentication Examples

This script demonstrates how to use the Simple Port Checker's mTLS functionality
to check for mutual TLS authentication support on various services.
"""

import asyncio
import json
from pathlib import Path

from simple_port_checker import MTLSChecker
from simple_port_checker.core.mtls_checker import generate_self_signed_cert, validate_certificate_files


async def basic_mtls_check():
    """Basic mTLS support check without client certificates."""
    print("=== Basic mTLS Support Check ===")
    
    checker = MTLSChecker(timeout=10)
    
    # Check some common services
    targets = [
        ("google.com", 443),
        ("github.com", 443),
        ("badssl.com", 443),
    ]
    
    for target, port in targets:
        print(f"\nChecking {target}:{port}...")
        
        result = await checker.check_mtls(target, port)
        
        print(f"  Supports mTLS: {result.supports_mtls}")
        print(f"  Requires client cert: {result.requires_client_cert}")
        print(f"  Client cert requested: {result.client_cert_requested}")
        
        if result.server_cert_info:
            cert = result.server_cert_info
            print(f"  Server cert subject: {cert.subject}")
            print(f"  Server cert issuer: {cert.issuer}")
            print(f"  Valid until: {cert.not_valid_after}")
        
        if result.error_message:
            print(f"  Error: {result.error_message}")


async def mtls_with_client_certificates():
    """Check mTLS with client certificates."""
    print("\n=== mTLS with Client Certificates ===")
    
    # Generate self-signed certificates for testing
    cert_path = "test_client.crt"
    key_path = "test_client.key"
    
    print(f"Generating self-signed certificate...")
    if generate_self_signed_cert("test-client", cert_path, key_path, days=30):
        print(f"✓ Certificate generated: {cert_path}, {key_path}")
        
        # Validate the generated certificates
        is_valid, message = validate_certificate_files(cert_path, key_path)
        print(f"Certificate validation: {message}")
        
        if is_valid:
            # Try mTLS check with client certificates
            checker = MTLSChecker(timeout=10)
            
            # Note: Most public websites don't require client certificates
            # This is for demonstration purposes
            result = await checker.check_mtls(
                "httpbin.org", 
                443, 
                client_cert_path=cert_path,
                client_key_path=key_path
            )
            
            print(f"\nChecking httpbin.org with client cert:")
            print(f"  Handshake successful: {result.handshake_successful}")
            print(f"  TLS version: {result.tls_version}")
            print(f"  Cipher suite: {result.cipher_suite}")
            
            if result.error_message:
                print(f"  Note: {result.error_message}")
        
        # Clean up test certificates
        Path(cert_path).unlink(missing_ok=True)
        Path(key_path).unlink(missing_ok=True)
        print("Test certificates cleaned up")
    else:
        print("Failed to generate certificates")


async def batch_mtls_check():
    """Perform batch mTLS checks on multiple targets."""
    print("\n=== Batch mTLS Check ===")
    
    checker = MTLSChecker(timeout=5)
    
    # List of targets to check
    targets = [
        ("google.com", 443),
        ("github.com", 443),
        ("stackoverflow.com", 443),
        ("aws.amazon.com", 443),
        ("cloudflare.com", 443),
    ]
    
    print(f"Checking {len(targets)} targets for mTLS support...")
    
    results = await checker.batch_check_mtls(
        targets,
        max_concurrent=3
    )
    
    # Display results
    mtls_supported = 0
    client_cert_required = 0
    
    for result in results:
        if isinstance(result, Exception):
            print(f"Error checking target: {result}")
            continue
            
        print(f"\n{result.target}:{result.port}")
        print(f"  Supports mTLS: {result.supports_mtls}")
        print(f"  Requires client cert: {result.requires_client_cert}")
        
        if result.supports_mtls:
            mtls_supported += 1
        if result.requires_client_cert:
            client_cert_required += 1
        
        if result.server_cert_info:
            cert = result.server_cert_info
            print(f"  Cert algorithm: {cert.key_algorithm}")
            if cert.san_dns_names:
                print(f"  SAN DNS: {', '.join(cert.san_dns_names[:3])}")
    
    print(f"\n=== Summary ===")
    print(f"Total targets: {len(results)}")
    print(f"mTLS supported: {mtls_supported}")
    print(f"Client cert required: {client_cert_required}")


async def mtls_certificate_analysis():
    """Analyze server certificates for mTLS-related information."""
    print("\n=== Certificate Analysis ===")
    
    checker = MTLSChecker(timeout=10)
    
    # Check certificates from various services
    targets = [
        "google.com",
        "github.com", 
        "badssl.com",
    ]
    
    for target in targets:
        print(f"\n--- {target} ---")
        
        result = await checker.check_mtls(target, 443)
        
        if result.server_cert_info:
            cert = result.server_cert_info
            print(f"Subject: {cert.subject}")
            print(f"Issuer: {cert.issuer}")
            print(f"Version: {cert.version}")
            print(f"Serial: {cert.serial_number}")
            print(f"Algorithm: {cert.key_algorithm} ({cert.key_size} bits)")
            print(f"Signature: {cert.signature_algorithm}")
            print(f"Valid from: {cert.not_valid_before}")
            print(f"Valid until: {cert.not_valid_after}")
            print(f"Is CA: {cert.is_ca}")
            print(f"Self-signed: {cert.is_self_signed}")
            print(f"SHA256 fingerprint: {cert.fingerprint_sha256}")
            
            if cert.san_dns_names:
                print(f"SAN DNS names: {', '.join(cert.san_dns_names)}")
            if cert.san_ip_addresses:
                print(f"SAN IP addresses: {', '.join(cert.san_ip_addresses)}")
        else:
            print("No certificate information available")


async def save_mtls_results():
    """Demonstrate saving mTLS results to JSON file."""
    print("\n=== Saving Results ===")
    
    checker = MTLSChecker(timeout=5)
    
    targets = [
        ("google.com", 443),
        ("github.com", 443),
    ]
    
    results = await checker.batch_check_mtls(targets)
    
    # Create a results summary
    results_data = {
        "scan_timestamp": "2025-09-17T12:00:00Z",
        "total_targets": len(results),
        "results": [result.dict() if hasattr(result, 'dict') else str(result) for result in results]
    }
    
    # Save to file
    output_file = "mtls_check_results.json"
    with open(output_file, "w") as f:
        json.dump(results_data, f, indent=2)
    
    print(f"Results saved to {output_file}")


async def main():
    """Run all mTLS examples."""
    print("Simple Port Checker - mTLS Examples")
    print("=" * 50)
    
    try:
        await basic_mtls_check()
        await mtls_with_client_certificates()
        await batch_mtls_check()
        await mtls_certificate_analysis()
        await save_mtls_results()
        
        print("\n" + "=" * 50)
        print("All examples completed successfully!")
        
    except Exception as e:
        print(f"Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
