#!/usr/bin/env python3
"""
Test script for DNS trace functionality.
"""

import asyncio
import dns.resolver
import json

from simple_port_checker.core.l7_detector import L7Detector

async def main():
    """Run DNS trace tests."""
    print("Testing DNS trace...")
    
    # Domains to test
    domains = ["sts-qa.gcc.gov.sg", "extadfs.gic.com.sg", "www.google.com"]
    
    for domain in domains:
        print(f"\n=== Testing {domain} ===")
        
        # Simple DNS lookup using dns.resolver directly
        try:
            print("\nDirect DNS resolution:")
            resolver = dns.resolver.Resolver()
            
            # CNAME lookup
            try:
                cname_answers = resolver.resolve(domain, "CNAME")
                for cname in cname_answers:
                    cname_str = str(cname.target).lower().rstrip('.')
                    print(f"CNAME: {domain} → {cname_str}")
                    
                    # Try to resolve the CNAME target
                    try:
                        a_answers = resolver.resolve(cname_str, "A")
                        for a_record in a_answers:
                            ip_str = str(a_record)
                            print(f"IP: {cname_str} → {ip_str}")
                    except Exception as e:
                        print(f"Failed to resolve CNAME to IP: {e}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                print("No CNAME records found")
                
                # Try direct A record lookup
                try:
                    a_answers = resolver.resolve(domain, "A")
                    for a_record in a_answers:
                        ip_str = str(a_record)
                        print(f"Direct A record: {domain} → {ip_str}")
                except Exception as e:
                    print(f"Failed to resolve A records: {e}")
        except Exception as e:
            print(f"DNS resolution error: {e}")
        
        # Test with our L7Detector
        print("\nUsing L7Detector.detect():")
        detector = L7Detector(timeout=5.0)
        
        try:
            # Execute the trace domain function directly
            detections, dns_trace = await detector._trace_domain_protection(domain)
            print(f"Trace results:\nDetections: {len(detections)}")
            print(f"DNS trace data: {json.dumps(dns_trace, indent=2)}")
            
            # Test the full detect method with our own trace function
            dns_detections, dns_trace = await detector._trace_domain_protection(domain)
            result = await detector.detect(domain)
            
            # Manually check and update the dns_trace field
            print(f"\nFull detection results:")
            print(f"Is protected: {result.is_protected}")
            if result.primary_protection:
                print(f"Primary protection: {result.primary_protection.service.value} ({result.primary_protection.confidence:.1%})")
                
            print(f"DNS trace in result before: {json.dumps(result.dns_trace, indent=2)}")
            
            # Manually update the result for debugging
            result.dns_trace = dns_trace
            print(f"DNS trace in result after manual update: {json.dumps(result.dns_trace, indent=2)}")
        except Exception as e:
            print(f"L7Detector error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
