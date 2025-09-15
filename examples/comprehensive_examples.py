"""
Comprehensive examples for Simple Port Checker Python API.

This file demonstrates various use cases and advanced features
of the Simple Port Checker library as a Python module.
"""

import asyncio
import json
import time
from typing import List, Dict, Any
from simple_port_checker import PortChecker, L7Detector, L7Protection, ScanResult, L7Result
from simple_port_checker.core.port_scanner import ScanConfig


# ============================================================================
# Basic Examples
# ============================================================================

async def basic_port_scan():
    """Basic port scanning example."""
    print("=== Basic Port Scan ===")
    
    scanner = PortChecker()
    
    # Scan with default common ports
    result = await scanner.scan_host("httpbin.org")
    print(f"Host: {result.host}")
    print(f"IP: {result.ip_address}")
    print(f"Scan time: {result.scan_time:.2f}s")
    print(f"Open ports: {[p.port for p in result.open_ports]}")
    
    # Show detailed port information
    for port in result.open_ports:
        print(f"  Port {port.port} ({port.service}): {port.banner[:50]}")


async def basic_l7_detection():
    """Basic L7 protection detection example."""
    print("\n=== Basic L7 Protection Detection ===")
    
    detector = L7Detector()
    
    # Check a site with known protection
    result = await detector.detect("cloudflare.com")
    print(f"Host: {result.host}")
    print(f"Protected: {result.is_protected}")
    
    if result.is_protected:
        primary = result.primary_protection
        print(f"Primary protection: {primary.service.value}")
        print(f"Confidence: {primary.confidence:.1%}")
        print(f"Indicators: {', '.join(primary.indicators[:3])}")
    
    # Show all detections
    print(f"All detections: {len(result.detections)}")
    for detection in result.detections:
        print(f"  {detection.service.value}: {detection.confidence:.1%}")


# ============================================================================
# Configuration Examples
# ============================================================================

async def custom_scan_configuration():
    """Example with custom scan configuration."""
    print("\n=== Custom Scan Configuration ===")
    
    # Create custom configuration for slow networks
    config = ScanConfig(
        timeout=10.0,           # Longer timeout
        concurrent_limit=25,    # Fewer concurrent connections
        delay_between_requests=0.2  # Small delay between requests
    )
    
    scanner = PortChecker(config)
    
    # Scan specific ports with custom config
    web_ports = [80, 443, 8080, 8443]
    result = await scanner.scan_host("httpbin.org", web_ports)
    
    print(f"Scanned {len(web_ports)} ports in {result.scan_time:.2f}s")
    print(f"Open ports: {[p.port for p in result.open_ports]}")


async def custom_l7_configuration():
    """Example with custom L7 detector configuration."""
    print("\n=== Custom L7 Detector Configuration ===")
    
    # Custom L7 detector settings
    detector = L7Detector(
        timeout=15.0,
        user_agent="SecurityScanner/1.0 (+https://example.com/bot)"
    )
    
    # Detect with DNS tracing enabled
    result = await detector.detect("github.com", trace_dns=True)
    
    print(f"Detection time: {result.response_time:.2f}s")
    print(f"Status code: {result.status_code}")
    
    if result.dns_trace:
        print(f"DNS trace available: {bool(result.dns_trace.get('cname_chain'))}")


# ============================================================================
# Advanced Examples
# ============================================================================

async def comprehensive_security_scan():
    """Comprehensive security assessment of a target."""
    print("\n=== Comprehensive Security Assessment ===")
    
    target = "httpbin.org"
    
    # Initialize scanners
    scanner = PortChecker()
    detector = L7Detector()
    
    print(f"Analyzing {target}...")
    
    # 1. Port scan
    print("  1. Port scanning...")
    scan_result = await scanner.scan_host(target)
    
    # 2. L7 protection detection with DNS tracing
    print("  2. L7 protection detection...")
    l7_result = await detector.detect(target, trace_dns=True)
    
    # 3. Service fingerprinting for open ports
    print("  3. Service fingerprinting...")
    service_details = {}
    for port_result in scan_result.open_ports[:5]:  # Limit to first 5 ports
        try:
            service_info = await scanner.check_service_version(
                target, port_result.port, port_result.service
            )
            service_details[port_result.port] = service_info
        except Exception as e:
            print(f"    Service check failed for port {port_result.port}: {e}")
    
    # 4. WAF testing (if L7 protection detected)
    waf_results = None
    if l7_result.is_protected:
        print("  4. WAF bypass testing...")
        try:
            waf_results = await detector.test_waf_bypass(target)
        except Exception as e:
            print(f"    WAF testing failed: {e}")
    
    # Generate report
    report = {
        "target": target,
        "scan_timestamp": time.time(),
        "port_scan": {
            "total_ports_scanned": len(scan_result.ports),
            "open_ports": [p.port for p in scan_result.open_ports],
            "scan_time": scan_result.scan_time
        },
        "l7_protection": {
            "is_protected": l7_result.is_protected,
            "detections": [
                {
                    "service": d.service.value,
                    "confidence": d.confidence,
                    "indicators": d.indicators[:3]  # First 3 indicators
                }
                for d in l7_result.detections
            ],
            "response_time": l7_result.response_time
        },
        "service_details": service_details,
        "waf_testing": waf_results
    }
    
    print("\n=== Security Assessment Report ===")
    print(json.dumps(report, indent=2, default=str))


async def batch_scanning():
    """Batch scanning multiple targets efficiently."""
    print("\n=== Batch Scanning Example ===")
    
    targets = [
        "httpbin.org",
        "example.com", 
        "github.com",
        "stackoverflow.com"
    ]
    
    scanner = PortChecker()
    detector = L7Detector()
    
    print(f"Scanning {len(targets)} targets...")
    
    # Concurrent port scanning
    print("  Running port scans...")
    scan_tasks = [
        scanner.scan_host(target, [80, 443, 22])
        for target in targets
    ]
    scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
    
    # Concurrent L7 detection
    print("  Running L7 detection...")
    l7_tasks = [
        detector.detect(target)
        for target in targets
    ]
    l7_results = await asyncio.gather(*l7_tasks, return_exceptions=True)
    
    # Process results
    print("\n=== Batch Results ===")
    for i, target in enumerate(targets):
        print(f"\n{target}:")
        
        # Port scan results
        scan_result = scan_results[i]
        if isinstance(scan_result, Exception):
            print(f"  Port scan failed: {scan_result}")
        else:
            print(f"  Open ports: {[p.port for p in scan_result.open_ports]}")
        
        # L7 detection results
        l7_result = l7_results[i]
        if isinstance(l7_result, Exception):
            print(f"  L7 detection failed: {l7_result}")
        elif l7_result.is_protected:
            primary = l7_result.primary_protection
            print(f"  Protection: {primary.service.value} ({primary.confidence:.1%})")
        else:
            print("  No L7 protection detected")


async def dns_analysis_example():
    """Advanced DNS analysis and tracing."""
    print("\n=== DNS Analysis Example ===")
    
    detector = L7Detector()
    
    targets = ["cloudflare.com", "github.com", "stackoverflow.com"]
    
    for target in targets:
        print(f"\nAnalyzing DNS for {target}:")
        
        # Get DNS trace information
        dns_info = await detector.trace_dns(target)
        
        # Display CNAME chain
        if dns_info.get('cname_chain'):
            print("  CNAME chain:")
            for cname in dns_info['cname_chain']:
                print(f"    {cname['from']} → {cname['to']} (depth: {cname['depth']})")
        else:
            print("  No CNAME records found")
        
        # Display resolved IPs
        if dns_info.get('resolved_ips'):
            print("  Resolved IPs:")
            for hostname, ips in dns_info['resolved_ips'].items():
                print(f"    {hostname}: {', '.join(ips)}")
        
        # Display IP protection analysis
        if dns_info.get('ip_protection'):
            print("  IP protection analysis:")
            for ip, protection in dns_info['ip_protection'].items():
                if protection.get('service') != 'none':
                    service = protection['service']
                    confidence = protection['confidence']
                    print(f"    {ip}: {service} ({confidence:.1%})")


async def service_fingerprinting():
    """Detailed service version detection and fingerprinting."""
    print("\n=== Service Fingerprinting Example ===")
    
    scanner = PortChecker()
    
    # Common web services to check
    targets = [
        ("httpbin.org", 80, "http"),
        ("httpbin.org", 443, "https"),
        ("github.com", 443, "https"),
    ]
    
    for hostname, port, service_type in targets:
        print(f"\nFingerprinting {hostname}:{port} ({service_type})")
        
        try:
            service_info = await scanner.check_service_version(
                hostname, port, service_type
            )
            
            print(f"  Service: {service_info['service']}")
            print(f"  Version: {service_info['version']}")
            
            if service_info.get('headers'):
                headers = service_info['headers']
                print(f"  Server: {headers.get('Server', 'Unknown')}")
                print(f"  Powered by: {headers.get('X-Powered-By', 'Unknown')}")
                
            if service_info.get('banner'):
                banner = service_info['banner'][:100]
                print(f"  Banner: {banner}")
                
        except Exception as e:
            print(f"  Fingerprinting failed: {e}")


async def waf_testing_example():
    """WAF detection and bypass testing example."""
    print("\n=== WAF Testing Example ===")
    
    detector = L7Detector()
    
    # Test sites (use only sites you own or have permission to test)
    test_targets = ["httpbin.org"]  # Safe testing endpoint
    
    for target in test_targets:
        print(f"\nTesting WAF on {target}:")
        
        # Standard L7 detection first
        l7_result = await detector.detect(target)
        print(f"  L7 protection detected: {l7_result.is_protected}")
        
        if l7_result.is_protected:
            primary = l7_result.primary_protection
            print(f"  Primary protection: {primary.service.value}")
        
        # WAF bypass testing
        try:
            waf_results = await detector.test_waf_bypass(target)
            
            print(f"  WAF behavior analysis:")
            print(f"    WAF detected: {waf_results['waf_detected']}")
            print(f"    Blocked requests: {len(waf_results['blocked_requests'])}")
            print(f"    Successful requests: {len(waf_results['successful_requests'])}")
            
            # Show sample blocked request
            if waf_results['blocked_requests']:
                blocked = waf_results['blocked_requests'][0]
                print(f"    Sample blocked payload: {blocked.get('payload', 'N/A')}")
                print(f"    Response status: {blocked.get('status', 'N/A')}")
                
        except Exception as e:
            print(f"  WAF testing failed: {e}")


# ============================================================================
# Error Handling Examples
# ============================================================================

async def error_handling_example():
    """Demonstrate proper error handling."""
    print("\n=== Error Handling Example ===")
    
    scanner = PortChecker()
    detector = L7Detector()
    
    # Test with invalid hostname
    print("Testing with invalid hostname:")
    result = await scanner.scan_host("invalid-hostname-12345.local")
    if result.error:
        print(f"  Scan error (expected): {result.error}")
    
    # Test with unreachable host
    print("\nTesting L7 detection on unreachable host:")
    l7_result = await detector.detect("192.0.2.1")  # TEST-NET-1 address
    if l7_result.error:
        print(f"  L7 detection error (expected): {l7_result.error}")
    
    # Test with connection timeout
    print("\nTesting with very short timeout:")
    config = ScanConfig(timeout=0.001)  # Extremely short timeout
    short_scanner = PortChecker(config)
    
    result = await short_scanner.scan_host("httpbin.org", [80])
    closed_ports = [p for p in result.ports if not p.is_open]
    if closed_ports:
        print(f"  Timeout caused ports to appear closed (expected)")


# ============================================================================
# Performance Examples
# ============================================================================

async def performance_comparison():
    """Compare different configuration performances."""
    print("\n=== Performance Comparison ===")
    
    target = "httpbin.org"
    ports = [80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143]
    
    # Test different configurations
    configs = [
        ("Default", ScanConfig()),
        ("High Concurrency", ScanConfig(concurrent_limit=200, timeout=2.0)),
        ("Conservative", ScanConfig(concurrent_limit=10, timeout=5.0, delay_between_requests=0.1)),
    ]
    
    for config_name, config in configs:
        scanner = PortChecker(config)
        
        start_time = time.time()
        result = await scanner.scan_host(target, ports)
        end_time = time.time()
        
        print(f"  {config_name}:")
        print(f"    Scan time: {result.scan_time:.2f}s")
        print(f"    Total time: {end_time - start_time:.2f}s")
        print(f"    Open ports: {len(result.open_ports)}")


# ============================================================================
# Custom Analysis Examples
# ============================================================================

async def custom_security_analysis():
    """Custom security analysis combining multiple data sources."""
    print("\n=== Custom Security Analysis ===")
    
    target = "github.com"
    
    scanner = PortChecker()
    detector = L7Detector()
    
    # Gather comprehensive data
    print(f"Performing comprehensive analysis of {target}...")
    
    # 1. Basic port scan
    scan_result = await scanner.scan_host(target, [22, 80, 443, 9418])  # Include git port
    
    # 2. L7 detection with DNS tracing
    l7_result = await detector.detect(target, trace_dns=True)
    
    # 3. DNS analysis
    dns_info = await detector.trace_dns(target)
    
    # 4. Service analysis for each open port
    service_analysis = {}
    for port_result in scan_result.open_ports:
        try:
            service_info = await scanner.check_service_version(
                target, port_result.port, port_result.service
            )
            service_analysis[port_result.port] = service_info
        except Exception as e:
            service_analysis[port_result.port] = {"error": str(e)}
    
    # Custom analysis logic
    security_score = 0
    recommendations = []
    
    # Analyze L7 protection
    if l7_result.is_protected:
        security_score += 30
        primary = l7_result.primary_protection
        recommendations.append(f"Good: Protected by {primary.service.value}")
    else:
        recommendations.append("Consider: No L7 protection detected")
    
    # Analyze open ports
    sensitive_ports = [22, 21, 23, 25, 110, 143, 993, 995]
    exposed_sensitive = [p.port for p in scan_result.open_ports if p.port in sensitive_ports]
    
    if exposed_sensitive:
        recommendations.append(f"Review: Sensitive ports exposed: {exposed_sensitive}")
    else:
        security_score += 20
    
    # Analyze HTTPS availability
    https_available = any(p.port == 443 for p in scan_result.open_ports)
    if https_available:
        security_score += 25
        recommendations.append("Good: HTTPS is available")
    
    # Analyze DNS configuration
    if dns_info.get('cname_chain'):
        security_score += 15
        recommendations.append("Good: Using CDN/proxy (CNAME detected)")
    
    # Generate custom report
    analysis_report = {
        "target": target,
        "security_score": min(security_score, 100),
        "risk_level": "Low" if security_score >= 70 else "Medium" if security_score >= 40 else "High",
        "open_ports": [p.port for p in scan_result.open_ports],
        "l7_protection": {
            "protected": l7_result.is_protected,
            "services": [d.service.value for d in l7_result.detections]
        },
        "dns_analysis": {
            "cname_chain": len(dns_info.get('cname_chain', [])),
            "ip_count": len(dns_info.get('resolved_ips', {}))
        },
        "recommendations": recommendations,
        "service_analysis": service_analysis
    }
    
    print("\n=== Custom Security Analysis Report ===")
    print(json.dumps(analysis_report, indent=2, default=str))


# ============================================================================
# Main Example Runner
# ============================================================================

async def main():
    """Run all examples."""
    print("Simple Port Checker - Comprehensive Python API Examples")
    print("=" * 60)
    
    try:
        # Basic examples
        await basic_port_scan()
        await basic_l7_detection()
        
        # Configuration examples
        await custom_scan_configuration()
        await custom_l7_configuration()
        
        # Advanced examples
        await comprehensive_security_scan()
        await batch_scanning()
        await dns_analysis_example()
        await service_fingerprinting()
        await waf_testing_example()
        
        # Error handling
        await error_handling_example()
        
        # Performance comparison
        await performance_comparison()
        
        # Custom analysis
        await custom_security_analysis()
        
    except KeyboardInterrupt:
        print("\nExamples interrupted by user")
    except Exception as e:
        print(f"\nExample error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
