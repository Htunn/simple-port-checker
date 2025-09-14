"""Example usage of the Simple Port Checker library."""

import asyncio
from simple_port_checker import PortChecker, L7Detector
from simple_port_checker.core.port_scanner import ScanConfig


async def basic_port_scan():
    """Basic port scanning example."""
    print("=== Basic Port Scan ===")

    scanner = PortChecker()
    result = await scanner.scan_host("example.com", [80, 443, 22, 21])

    print(f"Host: {result.host}")
    print(f"IP: {result.ip_address}")
    print(f"Scan time: {result.scan_time:.2f}s")
    print(f"Open ports: {len(result.open_ports)}")

    for port in result.open_ports:
        print(f"  Port {port.port} ({port.service}): {port.banner[:50]}")


async def custom_scan_config():
    """Example with custom scan configuration."""
    print("\n=== Custom Configuration Scan ===")

    config = ScanConfig(timeout=5.0, concurrent_limit=50, delay_between_requests=0.05)
    scanner = PortChecker(config)

    # Scan multiple hosts
    hosts = ["google.com", "github.com", "stackoverflow.com"]
    results = await scanner.scan_multiple_hosts(hosts, [80, 443])

    for result in results:
        print(f"{result.host}: {len(result.open_ports)} open ports")


async def l7_protection_detection():
    """L7 protection detection example."""
    print("\n=== L7 Protection Detection ===")

    detector = L7Detector(timeout=10.0)

    # Check popular sites that likely have L7 protection
    sites = ["cloudflare.com", "github.com", "amazon.com"]

    for site in sites:
        result = await detector.detect(site)

        print(f"\n{site}:")
        if result.error:
            print(f"  Error: {result.error}")
        elif result.is_protected:
            primary = result.primary_protection
            print(f"  Protection: {primary.service.value}")
            print(f"  Confidence: {primary.confidence:.1%}")
            print(f"  Indicators: {', '.join(primary.indicators[:3])}")
        else:
            print("  No L7 protection detected")


async def service_version_detection():
    """Service version detection example."""
    print("\n=== Service Version Detection ===")

    scanner = PortChecker()

    # Check common web servers
    hosts = ["nginx.org", "apache.org", "example.com"]

    for host in hosts:
        try:
            service_info = await scanner.check_service_version(host, 80, "http")

            print(f"\n{host}:")
            print(f"  Service: {service_info['service']}")
            print(f"  Version: {service_info['version']}")
            if service_info.get("headers"):
                server = service_info["headers"].get("Server", "Unknown")
                print(f"  Server: {server}")

        except Exception as e:
            print(f"{host}: Error - {e}")


async def waf_bypass_testing():
    """WAF bypass testing example."""
    print("\n=== WAF Bypass Testing ===")

    detector = L7Detector()

    # Test a site that likely has WAF protection
    test_host = "httpbin.org"  # This is a safe testing site

    try:
        waf_results = await detector.test_waf_bypass(test_host)

        print(f"WAF Detection Results for {test_host}:")
        print(f"  WAF Detected: {waf_results['waf_detected']}")
        print(f"  Blocked Requests: {len(waf_results['blocked_requests'])}")
        print(f"  Successful Requests: {len(waf_results['successful_requests'])}")

        if waf_results["blocked_requests"]:
            print("  Sample blocked payload:")
            blocked = waf_results["blocked_requests"][0]
            print(f"    Payload: {blocked.get('payload', 'N/A')}")
            print(f"    Status: {blocked.get('status', 'N/A')}")

    except Exception as e:
        print(f"WAF testing error: {e}")


async def comprehensive_example():
    """Comprehensive example combining all features."""
    print("\n=== Comprehensive Security Assessment ===")

    target = "example.com"

    # 1. Port scan
    scanner = PortChecker()
    scan_result = await scanner.scan_host(target, [80, 443, 22, 21, 25, 53])

    print(f"Port Scan Results for {target}:")
    print(f"  Open ports: {[p.port for p in scan_result.open_ports]}")

    # 2. L7 detection on web ports
    detector = L7Detector()
    l7_result = await detector.detect(target)

    print(f"\nL7 Protection Analysis:")
    if l7_result.is_protected:
        primary = l7_result.primary_protection
        print(
            f"  Primary Protection: {primary.service.value} ({primary.confidence:.1%})"
        )
    else:
        print("  No L7 protection detected")

    # 3. Service analysis for open ports
    print(f"\nService Analysis:")
    for port_result in scan_result.open_ports[:3]:  # Analyze first 3 open ports
        service_info = await scanner.check_service_version(
            target, port_result.port, port_result.service
        )

        print(f"  Port {port_result.port}:")
        print(f"    Service: {service_info['service']}")
        print(f"    Version: {service_info['version']}")
        if service_info.get("banner"):
            print(f"    Banner: {service_info['banner'][:100]}")


async def main():
    """Run all examples."""
    print("Simple Port Checker - Example Usage\n")

    try:
        await basic_port_scan()
        await custom_scan_config()
        await l7_protection_detection()
        await service_version_detection()
        await waf_bypass_testing()
        await comprehensive_example()

    except KeyboardInterrupt:
        print("\nExample interrupted by user")
    except Exception as e:
        print(f"\nExample error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
