# Simple Port Checker - Python API Documentation

This document provides comprehensive API documentation for using Simple Port Checker as a Python module.

## Installation

```bash
pip install simple-port-checker
```

## Quick Start

```python
import asyncio
from simple_port_checker import PortChecker, L7Detector

async def main():
    # Basic port scanning
    scanner = PortChecker()
    result = await scanner.scan_host("example.com")
    print(f"Open ports: {[p.port for p in result.open_ports]}")
    
    # L7 protection detection
    detector = L7Detector()
    l7_result = await detector.detect("example.com")
    if l7_result.is_protected:
        print(f"Protected by: {l7_result.primary_protection.service.value}")

asyncio.run(main())
```

## Core Classes

### PortChecker

The main class for port scanning operations.

#### Constructor

```python
from simple_port_checker import PortChecker
from simple_port_checker.core.port_scanner import ScanConfig

# Default configuration
scanner = PortChecker()

# Custom configuration
config = ScanConfig(
    timeout=5.0,
    concurrent_limit=100,
    delay_between_requests=0.1
)
scanner = PortChecker(config)
```

#### Methods

##### `scan_host(host, ports=None, timeout=None)`

Scan a single host for open ports.

**Parameters:**
- `host` (str): Target hostname or IP address
- `ports` (List[int], optional): List of ports to scan. Defaults to common ports
- `timeout` (float, optional): Connection timeout in seconds

**Returns:** `ScanResult` object

**Example:**
```python
# Scan common ports
result = await scanner.scan_host("example.com")

# Scan specific ports
result = await scanner.scan_host("example.com", [80, 443, 8080])

# Custom timeout
result = await scanner.scan_host("example.com", timeout=10.0)
```

##### `scan_multiple_hosts(hosts, ports=None, timeout=None)`

Scan multiple hosts concurrently.

**Parameters:**
- `hosts` (List[str]): List of hostnames or IP addresses
- `ports` (List[int], optional): List of ports to scan
- `timeout` (float, optional): Connection timeout in seconds

**Returns:** `List[ScanResult]`

**Example:**
```python
hosts = ["google.com", "github.com", "stackoverflow.com"]
results = await scanner.scan_multiple_hosts(hosts, [80, 443])

for result in results:
    print(f"{result.host}: {len(result.open_ports)} open ports")
```

##### `check_service_version(host, port, service_type=None)`

Get detailed service information for a specific port.

**Parameters:**
- `host` (str): Target hostname or IP address
- `port` (int): Port number to check
- `service_type` (str, optional): Expected service type

**Returns:** `Dict[str, Any]` with service information

**Example:**
```python
service_info = await scanner.check_service_version("example.com", 80, "http")
print(f"Server: {service_info['headers'].get('Server', 'Unknown')}")
```

### L7Detector

The main class for L7 protection detection (WAF, CDN, etc.).

#### Constructor

```python
from simple_port_checker import L7Detector

# Default configuration
detector = L7Detector()

# Custom configuration
detector = L7Detector(
    timeout=15.0,
    user_agent="Custom-Agent/1.0"
)
```

#### Methods

##### `detect(host, port=None, path="/", trace_dns=False)`

Detect L7 protection services on a host.

**Parameters:**
- `host` (str): Target hostname or IP address
- `port` (int, optional): Specific port to check
- `path` (str, optional): URL path to check. Defaults to "/"
- `trace_dns` (bool, optional): Include DNS tracing in detection

**Returns:** `L7Result` object

**Example:**
```python
# Basic detection
result = await detector.detect("cloudflare.com")

# With DNS tracing
result = await detector.detect("example.com", trace_dns=True)

# Specific port and path
result = await detector.detect("example.com", port=8080, path="/api")

if result.is_protected:
    protection = result.primary_protection
    print(f"Service: {protection.service.value}")
    print(f"Confidence: {protection.confidence:.1%}")
    print(f"Indicators: {protection.indicators}")
```

##### `trace_dns(host)`

Perform DNS trace analysis to identify protection services.

**Parameters:**
- `host` (str): Target hostname

**Returns:** `Dict[str, Any]` with DNS trace information

**Example:**
```python
dns_info = await detector.trace_dns("example.com")
print(f"CNAME chain: {dns_info['cname_chain']}")
print(f"Resolved IPs: {dns_info['resolved_ips']}")
```

##### `test_waf_bypass(host, port=None)`

Test for WAF presence using common bypass techniques.

**Parameters:**
- `host` (str): Target hostname
- `port` (int, optional): Port number

**Returns:** `Dict[str, Any]` with WAF test results

**Example:**
```python
waf_results = await detector.test_waf_bypass("example.com")
print(f"WAF detected: {waf_results['waf_detected']}")
print(f"Blocked requests: {len(waf_results['blocked_requests'])}")
```

## Data Models

### ScanResult

Contains the results of a port scan operation.

**Attributes:**
- `host` (str): Target hostname
- `ip_address` (str): Resolved IP address
- `ports` (List[PortResult]): List of port scan results
- `scan_time` (float): Time taken for the scan
- `error` (str, optional): Error message if scan failed

**Properties:**
- `open_ports`: List of open port results
- `closed_ports`: List of closed port results

**Example:**
```python
result = await scanner.scan_host("example.com")
print(f"Host: {result.host}")
print(f"IP: {result.ip_address}")
print(f"Scan time: {result.scan_time:.2f}s")

for port in result.open_ports:
    print(f"Port {port.port}: {port.service}")
```

### PortResult

Contains information about a single port.

**Attributes:**
- `port` (int): Port number
- `is_open` (bool): Whether the port is open
- `service` (str): Service name (e.g., "http", "ssh")
- `banner` (str): Service banner if available
- `error` (str, optional): Error message if applicable

### L7Result

Contains the results of L7 protection detection.

**Attributes:**
- `host` (str): Target hostname
- `url` (str): Full URL that was checked
- `detections` (List[L7Detection]): List of detected protection services
- `response_headers` (Dict[str, str]): HTTP response headers
- `response_time` (float): Response time in seconds
- `status_code` (int, optional): HTTP status code
- `error` (str, optional): Error message if detection failed
- `dns_trace` (Dict[str, Any], optional): DNS trace information

**Properties:**
- `is_protected`: Whether any L7 protection was detected
- `primary_protection`: The protection service with highest confidence

**Example:**
```python
result = await detector.detect("cloudflare.com")
print(f"Protected: {result.is_protected}")

if result.primary_protection:
    protection = result.primary_protection
    print(f"Service: {protection.service.value}")
    print(f"Confidence: {protection.confidence:.1%}")
```

### L7Detection

Information about a detected L7 protection service.

**Attributes:**
- `service` (L7Protection): The protection service type
- `confidence` (float): Confidence level (0.0 to 1.0)
- `indicators` (List[str]): Evidence that led to this detection
- `details` (Dict[str, Any]): Additional detection details

### L7Protection

Enumeration of supported L7 protection services.

**Values:**
- `CLOUDFLARE`: Cloudflare WAF and DDoS Protection
- `AWS_WAF`: Amazon Web Application Firewall
- `AZURE_WAF`: Microsoft Azure Web Application Firewall
- `F5_BIG_IP`: F5 Application Security Manager
- `AKAMAI`: Akamai Web Application Protector
- `IMPERVA`: Imperva SecureSphere WAF
- `SUCURI`: Sucuri Website Firewall
- `FASTLY`: Fastly Edge Security
- `KEYCDN`: KeyCDN Security
- `MAXCDN`: MaxCDN Security
- `INCAPSULA`: Incapsula (now part of Imperva)
- `BARRACUDA`: Barracuda WAF
- `FORTINET`: FortiWeb WAF
- `CITRIX`: Citrix NetScaler
- `RADWARE`: Radware DefensePro
- `AZURE_FRONT_DOOR`: Azure Front Door
- `UNKNOWN`: Unknown protection service

## Configuration

### ScanConfig

Configuration class for port scanning operations.

**Parameters:**
- `timeout` (float): Connection timeout in seconds. Default: 3.0
- `concurrent_limit` (int): Maximum concurrent connections. Default: 100
- `delay_between_requests` (float): Delay between requests in seconds. Default: 0.0

**Example:**
```python
from simple_port_checker.core.port_scanner import ScanConfig

config = ScanConfig(
    timeout=5.0,
    concurrent_limit=50,
    delay_between_requests=0.1
)

scanner = PortChecker(config)
```

## Error Handling

The library raises standard Python exceptions and includes error information in result objects.

```python
try:
    result = await scanner.scan_host("invalid-hostname.local")
    if result.error:
        print(f"Scan error: {result.error}")
        
    l7_result = await detector.detect("example.com")
    if l7_result.error:
        print(f"Detection error: {l7_result.error}")
        
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Common Use Cases

### Security Assessment

```python
async def security_assessment(target):
    scanner = PortChecker()
    detector = L7Detector()
    
    # 1. Port scan
    scan_result = await scanner.scan_host(target)
    print(f"Open ports: {[p.port for p in scan_result.open_ports]}")
    
    # 2. L7 protection check
    l7_result = await detector.detect(target, trace_dns=True)
    if l7_result.is_protected:
        print(f"Protected by: {l7_result.primary_protection.service.value}")
    
    # 3. Service fingerprinting
    for port in scan_result.open_ports[:5]:  # Check first 5 open ports
        service_info = await scanner.check_service_version(
            target, port.port, port.service
        )
        print(f"Port {port.port}: {service_info['service']} {service_info['version']}")
```

### Batch Processing

```python
async def scan_multiple_targets(targets):
    scanner = PortChecker()
    detector = L7Detector()
    
    # Concurrent port scanning
    scan_results = await scanner.scan_multiple_hosts(targets, [80, 443])
    
    # Concurrent L7 detection
    l7_tasks = [detector.detect(target) for target in targets]
    l7_results = await asyncio.gather(*l7_tasks, return_exceptions=True)
    
    # Process results
    for i, target in enumerate(targets):
        scan_result = scan_results[i]
        l7_result = l7_results[i] if not isinstance(l7_results[i], Exception) else None
        
        print(f"\n{target}:")
        print(f"  Open ports: {len(scan_result.open_ports)}")
        if l7_result and l7_result.is_protected:
            print(f"  Protection: {l7_result.primary_protection.service.value}")
```

### Custom Analysis

```python
async def custom_waf_analysis(target):
    detector = L7Detector()
    
    # Standard detection
    result = await detector.detect(target)
    
    # DNS analysis
    dns_info = await detector.trace_dns(target)
    
    # WAF bypass testing (use responsibly!)
    waf_test = await detector.test_waf_bypass(target)
    
    # Combine results
    analysis = {
        'target': target,
        'protection_detected': result.is_protected,
        'protection_services': [d.service.value for d in result.detections],
        'dns_chain': dns_info.get('cname_chain', []),
        'waf_behavior': waf_test['waf_detected']
    }
    
    return analysis
```

## Performance Considerations

- Use `ScanConfig` to tune performance for your network conditions
- The library uses async/await for concurrent operations
- DNS resolution is cached automatically
- Consider rate limiting for large-scale scans
- Use `trace_dns=True` only when needed as it adds overhead

## Best Practices

1. **Always use async/await context**:
   ```python
   async def main():
       scanner = PortChecker()
       result = await scanner.scan_host("example.com")
   
   asyncio.run(main())
   ```

2. **Handle errors gracefully**:
   ```python
   result = await scanner.scan_host("example.com")
   if result.error:
       print(f"Scan failed: {result.error}")
       return
   ```

3. **Use appropriate timeouts**:
   ```python
   config = ScanConfig(timeout=10.0)  # Longer timeout for slow networks
   scanner = PortChecker(config)
   ```

4. **Respect rate limits**:
   ```python
   config = ScanConfig(
       concurrent_limit=20,  # Reduce for rate-limited targets
       delay_between_requests=0.5
   )
   ```

5. **Use specific port lists when possible**:
   ```python
   # Instead of scanning all common ports
   web_ports = [80, 443, 8080, 8443]
   result = await scanner.scan_host("example.com", web_ports)
   ```

## Legal and Ethical Considerations

- Only scan systems you own or have explicit permission to test
- Respect robots.txt and security policies
- Use rate limiting to avoid overwhelming target systems
- Be aware that scanning may trigger security alerts
- Consider using the library in compliance with your organization's security policies
