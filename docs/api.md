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

### MTLSChecker

Class for checking mTLS (Mutual TLS) authentication support and requirements.

#### Constructor

```python
from simple_port_checker import MTLSChecker

# Default configuration
checker = MTLSChecker()

# Custom configuration
checker = MTLSChecker(timeout=10, verify_ssl=True)
```

**Parameters:**
- `timeout` (int): Connection timeout in seconds (default: 10)
- `verify_ssl` (bool): Whether to verify SSL certificates (default: True)

#### Methods

##### `check_mtls(target, port=443, client_cert_path=None, client_key_path=None, ca_bundle_path=None)`

Check if target supports mTLS authentication.

**Parameters:**
- `target` (str): Target hostname or IP address
- `port` (int): Target port (default: 443)
- `client_cert_path` (str, optional): Path to client certificate file (PEM format)
- `client_key_path` (str, optional): Path to client private key file (PEM format)
- `ca_bundle_path` (str, optional): Path to CA bundle file

**Returns:** `MTLSResult` object

**Example:**
```python
# Basic mTLS check
result = await checker.check_mtls("example.com")
print(f"Supports mTLS: {result.supports_mtls}")
print(f"Requires client cert: {result.requires_client_cert}")

# With client certificates
result = await checker.check_mtls(
    "example.com", 
    client_cert_path="client.crt",
    client_key_path="client.key"
)
print(f"Handshake successful: {result.handshake_successful}")
print(f"TLS version: {result.tls_version}")
```

##### `batch_check_mtls(targets, client_cert_path=None, client_key_path=None, ca_bundle_path=None, max_concurrent=10)`

Perform mTLS checks on multiple targets concurrently.

**Parameters:**
- `targets` (List[Tuple[str, int]]): List of (hostname, port) tuples
- `client_cert_path` (str, optional): Path to client certificate file
- `client_key_path` (str, optional): Path to client private key file
- `ca_bundle_path` (str, optional): Path to CA bundle file
- `max_concurrent` (int): Maximum concurrent connections (default: 10)

**Returns:** `List[MTLSResult]`

**Example:**
```python
targets = [
    ("example.com", 443),
    ("test.example.com", 8443),
]

results = await checker.batch_check_mtls(targets)
for result in results:
    print(f"{result.target}:{result.port} - mTLS: {result.supports_mtls}")
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

### MTLSResult

Contains the results of mTLS authentication checks.

**Attributes:**
- `target` (str): Target hostname or IP address
- `port` (int): Target port number
- `supports_mtls` (bool): Whether the target supports mTLS
- `requires_client_cert` (bool): Whether client certificate is required
- `server_cert_info` (CertificateInfo, optional): Server certificate information
- `client_cert_requested` (bool): Whether server requests client certificate
- `handshake_successful` (bool): Whether mTLS handshake was successful
- `error_message` (str, optional): Error message if check failed
- `cipher_suite` (str, optional): Cipher suite used in successful connection
- `tls_version` (str, optional): TLS version used
- `verification_mode` (str, optional): Certificate verification mode
- `ca_bundle_path` (str, optional): Path to CA bundle used
- `timestamp` (str): Timestamp of the check

**Example:**
```python
result = await checker.check_mtls("example.com")
print(f"mTLS supported: {result.supports_mtls}")
print(f"Client cert required: {result.requires_client_cert}")

if result.server_cert_info:
    cert = result.server_cert_info
    print(f"Server cert subject: {cert.subject}")
    print(f"Valid until: {cert.not_valid_after}")
```

### CertificateInfo

Information about an X.509 certificate.

**Attributes:**
- `subject` (str): Certificate subject DN
- `issuer` (str): Certificate issuer DN
- `version` (int): Certificate version
- `serial_number` (str): Certificate serial number
- `not_valid_before` (str): Certificate validity start date
- `not_valid_after` (str): Certificate validity end date
- `signature_algorithm` (str): Signature algorithm used
- `key_algorithm` (str): Public key algorithm
- `key_size` (int, optional): Public key size in bits
- `san_dns_names` (List[str]): Subject Alternative Name DNS entries
- `san_ip_addresses` (List[str]): Subject Alternative Name IP entries
- `is_ca` (bool): Whether this is a CA certificate
- `is_self_signed` (bool): Whether this is a self-signed certificate
- `fingerprint_sha256` (str): SHA-256 fingerprint of the certificate

**Example:**
```python
if result.server_cert_info:
    cert = result.server_cert_info
    print(f"Subject: {cert.subject}")
    print(f"Algorithm: {cert.key_algorithm} ({cert.key_size} bits)")
    print(f"SAN DNS: {', '.join(cert.san_dns_names)}")
    print(f"Fingerprint: {cert.fingerprint_sha256}")
```

### BatchMTLSResult

Contains the results of batch mTLS checks.

**Attributes:**
- `results` (List[MTLSResult]): Individual mTLS check results
- `total_targets` (int): Total number of targets checked
- `successful_checks` (int): Number of successful checks
- `failed_checks` (int): Number of failed checks
- `mtls_supported_count` (int): Number of targets supporting mTLS
- `mtls_required_count` (int): Number of targets requiring client certificates
- `timestamp` (str): Batch operation timestamp

**Example:**
```python
batch_result = BatchMTLSResult.from_results(results)
print(f"Total: {batch_result.total_targets}")
print(f"mTLS supported: {batch_result.mtls_supported_count}")
print(f"Success rate: {batch_result.successful_checks / batch_result.total_targets:.1%}")
```

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

### mTLS Authentication Testing

```python
async def mtls_security_assessment(targets):
    checker = MTLSChecker(timeout=10)
    
    # Batch check for mTLS support
    target_ports = [(target, 443) for target in targets]
    results = await checker.batch_check_mtls(target_ports)
    
    for result in results:
        print(f"\n{result.target}:{result.port}")
        print(f"  Supports mTLS: {result.supports_mtls}")
        print(f"  Requires client cert: {result.requires_client_cert}")
        
        if result.server_cert_info:
            cert = result.server_cert_info
            print(f"  Certificate issuer: {cert.issuer}")
            print(f"  Key algorithm: {cert.key_algorithm} ({cert.key_size} bits)")
            
        if result.error_message:
            print(f"  Error: {result.error_message}")

# Generate test certificates
from simple_port_checker.core.mtls_checker import generate_self_signed_cert

async def test_with_client_certs(target):
    # Generate certificates for testing
    cert_path = "test_client.crt"
    key_path = "test_client.key"
    
    if generate_self_signed_cert("test-client", cert_path, key_path):
        checker = MTLSChecker()
        
        # Test with client certificates
        result = await checker.check_mtls(
            target,
            client_cert_path=cert_path,
            client_key_path=key_path
        )
        
        print(f"mTLS handshake successful: {result.handshake_successful}")
        print(f"TLS version: {result.tls_version}")
        print(f"Cipher suite: {result.cipher_suite}")
        
        # Clean up
        Path(cert_path).unlink(missing_ok=True)
        Path(key_path).unlink(missing_ok=True)
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
