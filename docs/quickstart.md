# Simple Port Checker - Quick Start Guide

## Installation

```bash
pip install simple-port-checker
```

## Basic Usage

### Command Line

```bash
# Basic port scan
port-checker scan example.com

# Scan specific ports
port-checker scan example.com --ports 80,443,8080

# Check L7 protection
port-checker l7-check example.com

# Full scan
port-checker full-scan example.com --output results.json
```

### Python API

```python
import asyncio
from simple_port_checker import PortChecker, L7Detector

async def main():
    # Port scanning
    scanner = PortChecker()
    result = await scanner.scan_host("example.com", [80, 443, 22])
    
    print(f"Open ports: {[p.port for p in result.open_ports]}")
    
    # L7 protection detection
    detector = L7Detector()
    l7_result = await detector.detect("example.com")
    
    if l7_result.is_protected:
        protection = l7_result.primary_protection
        print(f"Protection: {protection.service.value} ({protection.confidence:.1%})")

asyncio.run(main())
```

## Configuration

Create `~/.port-checker.yaml`:

```yaml
default_ports: [80, 443, 8080, 8443, 22, 21, 25, 53]
timeout: 5
concurrent_limit: 50
user_agent: "SimplePortChecker/1.0"
```

## Advanced Features

### Batch Scanning

```python
hosts = ["example.com", "google.com", "github.com"]
results = await scanner.scan_multiple_hosts(hosts, [80, 443])

for result in results:
    print(f"{result.host}: {len(result.open_ports)} open ports")
```

### Service Detection

```python
service_info = await scanner.check_service_version("example.com", 80)
print(f"Server: {service_info['version']}")
```

### WAF Testing

```python
waf_results = await detector.test_waf_bypass("example.com")
print(f"WAF detected: {waf_results['waf_detected']}")
```

## Output Formats

### JSON Output

```bash
port-checker scan example.com --output scan_results.json
```

### Programmatic Access

```python
# Save to file
result.save_to_file("results.json")

# Convert to dict
data = result.to_dict()

# Get JSON string
json_str = result.to_json(indent=2)
```

## Security Considerations

- Only scan systems you own or have explicit permission to test
- Be mindful of rate limiting and network policies
- Some scans may trigger security alerts
- Use responsibly for legitimate security testing only

## Troubleshooting

### Common Issues

1. **DNS Resolution Errors**
   ```bash
   # Check if hostname resolves
   nslookup example.com
   ```

2. **Connection Timeouts**
   ```bash
   # Increase timeout
   port-checker scan example.com --timeout 10
   ```

3. **Rate Limiting**
   ```bash
   # Reduce concurrency
   port-checker scan example.com --concurrent 10
   ```

### Debug Mode

```bash
port-checker scan example.com --verbose
```

## Examples

See the `examples/` directory for complete usage examples:
- `usage_examples.py` - Comprehensive examples
- `batch_scanning.py` - Batch scanning multiple targets
- `custom_config.py` - Custom configuration examples
