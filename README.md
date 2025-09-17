# Simple Port Checker

A comprehensive Python tool for checking firewall ports, detecting L7 protection services (WAF, CDN, etc.), and testing mTLS authentication.

## Features

- ✅ **Port Scanning**: Check well-known firewall ports and services
- 🛡️ **L7 Protection Detection**: Identify WAF/CDN services (F5, AWS WAF, Azure, Cloudflare, etc.)
- 🔐 **mTLS Authentication**: Check mutual TLS support and certificate requirements
- 🌐 **DNS Trace**: Advanced DNS CNAME chain analysis and IP protection detection
- 🚀 **Async Support**: High-performance concurrent scanning
- 📊 **Rich Output**: Beautiful terminal output with progress bars
- 🔧 **Unified CLI**: All functionality accessible through a single command interface
- 📦 **Pip Installable**: Available on PyPI
- 🐍 **Type Hints**: Full type hint support for better IDE integration
- 🏗️ **Production Ready**: Follows Python packaging best practices

## Installation

### From PyPI (recommended)
```bash
pip install simple-port-checker
```

### From Source
```bash
git clone https://github.com/htunn/simple-port-checker.git
cd simple-port-checker
pip install -e .
```

## Quick Start

### Command Line Usage

```bash
# Basic port scan
port-checker scan example.com

# Scan specific ports
port-checker scan example.com --ports 80,443,8080

# Check L7 protection
port-checker l7-check example.com

# DNS trace analysis
port-checker dns-trace example.com

# L7 check with DNS tracing
port-checker l7-check example.com --trace-dns

# Full scan with L7 detection
port-checker full-scan example.com

# Scan multiple targets
port-checker scan example.com google.com --output results.json

# Run as Python module
python -m simple_port_checker scan example.com

# Check mTLS support
port-checker mtls-check example.com

# Check mTLS with client certificates
port-checker mtls-check example.com --client-cert client.crt --client-key client.key

# Generate test certificates for mTLS testing
port-checker mtls-gen-cert test-client.example.com

# Validate certificate files
port-checker mtls-validate-cert client.crt client.key

# Check multiple targets for mTLS support
port-checker mtls-check example.com test.example.com --concurrent 5
```

### Python API Usage

```python
import asyncio
from simple_port_checker import PortChecker, L7Detector

# Initialize scanner
scanner = PortChecker()

async def main():
    # Scan ports
    results = await scanner.scan_host("blog.htunnthuthu.tech", ports=[80, 443, 8080])
    print(f"Open ports: {len([p for p in results.ports if p.is_open])}")

    # Detect L7 protection
    detector = L7Detector()
    protection = await detector.detect("blog.htunnthuthu.tech")
    if protection.primary_protection:
        service = protection.primary_protection.service.value
        confidence = protection.primary_protection.confidence
        print(f"L7 Protection: {service} ({confidence:.0%})")
    else:
        print("No L7 protection detected")

# Run the async function
asyncio.run(main())
```

### mTLS Authentication Checking

```python
import asyncio
from simple_port_checker import MTLSChecker

async def check_mtls():
    checker = MTLSChecker()
    
    # Basic mTLS support check
    result = await checker.check_mtls("example.com")
    print(f"Supports mTLS: {result.supports_mtls}")
    print(f"Requires client cert: {result.requires_client_cert}")
    
    # Check with client certificates
    result = await checker.check_mtls(
        "example.com", 
        client_cert_path="client.crt",
        client_key_path="client.key"
    )
    print(f"Handshake successful: {result.handshake_successful}")
    
    # Batch check multiple targets
    targets = [("example.com", 443), ("test.com", 8443)]
    results = await checker.batch_check_mtls(targets)
    
    for result in results:
        print(f"{result.target}: mTLS={result.supports_mtls}")

asyncio.run(check_mtls())
```

# mTLS Authentication Checking

## Overview

The mTLS (Mutual TLS) feature provides comprehensive testing and validation of mutual TLS authentication configurations. This is essential for:

- **🔒 Zero Trust Security**: Verify mutual authentication in zero-trust architectures
- **📋 Compliance Audits**: Ensure mTLS requirements are properly implemented
- **🛡️ API Security**: Test client certificate authentication for APIs
- **🔍 Security Assessments**: Identify services requiring mutual authentication
- **📊 Certificate Management**: Analyze and validate certificate configurations

## mTLS Command Line Usage

### Basic mTLS Checking

```bash
# Check if a service supports mTLS
port-checker mtls-check api.example.com

# Check mTLS on custom port
port-checker mtls-check api.example.com --port 8443

# Check with verbose output for detailed information
port-checker mtls-check api.example.com --verbose

# Check multiple targets concurrently
port-checker mtls-check api1.example.com api2.example.com --concurrent 10

# Save results to JSON
port-checker mtls-check api.example.com --output mtls-results.json
```

### Client Certificate Authentication

```bash
# Generate test certificates for mTLS testing
port-checker mtls-gen-cert client.example.com
# Creates: client.crt and client.key

# Validate certificate and key files
port-checker mtls-validate-cert client.crt client.key

# Test mTLS with client certificates
port-checker mtls-check api.example.com \
  --client-cert client.crt \
  --client-key client.key

# Test with custom CA bundle
port-checker mtls-check api.example.com \
  --client-cert client.crt \
  --client-key client.key \
  --ca-bundle /path/to/ca-bundle.pem
```

### Advanced Options

```bash
# Disable SSL verification (for testing)
port-checker mtls-check internal-api.company.com --no-verify

# Custom timeout and concurrency
port-checker mtls-check api.example.com \
  --timeout 30 \
  --concurrent 5

# Batch check with different configurations
port-checker mtls-check \
  api1.example.com:443 \
  api2.example.com:8443 \
  internal.example.com:9443 \
  --client-cert client.crt \
  --client-key client.key \
  --verbose \
  --output comprehensive-mtls-audit.json
```

## mTLS Python API Usage

```python
import asyncio
from simple_port_checker import MTLSChecker

async def basic_mtls_check():
    """Basic mTLS support checking."""
    checker = MTLSChecker(timeout=10)
    
    # Check single target
    result = await checker.check_mtls("api.example.com")
    
    print(f"Target: {result.target}:{result.port}")
    print(f"Supports mTLS: {result.supports_mtls}")
    print(f"Requires client cert: {result.requires_client_cert}")
    print(f"Handshake successful: {result.handshake_successful}")
    
    if result.server_cert_info:
        cert = result.server_cert_info
        print(f"Server cert: {cert.subject}")
        print(f"Valid until: {cert.not_valid_after}")

async def mtls_with_client_certs():
    """mTLS testing with client certificates."""
    checker = MTLSChecker()
    
    # Test with client certificates
    result = await checker.check_mtls(
        "api.example.com",
        client_cert_path="client.crt",
        client_key_path="client.key"
    )
    
    print(f"mTLS handshake: {'✓' if result.handshake_successful else '✗'}")
    print(f"TLS version: {result.tls_version}")
    print(f"Cipher suite: {result.cipher_suite}")

async def batch_mtls_check():
    """Batch mTLS checking with progress tracking."""
    checker = MTLSChecker()
    
    targets = [
        "api1.example.com",
        "api2.example.com", 
        ("internal-api.company.com", 8443)
    ]
    
    def progress_callback(completed, total, result):
        print(f"Progress: {completed}/{total} - {result.target}: {result.supports_mtls}")
    
    results = await checker.batch_check_mtls(
        targets,
        max_concurrent=5,
        progress_callback=progress_callback
    )
    
    # Analyze results
    mtls_supported = sum(1 for r in results if r.supports_mtls)
    print(f"mTLS supported: {mtls_supported}/{len(results)} targets")

async def production_mtls_audit():
    """Production-ready mTLS audit with comprehensive error handling."""
    checker = MTLSChecker(
        timeout=15,
        max_retries=2,
        retry_delay=1.0,
        enable_logging=True
    )
    
    targets = [
        "api.example.com",
        "secure-api.example.com",
        "internal-api.company.com"
    ]
    
    results = []
    for target in targets:
        try:
            result = await checker.check_mtls(target)
            results.append(result)
            
            # Log important findings
            if result.requires_client_cert:
                print(f"⚠️  {target} REQUIRES client certificates")
            elif result.supports_mtls:
                print(f"ℹ️  {target} supports mTLS (optional)")
            else:
                print(f"ℹ️  {target} no mTLS support")
                
        except Exception as e:
            print(f"❌ Error checking {target}: {e}")
    
    # Get performance metrics
    metrics = checker.get_metrics()
    print(f"\nMetrics: {metrics['successful_connections']}/{metrics['total_requests']} successful")
    print(f"Average time: {metrics['total_time']/metrics['total_requests']:.3f}s")

# Run examples
asyncio.run(basic_mtls_check())
asyncio.run(mtls_with_client_certs())
asyncio.run(batch_mtls_check())
asyncio.run(production_mtls_audit())
```

## Architecture & Flow

The following sequence diagram illustrates the end-to-end flow of Simple Port Checker:

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant PortChecker
    participant L7Detector
    participant Target as Target Host
    participant DNS
    participant HTTP as HTTP/HTTPS
    
    %% Port Scanning Flow
    rect rgb(200, 255, 200)
        Note over User, HTTP: Port Scanning Phase
        User->>+CLI: port-checker scan target.com
        CLI->>+PortChecker: scan_host(target.com, ports)
        
        PortChecker->>+DNS: Resolve hostname
        DNS-->>-PortChecker: IP address
        
        par Port 80
            PortChecker->>+Target: TCP Connect :80
            Target-->>-PortChecker: Connection response
        and Port 443  
            PortChecker->>+Target: TCP Connect :443
            Target-->>-PortChecker: Connection response
        and Port 22
            PortChecker->>+Target: TCP Connect :22
            Target-->>-PortChecker: Connection response
        end
        
        PortChecker->>+Target: Banner grabbing
        Target-->>-PortChecker: Service banners
        
        PortChecker-->>-CLI: ScanResult
        CLI-->>-User: Rich formatted output
    end
    
    %% L7 Protection Detection Flow  
    rect rgb(200, 200, 255)
        Note over User, HTTP: L7 Protection Detection Phase
        User->>+CLI: port-checker l7-check target.com
        CLI->>+L7Detector: detect(target.com)
        
        L7Detector->>+HTTP: HTTPS Request
        HTTP-->>-L7Detector: Response + Headers
        
        L7Detector->>L7Detector: Analyze Headers<br/>(CF-Ray, X-Amzn-RequestId, etc.)
        L7Detector->>L7Detector: Check Response Body<br/>(WAF signatures)
        
        L7Detector->>+DNS: CNAME Lookup
        DNS-->>-L7Detector: DNS Records
        
        L7Detector->>L7Detector: Match Signatures<br/>(Cloudflare, AWS WAF, etc.)
        
        alt WAF/CDN Detected
            L7Detector-->>CLI: L7Result (Protected)
            CLI-->>User: "✓ Protection: Cloudflare (95%)"
        else No Protection
            L7Detector-->>CLI: L7Result (Unprotected) 
            CLI-->>User: "✗ No L7 Protection Detected"
        end
        
        L7Detector-->>-CLI: L7Result
        CLI-->>-User: Rich formatted output
    end
    
    %% Full Scan Flow
    rect rgb(255, 255, 200)
        Note over User, HTTP: Full Scan (Combined)
        User->>+CLI: port-checker full-scan target.com
        CLI->>CLI: Execute Port Scan
        CLI->>CLI: Execute L7 Detection
        CLI-->>-User: Complete security assessment
    end
```

## mTLS Authentication Flow

The following sequence diagram illustrates the complete mTLS authentication checking process:

```mermaid
sequenceDiagram
    participant Client as Simple Port Checker
    participant Target as Target Server
    participant CA as Certificate Authority
    participant Logger as Metrics & Logging
    
    %% Initial Setup
    rect rgb(200, 220, 255)
        Note over Client: mTLS Check Initialization
        Client->>Logger: Start mTLS check session
        Client->>Client: Validate target hostname/IP
        Client->>Client: Validate port range (1-65535)
        alt Client certificates provided
            Client->>Client: Validate cert/key files exist
            Client->>Client: Verify cert/key pair match
        end
    end
    
    %% Phase 1: Server Certificate Discovery
    rect rgb(200, 255, 200)
        Note over Client,Target: Phase 1: Server Certificate Analysis
        Client->>+Target: TCP Connect (port 443/custom)
        Target-->>-Client: Connection established
        
        Client->>+Target: TLS Handshake (no client cert)
        Target->>Target: Present server certificate
        Target-->>-Client: Server certificate + chain
        
        Client->>Client: Parse X.509 certificate
        Client->>Client: Extract subject, issuer, SAN, algorithms
        Client->>Client: Verify certificate validity dates
        Client->>Logger: Log certificate details
    end
    
    %% Phase 2: Client Certificate Requirement Detection
    rect rgb(255, 220, 200)
        Note over Client,Target: Phase 2: Client Certificate Requirement Detection
        Client->>+Target: TLS Handshake (without client cert)
        
        alt Server requires client certificate
            Target-->>Client: SSL Error: certificate required
            Client->>Client: Set requires_client_cert = true
            Client->>Client: Set client_cert_requested = true
        else Server supports optional client certificate
            Target-->>Client: SSL Error: handshake failure
            Client->>Client: Set requires_client_cert = false
            Client->>Client: Set client_cert_requested = true
        else Server does not support mTLS
            Target-->>-Client: TLS Handshake successful
            Client->>Client: Set supports_mtls = false
            Client->>Client: Set client_cert_requested = false
        end
    end
    
    %% Phase 3: mTLS Authentication Testing (if certificates provided)
    rect rgb(255, 200, 255)
        Note over Client,Target: Phase 3: mTLS Authentication Testing
        alt Client certificates provided
            Client->>Client: Load client certificate chain
            Client->>Client: Load private key
            
            Client->>+Target: mTLS Handshake with client cert
            Target->>Target: Verify client certificate
            
            alt Certificate validation successful
                Target->>CA: Verify certificate chain (optional)
                CA-->>Target: Certificate chain valid
                Target-->>Client: mTLS Handshake successful
                Target-->>-Client: Cipher suite + TLS version
                Client->>Client: Set handshake_successful = true
                Client->>Client: Extract cipher suite info
                Client->>Client: Extract TLS version
            else Certificate validation failed
                Target-->>-Client: SSL Error: certificate verification failed
                Client->>Client: Set handshake_successful = false
                Client->>Client: Log authentication failure
            end
        else
            Note over Client: Skip mTLS test (no client certificates)
        end
    end
    
    %% Phase 4: Results Compilation and Metrics
    rect rgb(220, 220, 255)
        Note over Client,Logger: Phase 4: Results & Metrics
        Client->>Client: Compile MTLSResult object
        Client->>Client: Update performance metrics
        Client->>Logger: Log final results
        
        alt Batch operation
            Client->>Client: Aggregate batch statistics
            Client->>Client: Calculate success rates
            Client->>Logger: Log batch completion metrics
        end
        
        Client->>Logger: Record timing metrics
        Client->>Logger: Update error counters
    end
    
    %% Return Results
    Note over Client: Return comprehensive mTLS analysis
```

### Flow Explanation

1. **Initialization Phase** (Blue): Validates inputs, checks certificate files, and prepares for the mTLS check
2. **Server Certificate Analysis** (Green): Establishes connection and analyzes the server's X.509 certificate
3. **Client Certificate Detection** (Orange): Determines if the server supports/requires client certificates
4. **mTLS Authentication Testing** (Purple): Tests actual mutual authentication if client certificates are provided
5. **Results & Metrics** (Light Blue): Compiles results and updates performance metrics

### Key Decision Points

- **Certificate Requirement Detection**: Uses SSL error analysis to determine mTLS support level
- **Authentication Testing**: Only performed when client certificates are available
- **Error Handling**: Comprehensive error categorization for different failure modes
- **Metrics Collection**: Tracks performance and reliability statistics throughout the process

### Supported Detection Methods

1. **Port Scanning**: TCP connection attempts with banner grabbing
2. **HTTP Header Analysis**: Identifying protection service signatures
3. **DNS Analysis**: CNAME records pointing to CDN/WAF providers
4. **Response Pattern Matching**: Service-specific response signatures
5. **IP Range Detection**: Known IP ranges for major providers

## Supported L7 Protection Services

- **AWS WAF** - Amazon Web Application Firewall
- **Azure WAF** - Microsoft Azure Web Application Firewall  
- **F5 BIG-IP** - F5 Application Security Manager
- **Cloudflare** - Cloudflare WAF and DDoS Protection
- **Akamai** - Akamai Web Application Protector
- **Imperva** - Imperva SecureSphere WAF
- **Sucuri** - Sucuri Website Firewall
- **Fastly** - Fastly Edge Security
- **KeyCDN** - KeyCDN Security
- **MaxCDN** - MaxCDN Security

## Well-Known Ports Checked

| Port | Service | Description |
|------|---------|-------------|
| 80 | HTTP | Web traffic |
| 443 | HTTPS | Secure web traffic |
| 8080 | HTTP-ALT | Alternative HTTP |
| 8443 | HTTPS-ALT | Alternative HTTPS |
| 3389 | RDP | Remote Desktop Protocol |
| 22 | SSH | Secure Shell |
| 21 | FTP | File Transfer Protocol |
| 25 | SMTP | Simple Mail Transfer Protocol |
| 53 | DNS | Domain Name System |
| 110 | POP3 | Post Office Protocol |
| 143 | IMAP | Internet Message Access Protocol |
| 993 | IMAPS | IMAP over SSL |
| 995 | POP3S | POP3 over SSL |
| 587 | SMTP-MSA | SMTP Message Submission |

## CLI Commands

### `port-checker scan`
Scan target hosts for open ports.

```bash
port-checker scan TARGET [OPTIONS]

Options:
  --ports TEXT        Comma-separated list of ports (default: common ports)
  --timeout INTEGER   Connection timeout in seconds (default: 3)
  --concurrent INTEGER Maximum concurrent connections (default: 100)
  --output TEXT       Output file (JSON format)
  --verbose          Enable verbose output
```

### `port-checker l7-check`
Check for L7 protection services.

```bash
port-checker l7-check TARGET [OPTIONS]

Options:
  --timeout INTEGER   Request timeout in seconds (default: 10)
  --user-agent TEXT   Custom User-Agent string
  --output TEXT       Output file (JSON format)
  --verbose          Enable verbose output
```

### `port-checker full-scan`
Perform both port scanning and L7 protection detection.

```bash
port-checker full-scan TARGET [OPTIONS]

Options:
  --ports TEXT        Comma-separated list of ports
  --timeout INTEGER   Connection timeout in seconds
  --concurrent INTEGER Maximum concurrent connections
  --output TEXT       Output file (JSON format)
  --verbose          Enable verbose output
```

### `port-checker mtls-check`
Check for mTLS support on target hosts.

```bash
port-checker mtls-check TARGET [OPTIONS]

Options:
  --client-cert TEXT  Path to client certificate file
  --client-key TEXT   Path to client private key file
  --timeout INTEGER   Request timeout in seconds (default: 10)
  --output TEXT       Output file (JSON format)
  --verbose          Enable verbose output
```

### `port-checker mtls-gen-cert`
Generate test certificates for mTLS testing.

```bash
port-checker mtls-gen-cert COMMON_NAME [OPTIONS]

Options:
  --days INTEGER      Number of days the certificate is valid (default: 365)
  --output-dir TEXT   Directory to save the generated certificate and key
  --verbose          Enable verbose output
```

### `port-checker mtls-validate-cert`
Validate client certificate and key files.

```bash
port-checker mtls-validate-cert CERT_FILE KEY_FILE [OPTIONS]

Options:
  --verbose          Enable verbose output
```

## Configuration

Create a configuration file at `~/.port-checker.yaml`:

```yaml
default_ports: [80, 443, 8080, 8443, 22, 21, 25, 53]
timeout: 5
concurrent_limit: 50
user_agent: "SimplePortChecker/1.0"
```

## Development

### Setup Development Environment

```bash
git clone https://github.com/htunn/simple-port-checker.git
cd simple-port-checker
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest
pytest --cov=simple_port_checker  # With coverage
```

### Code Formatting

```bash
black src/ tests/
isort src/ tests/
flake8 src/ tests/
mypy src/
```

### Pre-commit Hooks

```bash
pre-commit install
pre-commit run --all-files
```

## Production Deployment Examples

### Enterprise Security Audit Script

```bash
#!/bin/bash
# enterprise-mtls-audit.sh
# Production-ready mTLS security audit script

set -euo pipefail

# Configuration
TARGETS_FILE="production-apis.txt"
CLIENT_CERT="/secure/certs/audit-client.crt"
CLIENT_KEY="/secure/keys/audit-client.key"
CA_BUNDLE="/etc/ssl/certs/enterprise-ca-bundle.pem"
OUTPUT_DIR="/var/log/security-audits"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "🔍 Starting Enterprise mTLS Security Audit - $TIMESTAMP"

# Validate certificate files
if ! port-checker mtls-validate-cert "$CLIENT_CERT" "$CLIENT_KEY"; then
    echo "❌ Certificate validation failed"
    exit 1
fi

# Run comprehensive audit
port-checker mtls-check \
    --client-cert "$CLIENT_CERT" \
    --client-key "$CLIENT_KEY" \
    --ca-bundle "$CA_BUNDLE" \
    --timeout 30 \
    --concurrent 10 \
    --verbose \
    --output "$OUTPUT_DIR/mtls-audit-$TIMESTAMP.json" \
    $(cat "$TARGETS_FILE")

echo "✅ Audit completed. Results saved to $OUTPUT_DIR/mtls-audit-$TIMESTAMP.json"

# Generate summary report
python3 -c "
import json
import sys

with open('$OUTPUT_DIR/mtls-audit-$TIMESTAMP.json') as f:
    data = json.load(f)

total = data['total_targets']
mtls_required = data['mtls_required_count']
mtls_supported = data['mtls_supported_count']

print(f'📊 Audit Summary:')
print(f'   Total APIs: {total}')
print(f'   mTLS Required: {mtls_required} ({mtls_required/total*100:.1f}%)')
print(f'   mTLS Supported: {mtls_supported} ({mtls_supported/total*100:.1f}%)')

if mtls_required < total * 0.8:
    print('⚠️  WARNING: Less than 80% of APIs require mTLS')
    sys.exit(1)
else:
    print('✅ Good: Majority of APIs properly secured with mTLS')
"
```

### Kubernetes Deployment Health Check

```yaml
# k8s-mtls-healthcheck.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: mtls-health-check
data:
  check-mtls.sh: |
    #!/bin/bash
    set -e
    
    # Check service mesh mTLS configuration
    port-checker mtls-check \
      service-a.production.svc.cluster.local:8443 \
      service-b.production.svc.cluster.local:8443 \
      --client-cert /etc/certs/tls.crt \
      --client-key /etc/certs/tls.key \
      --ca-bundle /etc/ca-certs/ca.crt \
      --timeout 10 \
      --output /tmp/mtls-health.json
    
    # Validate all services require mTLS
    if ! grep -q '"requires_client_cert": true' /tmp/mtls-health.json; then
      echo "❌ mTLS not properly configured"
      exit 1
    fi
    
    echo "✅ mTLS health check passed"
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: mtls-health-check
spec:
  schedule: "*/15 * * * *"  # Every 15 minutes
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: mtls-checker
            image: python:3.12-slim
            command:
            - /bin/bash
            - /scripts/check-mtls.sh
            volumeMounts:
            - name: scripts
              mountPath: /scripts
            - name: certs
              mountPath: /etc/certs
            - name: ca-certs
              mountPath: /etc/ca-certs
          volumes:
          - name: scripts
            configMap:
              name: mtls-health-check
              defaultMode: 0755
          - name: certs
            secret:
              secretName: service-mesh-certs
          - name: ca-certs
            secret:
              secretName: ca-certificates
          restartPolicy: OnFailure
```

### CI/CD Pipeline Integration

```yaml
# .github/workflows/mtls-security-scan.yml
name: mTLS Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  mtls-security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.12'
    
    - name: Install Simple Port Checker
      run: |
        pip install simple-port-checker cryptography
    
    - name: Setup test certificates
      run: |
        # Generate test certificates for scanning
        port-checker mtls-gen-cert ci-test-client
        
    - name: Run mTLS Security Scan
      env:
        API_ENDPOINTS: ${{ secrets.API_ENDPOINTS }}
      run: |
        echo "$API_ENDPOINTS" > endpoints.txt
        
        port-checker mtls-check \
          --client-cert ci-test-client.crt \
          --client-key ci-test-client.key \
          --timeout 30 \
          --concurrent 5 \
          --output mtls-scan-results.json \
          $(cat endpoints.txt)
    
    - name: Analyze Results
      run: |
        python3 -c "
        import json
        import os
        
        with open('mtls-scan-results.json') as f:
            data = json.load(f)
        
        failed = data['failed_checks']
        total = data['total_targets']
        
        if failed > 0:
            print(f'❌ {failed}/{total} endpoints failed mTLS check')
            exit(1)
        else:
            print(f'✅ All {total} endpoints passed mTLS check')
        "
    
    - name: Upload Results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: mtls-scan-results
        path: mtls-scan-results.json
        retention-days: 30
```

### Docker Container Security Scan

```dockerfile
# Dockerfile.mtls-scanner
FROM python:3.12-slim

# Install security scanning tools
RUN apt-get update && apt-get install -y \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Simple Port Checker
RUN pip install simple-port-checker cryptography

# Create scanner script
COPY mtls-scan.py /app/
COPY entrypoint.sh /app/

WORKDIR /app
ENTRYPOINT ["./entrypoint.sh"]
```

```bash
# entrypoint.sh
#!/bin/bash
set -euo pipefail

echo "🔍 Starting Container mTLS Security Scan"

# Default configuration
TARGETS=${TARGETS:-""}
TIMEOUT=${TIMEOUT:-"30"}
CONCURRENT=${CONCURRENT:-"10"}
OUTPUT=${OUTPUT:-"/tmp/mtls-results.json"}

if [ -z "$TARGETS" ]; then
    echo "❌ No targets specified. Set TARGETS environment variable."
    exit 1
fi

# Run the scan
python3 /app/mtls-scan.py \
    --targets "$TARGETS" \
    --timeout "$TIMEOUT" \
    --concurrent "$CONCURRENT" \
    --output "$OUTPUT"

echo "✅ Scan completed. Results in $OUTPUT"
```

```python
# mtls-scan.py
#!/usr/bin/env python3
import asyncio
import argparse
import json
import logging
import sys
from simple_port_checker import MTLSChecker

async def main():
    parser = argparse.ArgumentParser(description='Container mTLS Security Scanner')
    parser.add_argument('--targets', required=True, help='Comma-separated list of targets')
    parser.add_argument('--timeout', type=int, default=30, help='Connection timeout')
    parser.add_argument('--concurrent', type=int, default=10, help='Max concurrent checks')
    parser.add_argument('--output', default='/tmp/results.json', help='Output file')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    # Parse targets
    targets = [t.strip() for t in args.targets.split(',') if t.strip()]
    
    # Initialize checker
    checker = MTLSChecker(timeout=args.timeout, enable_logging=args.verbose)
    
    print(f"🔍 Scanning {len(targets)} targets...")
    
    # Run scan
    results = await checker.batch_check_mtls(targets, max_concurrent=args.concurrent)
    
    # Generate summary
    successful = sum(1 for r in results if r.error_message is None)
    mtls_supported = sum(1 for r in results if r.supports_mtls)
    mtls_required = sum(1 for r in results if r.requires_client_cert)
    
    summary = {
        'total_targets': len(targets),
        'successful_checks': successful,
        'failed_checks': len(targets) - successful,
        'mtls_supported': mtls_supported,
        'mtls_required': mtls_required,
        'results': [r.dict() for r in results]
    }
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"📊 Results: {successful}/{len(targets)} successful")
    print(f"🔐 mTLS: {mtls_supported} supported, {mtls_required} required")
    
    # Exit with error if any checks failed
    if successful < len(targets):
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())
```

### Usage Examples

```bash
# Run the container scanner
docker run --rm \
  -e TARGETS="api1.example.com,api2.example.com:8443" \
  -e TIMEOUT=30 \
  -e CONCURRENT=5 \
  -v $(pwd)/results:/tmp \
  mtls-scanner:latest

# Enterprise audit
./enterprise-mtls-audit.sh

# Quick security check
port-checker mtls-check \
  api.example.com \
  secure-api.example.com:8443 \
  --verbose \
  --output security-assessment.json
```

## Summary

The Simple Port Checker with mTLS authentication support provides a comprehensive, production-ready solution for:

- **🔒 Security Assessment**: Complete mTLS configuration analysis
- **📋 Compliance Auditing**: Automated compliance checking for enterprise environments  
- **🛡️ API Security**: Client certificate authentication testing
- **🔍 Certificate Management**: Validation and generation of certificates
- **📊 Performance Monitoring**: Detailed metrics and reliability tracking
- **🚀 Production Integration**: CI/CD pipeline and enterprise deployment support

### Key Advantages

1. **Production-Ready**: Built with enterprise security and reliability requirements
2. **Comprehensive Analysis**: Complete mTLS authentication flow validation
3. **Flexible Integration**: Support for various deployment scenarios (CLI, API, containers)
4. **Detailed Reporting**: Rich output formats with actionable insights
5. **Performance Optimized**: Concurrent processing with configurable retry logic
6. **Security Focused**: Best practices for certificate handling and validation

### Getting Started

```bash
# Install with mTLS support
pip install simple-port-checker cryptography

# Quick mTLS check
port-checker mtls-check api.example.com --verbose

# Generate test certificates
port-checker mtls-gen-cert test-client.example.com

# Enterprise security audit
port-checker mtls-check $(cat production-apis.txt) \
  --client-cert audit-client.crt \
  --client-key audit-client.key \
  --output security-audit.json \
  --verbose
```

The mTLS functionality seamlessly integrates with existing port scanning and L7 protection detection features, providing a complete security assessment toolkit for modern infrastructure.


## What's New in v0.2.0 🎉

This major release brings significant improvements to project structure and functionality:

### 🏗️ **Complete Project Refactoring**
- **Unified CLI**: All functionality now accessible through main `port-checker` command
- **Clean Architecture**: Proper Python package structure following best practices
- **Type Safety**: Full type hint support with `py.typed` file

### 🔍 **Enhanced DNS Analysis**
- **DNS Trace Command**: New `dns-trace` command for detailed CNAME chain analysis
- **Integrated Tracing**: Use `--trace-dns` flag with L7 checks for comprehensive analysis
- **Better Detection**: Improved protection detection through DNS-based analysis

### 🚀 **Production Ready**
- **Security Policy**: Added comprehensive security guidelines
- **Better Testing**: Reorganized test suite following Python standards
- **Documentation**: Updated and improved documentation
- **CI/CD Ready**: Optimized for automated builds and publishing

### ⚡ **Breaking Changes**
- Removed standalone scripts (use unified CLI instead)
- Moved tests to top-level directory
- Removed `run.py` (use `python -m simple_port_checker` or installed commands)


## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

### v0.2.0 (Latest)
- Major project refactoring and cleanup
- Unified CLI interface with DNS trace functionality
- Production-ready structure with type hints
- Enhanced security and documentation

### v0.1.0 (Initial Release)
- Basic port scanning functionality
- L7 protection detection
- CLI interface
- Async support
- Rich terminal output

## Security Considerations

This tool is intended for legitimate security testing and network diagnostics only. Users are responsible for ensuring they have proper authorization before scanning any networks or systems they do not own.

For security vulnerabilities, please see our [Security Policy](SECURITY.md).

## Support

- 📖 [Documentation](https://github.com/htunn/simple-port-checker#readme)
- 🐛 [Issue Tracker](https://github.com/htunn/simple-port-checker/issues)

## Acknowledgments

- Thanks to the Python community for excellent libraries
- Inspired by nmap and other network scanning tools
- Built with ❤️ for the security community

