# Simple Port Checker - Docker Documentation

🐳 **Official Docker Hub Repository**: [htunnthuthu/simple-port-checker](https://hub.docker.com/r/htunnthuthu/simple-port-checker)

A comprehensive, lightweight Docker container for network secu## 🔒 Certificate Analy## 🔧 Configuration & Environmentis Featuresity testing, port scanning, L7 protection detection, SSL/TLS certificate analysis, and mTLS authentication testing. Perfect for DevSecOps pipelines, security assessments, and network troubleshooting.

## 📦 Available Tags

| Tag | Description | Size | Architectures |
|-----|-------------|------|---------------|
| `latest` | Latest stable release with certificate analysis | ~55MB | `linux/amd64`, `linux/arm64` |
| `v0.4.1` | Version 0.4.1 with SSL/TLS certificate analysis | ~55MB | `linux/amd64`, `linux/arm64` |
| `v0.4.0` | Version 0.4.0 | ~50MB | `linux/amd64`, `linux/arm64` |
| `v0.3.0` | Version 0.3.0 | ~48MB | `linux/amd64`, `linux/arm64` |

**Recommendation**: Use `latest` for the most recent features, or pin to specific version tags for production deployments.

## 🚀 Quick Start

```bash
# Run a basic port scan
docker run --rm htunnthuthu/simple-port-checker:latest scan example.com

# Check for L7 protection (WAF/CDN)
docker run --rm htunnthuthu/simple-port-checker:latest l7-check example.com

# Analyze SSL/TLS certificate chain
docker run --rm htunnthuthu/simple-port-checker:latest cert-check example.com

# Full security scan with all features
docker run --rm htunnthuthu/simple-port-checker:latest full-scan example.com
```

## ️ Usage Examples

### Basic Port Scanning
```bash
# Scan common ports
docker run --rm htunnthuthu/simple-port-checker:latest scan google.com

# Scan specific ports
docker run --rm htunnthuthu/simple-port-checker:latest scan example.com --ports 80,443,8080,9000

# Scan multiple targets
docker run --rm htunnthuthu/simple-port-checker:latest scan google.com cloudflare.com --concurrent 10
```

### L7 Protection Detection
```bash
# Basic L7 protection check
docker run --rm htunnthuthu/simple-port-checker:latest l7-check example.com

# L7 check with DNS tracing
docker run --rm htunnthuthu/simple-port-checker:latest l7-check example.com --trace-dns

# Check multiple sites for protection
docker run --rm htunnthuthu/simple-port-checker:latest l7-check site1.com site2.com
```

### Certificate Chain Analysis
```bash
# Basic certificate analysis
docker run --rm htunnthuthu/simple-port-checker:latest cert-check github.com

# Complete certificate chain analysis
docker run --rm htunnthuthu/simple-port-checker:latest cert-chain example.com

# Detailed certificate information with PEM format
docker run --rm htunnthuthu/simple-port-checker:latest cert-info example.com --show-pem

# Certificate analysis with custom port
docker run --rm htunnthuthu/simple-port-checker:latest cert-check example.com --port 8443

# Save certificate analysis results
docker run --rm -v $(pwd)/results:/app/output \
  htunnthuthu/simple-port-checker:latest cert-chain example.com \
  --output /app/output/cert-analysis.json

# Verify hostname against certificate
docker run --rm htunnthuthu/simple-port-checker:latest cert-check example.com --no-verify-hostname

# Enable revocation checking (OCSP/CRL)
docker run --rm htunnthuthu/simple-port-checker:latest cert-chain example.com --check-revocation
```

### mTLS Authentication Testing
```bash
# Check mTLS support
docker run --rm htunnthuthu/simple-port-checker:latest mtls-check example.com

# Test with client certificates (mount volume)
docker run --rm -v /path/to/certs:/certs \
  htunnthuthu/simple-port-checker:latest mtls-check example.com \
  --client-cert /certs/client.crt --client-key /certs/client.key

# Generate test certificates
docker run --rm -v $(pwd)/certs:/output \
  htunnthuthu/simple-port-checker:latest mtls-gen-cert test.example.com \
  --output-dir /output
```

### Comprehensive Security Scanning
```bash
# Full scan with all features
docker run --rm htunnthuthu/simple-port-checker:latest full-scan example.com

# Save results to host system
docker run --rm -v $(pwd)/results:/app/output \
  htunnthuthu/simple-port-checker:latest full-scan example.com \
  --output /app/output/security-report.json

# Verbose output with detailed logging
docker run --rm htunnthuthu/simple-port-checker:latest full-scan example.com --verbose
```

## 🏗️ Integration Examples

### CI/CD Pipeline Integration

#### GitHub Actions
```yaml
- name: Security Port Scan
  run: |
    docker run --rm -v ${{ github.workspace }}/reports:/app/output \
      htunnthuthu/simple-port-checker:latest full-scan ${{ env.TARGET_HOST }} \
      --output /app/output/security-scan.json

- name: Certificate Analysis
  run: |
    docker run --rm -v ${{ github.workspace }}/reports:/app/output \
      htunnthuthu/simple-port-checker:latest cert-chain ${{ env.TARGET_HOST }} \
      --output /app/output/cert-analysis.json --check-revocation
```

#### GitLab CI
```yaml
security_scan:
  image: docker:latest
  script:
    - docker run --rm -v $PWD/reports:/app/output 
        htunnthuthu/simple-port-checker:latest full-scan $TARGET_HOST 
        --output /app/output/security-scan.json
    - docker run --rm -v $PWD/reports:/app/output
        htunnthuthu/simple-port-checker:latest cert-chain $TARGET_HOST
        --output /app/output/cert-analysis.json
  artifacts:
    reports:
      paths:
        - reports/security-scan.json
        - reports/cert-analysis.json
```

#### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    docker run --rm -v $WORKSPACE/reports:/app/output \
                      htunnthuthu/simple-port-checker:latest full-scan $TARGET_HOST \
                      --output /app/output/security-scan.json
                '''
                sh '''
                    docker run --rm -v $WORKSPACE/reports:/app/output \
                      htunnthuthu/simple-port-checker:latest cert-chain $TARGET_HOST \
                      --output /app/output/cert-analysis.json --verbose
                '''
                archiveArtifacts artifacts: 'reports/*.json'
            }
        }
    }
}
```

### Docker Compose Integration
```yaml
version: '3.8'
services:
  port-scanner:
    image: htunnthuthu/simple-port-checker:latest
    command: full-scan example.com --output /app/output/results.json
    volumes:
      - ./scan-results:/app/output
    environment:
      - TARGET_HOST=example.com
      
  cert-analyzer:
    image: htunnthuthu/simple-port-checker:latest
    command: cert-chain example.com --output /app/output/cert-analysis.json --check-revocation
    volumes:
      - ./cert-results:/app/output
    environment:
      - TARGET_HOST=example.com
```

### Kubernetes Job
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: security-port-scan
spec:
  template:
    spec:
      containers:
      - name: port-scanner
        image: htunnthuthu/simple-port-checker:latest
        command: ["port-checker", "full-scan", "example.com"]
        volumeMounts:
        - name: results-volume
          mountPath: /app/output
      volumes:
      - name: results-volume
        persistentVolumeClaim:
          claimName: scan-results-pvc
      restartPolicy: Never
---
apiVersion: batch/v1
kind: Job
metadata:
  name: certificate-analysis
spec:
  template:
    spec:
      containers:
      - name: cert-analyzer
        image: htunnthuthu/simple-port-checker:latest
        command: ["port-checker", "cert-chain", "example.com", "--output", "/app/output/cert-analysis.json"]
        volumeMounts:
        - name: cert-volume
          mountPath: /app/output
      volumes:
      - name: cert-volume
        persistentVolumeClaim:
          claimName: cert-results-pvc
      restartPolicy: Never
```

## � Certificate Analysis Features

### Certificate Chain Analysis
- ✅ Complete SSL/TLS certificate chain extraction
- ✅ Certificate validation and trust path verification  
- ✅ Missing intermediate certificate detection
- ✅ Certificate expiration and validity checking
- ✅ Hostname validation against certificate SAN/CN

### Certificate Information
- ✅ Certificate subject and issuer details
- ✅ Public key algorithm and key size analysis
- ✅ Digital signature algorithm identification
- ✅ Certificate extensions parsing (Key Usage, EKU, etc.)
- ✅ Subject Alternative Names (SAN) extraction

### Trust and Security Analysis
- ✅ Chain of trust validation
- ✅ Self-signed certificate detection
- ✅ CA certificate identification
- ✅ OCSP and CRL URL extraction for revocation checking
- ✅ Certificate fingerprint generation (SHA-1, SHA-256)

## �🔧 Configuration & Environment

### Environment Variables
```bash
# Set timeout for operations
docker run --rm -e TIMEOUT=30 htunnthuthu/simple-port-checker:latest scan example.com

# Enable debug logging
docker run --rm -e DEBUG=1 htunnthuthu/simple-port-checker:latest l7-check example.com

# Certificate analysis timeout
docker run --rm -e CERT_TIMEOUT=15 htunnthuthu/simple-port-checker:latest cert-chain example.com
```

### Volume Mounts
```bash
# Mount configuration directory
docker run --rm -v /host/config:/app/config \
  htunnthuthu/simple-port-checker:latest scan example.com

# Mount output directory for reports
docker run --rm -v /host/reports:/app/output \
  htunnthuthu/simple-port-checker:latest full-scan example.com \
  --output /app/output/report.json

# Mount certificate directory for mTLS
docker run --rm -v /host/certs:/app/certs \
  htunnthuthu/simple-port-checker:latest mtls-check example.com \
  --client-cert /app/certs/client.crt --client-key /app/certs/client.key
```

## 🔒 Security Features

### Non-Root User
- ✅ Container runs as non-root user `scanner` (UID: 1000)
- ✅ No privileged access required
- ✅ Minimal attack surface

### Minimal Dependencies
- ✅ Based on Alpine Linux for small footprint
- ✅ Only essential packages included
- ✅ Regular security updates via automated builds

### Security Scanning
- ✅ Images scanned with Trivy for vulnerabilities
- ✅ Security reports available in repository
- ✅ SARIF format reports for integration

## 🏷️ Image Specifications

### Base Image
- **OS**: Alpine Linux (latest stable)
- **Python**: 3.12+
- **Architecture**: Multi-arch (AMD64, ARM64)
- **User**: Non-root (`scanner:scanner`)

### Installed Tools
- ✅ Simple Port Checker (latest version)
- ✅ Python runtime and required dependencies
- ✅ SSL/TLS libraries for certificate handling
- ✅ DNS resolution utilities
- ✅ OpenSSL for certificate chain extraction
- ✅ Cryptography libraries for certificate analysis

### Performance
- **Image Size**: ~55MB compressed (with certificate analysis tools)
- **Startup Time**: <2 seconds
- **Memory Usage**: <100MB typical, <150MB with certificate analysis
- **CPU Usage**: Optimized for concurrent operations
- **Certificate Analysis**: <5 seconds for typical certificate chains

## 📊 Output Formats

### JSON Output
```bash
# Structured JSON for automation
docker run --rm htunnthuthu/simple-port-checker:latest scan example.com --format json

# Pretty printed JSON
docker run --rm htunnthuthu/simple-port-checker:latest scan example.com --format json --pretty

# Certificate analysis in JSON format
docker run --rm htunnthuthu/simple-port-checker:latest cert-chain example.com --output cert-results.json
```

### Text Output
```bash
# Human readable text (default)
docker run --rm htunnthuthu/simple-port-checker:latest scan example.com

# Verbose text output
docker run --rm htunnthuthu/simple-port-checker:latest scan example.com --verbose
```

### CSV Output
```bash
# CSV format for spreadsheet import
docker run --rm htunnthuthu/simple-port-checker:latest scan example.com --format csv
```

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Ensure proper volume permissions
docker run --rm -v $(pwd)/output:/app/output:Z \
  htunnthuthu/simple-port-checker:latest scan example.com \
  --output /app/output/results.json
```

#### Network Connectivity
```bash
# Test network connectivity
docker run --rm htunnthuthu/simple-port-checker:latest scan google.com

# Use host networking if needed
docker run --rm --network host \
  htunnthuthu/simple-port-checker:latest scan localhost
```

#### Certificate Issues
```bash
# Debug certificate chain retrieval
docker run --rm htunnthuthu/simple-port-checker:latest cert-check example.com --verbose

# Disable hostname verification for testing
docker run --rm htunnthuthu/simple-port-checker:latest cert-check example.com --no-verify-hostname

# Test certificate with custom port
docker run --rm htunnthuthu/simple-port-checker:latest cert-info example.com --port 8443

# Show certificate in PEM format for inspection
docker run --rm htunnthuthu/simple-port-checker:latest cert-info example.com --show-pem
```

### Debug Mode
```bash
# Enable verbose logging
docker run --rm htunnthuthu/simple-port-checker:latest scan example.com --verbose

# Get version information
docker run --rm htunnthuthu/simple-port-checker:latest --version

# Display help
docker run --rm htunnthuthu/simple-port-checker:latest --help
```

## 📈 Performance Tuning

### Concurrent Operations
```bash
# Adjust concurrency for better performance
docker run --rm htunnthuthu/simple-port-checker:latest scan example.com --concurrent 20

# Scan multiple targets efficiently
docker run --rm htunnthuthu/simple-port-checker:latest scan \
  site1.com site2.com site3.com --concurrent 10
```

### Resource Limits
```bash
# Set memory limits
docker run --rm --memory=512m htunnthuthu/simple-port-checker:latest scan example.com

# Set CPU limits
docker run --rm --cpus=2 htunnthuthu/simple-port-checker:latest full-scan example.com
```

## 🔗 Related Links

- **GitHub Repository**: [Htunn/simple-port-checker](https://github.com/Htunn/simple-port-checker)
- **PyPI Package**: [simple-port-checker](https://pypi.org/project/simple-port-checker/)
- **Documentation**: [Project Docs](https://github.com/Htunn/simple-port-checker/tree/main/docs)
- **Issues & Support**: [GitHub Issues](https://github.com/Htunn/simple-port-checker/issues)
- **Security Policy**: [SECURITY.md](https://github.com/Htunn/simple-port-checker/blob/main/SECURITY.md)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/Htunn/simple-port-checker/blob/main/LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](https://github.com/Htunn/simple-port-checker/blob/main/CONTRIBUTING.md) for details.

---

**Maintainer**: [htunnthuthu](https://github.com/Htunn) (htunnthuthu.linux@gmail.com)  
**Last Updated**: September 22, 2025  
**Docker Hub**: [htunnthuthu/simple-port-checker](https://hub.docker.com/r/htunnthuthu/simple-port-checker)
