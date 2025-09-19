# Simple Port Checker - Docker Documentation

🐳 **Official Docker Hub Repository**: [htunnthuthu/simple-port-checker](https://hub.docker.com/r/htunnthuthu/simple-port-checker)

A comprehensive, lightweight Docker container for network security testing, port scanning, L7 protection detection, and mTLS authentication testing. Perfect for DevSecOps pipelines, security assessments, and network troubleshooting.

## 🚀 Quick Start

```bash
# Run a basic port scan
docker run --rm htunnthuthu/simple-port-checker:latest scan example.com

# Check for L7 protection (WAF/CDN)
docker run --rm htunnthuthu/simple-port-checker:latest l7-check example.com

# Full security scan with all features
docker run --rm htunnthuthu/simple-port-checker:latest full-scan example.com
```

## 📦 Available Tags

| Tag | Description | Size | Architectures |
|-----|-------------|------|---------------|
| `latest` | Latest stable release | ~50MB | `linux/amd64`, `linux/arm64` |
| `v0.4.0` | Version 0.4.0 | ~50MB | `linux/amd64`, `linux/arm64` |
| `v0.3.0` | Version 0.3.0 | ~48MB | `linux/amd64`, `linux/arm64` |

**Recommendation**: Use `latest` for the most recent features, or pin to specific version tags for production deployments.

## 🛠️ Usage Examples

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
```

#### GitLab CI
```yaml
security_scan:
  image: docker:latest
  script:
    - docker run --rm -v $PWD/reports:/app/output 
        htunnthuthu/simple-port-checker:latest full-scan $TARGET_HOST 
        --output /app/output/security-scan.json
  artifacts:
    reports:
      paths:
        - reports/security-scan.json
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
```

## 🔧 Configuration & Environment

### Environment Variables
```bash
# Set timeout for operations
docker run --rm -e TIMEOUT=30 htunnthuthu/simple-port-checker:latest scan example.com

# Enable debug logging
docker run --rm -e DEBUG=1 htunnthuthu/simple-port-checker:latest l7-check example.com
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

### Performance
- **Image Size**: ~50MB compressed
- **Startup Time**: <2 seconds
- **Memory Usage**: <100MB typical
- **CPU Usage**: Optimized for concurrent operations

## 📊 Output Formats

### JSON Output
```bash
# Structured JSON for automation
docker run --rm htunnthuthu/simple-port-checker:latest scan example.com --format json

# Pretty printed JSON
docker run --rm htunnthuthu/simple-port-checker:latest scan example.com --format json --pretty
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
# Verify certificate files are readable
docker run --rm -v /path/to/certs:/certs \
  htunnthuthu/simple-port-checker:latest mtls-validate-cert \
  /certs/client.crt /certs/client.key
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
**Last Updated**: September 19, 2025  
**Docker Hub**: [htunnthuthu/simple-port-checker](https://hub.docker.com/r/htunnthuthu/simple-port-checker)
