# Simple Port Checker

A comprehensive Python tool for checking firewall ports and detecting L7 protection services (WAF, CDN, etc.).

## Features

- ✅ **Port Scanning**: Check well-known firewall ports and services
- 🛡️ **L7 Protection Detection**: Identify WAF/CDN services (F5, AWS WAF, Azure, Cloudflare, etc.)
- 🚀 **Async Support**: High-performance concurrent scanning
- 📊 **Rich Output**: Beautiful terminal output with progress bars
- 🔧 **CLI Interface**: Easy-to-use command-line interface
- 📦 **Pip Installable**: Available on PyPI

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

# Full scan with L7 detection
port-checker full-scan example.com

# Scan multiple targets
port-checker scan example.com google.com --output results.json
```

### Python API Usage

```python
from simple_port_checker import PortChecker, L7Detector

# Initialize scanner
scanner = PortChecker()

# Scan ports
results = await scanner.scan_host("example.com", ports=[80, 443, 8080])
print(f"Open ports: {len([p for p in results.ports if p.is_open])}")

# Detect L7 protection
detector = L7Detector()
protection = await detector.detect("example.com")
if protection.primary_protection:
    service = protection.primary_protection.service.value
    confidence = protection.primary_protection.confidence
    print(f"L7 Protection: {service} ({confidence:.0%})")
else:
    print("No L7 protection detected")
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

### Key Components

- **CLI**: Rich command-line interface with progress bars and colored output
- **PortChecker**: Async port scanner with configurable concurrency and timeouts
- **L7Detector**: HTTP header and DNS analysis for WAF/CDN detection
- **DNS Resolution**: Hostname to IP mapping and CNAME analysis
- **Target Host**: The system being scanned for open ports and services
- **HTTP/HTTPS**: Web service detection and L7 protection analysis

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

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v0.1.0 (Initial Release)
- Basic port scanning functionality
- L7 protection detection
- CLI interface
- Async support
- Rich terminal output

## Security Considerations

This tool is intended for legitimate security testing and network diagnostics only. Users are responsible for ensuring they have proper authorization before scanning any networks or systems they do not own.

## Support

- 📖 [Documentation](https://github.com/htunn/simple-port-checker#readme)
- 🐛 [Issue Tracker](https://github.com/htunn/simple-port-checker/issues)
- 💬 [Discussions](https://github.com/htunn/simple-port-checker/discussions)

## Acknowledgments

- Thanks to the Python community for excellent libraries
- Inspired by nmap and other network scanning tools
- Built with ❤️ for the security community
