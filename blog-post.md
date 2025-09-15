# Building a Modern Python CLI Tool: My Journey with Simple Port Checker

*A deep dive into creating a production-ready network security tool with async Python, rich terminal UI, and PyPI packaging*

---

## The Problem That Started It All

As someone who works with network security and infrastructure, I found myself constantly switching between different tools to perform what should be simple tasks: checking if ports are open, identifying whether a website is protected by WAF/CDN services, and understanding the DNS chain. Tools like `nmap` are powerful but overkill for quick checks, while simple port scanners lack the intelligence to detect modern protection services.

That's when I decided to build **Simple Port Checker** – a unified CLI tool that combines port scanning, L7 protection detection, and DNS analysis in one beautiful, async-powered package.

## What Makes This Project Special

### 🚀 **Modern Python Architecture**

Instead of building another quick script, I wanted to create something production-ready from day one. Here's what that meant:

```python
# Type hints everywhere for better IDE support and maintainability
async def scan_host(
    self, 
    target: str, 
    ports: List[int], 
    timeout: int = 3
) -> ScanResult:
    """Scan a target host for open ports with full type safety."""
```

The entire codebase uses type hints with a `py.typed` file, making it a joy to work with in modern IDEs like VS Code or PyCharm.

### 🎨 **Rich Terminal Experience**

One thing that bothers me about most CLI tools is ugly output. I used the fantastic `rich` library to create progress bars, beautiful tables, and colorful output that actually makes sense:

```python
# Beautiful progress bars that show real progress
with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    MofNCompleteColumn(),
    TimeElapsedColumn(),
) as progress:
    task = progress.add_task("Scanning hosts...", total=len(targets))
```

### ⚡ **Async Everything**

Network operations are inherently I/O bound, so I built everything async from the ground up using `aiohttp` and `asyncio`:

```python
async def _scan_port(self, ip: str, port: int, timeout: int) -> PortResult:
    """Async port scanning with proper timeout handling."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return PortResult(port=port, is_open=True, service=self._get_service_name(port))
    except (asyncio.TimeoutError, OSError):
        return PortResult(port=port, is_open=False)
```

This allows scanning hundreds of ports across multiple hosts in seconds rather than minutes.

## The L7 Protection Detection Challenge

The most interesting technical challenge was building intelligent detection for WAF/CDN services. Modern web applications are protected by services like Cloudflare, AWS WAF, or F5 BIG-IP, and each has unique fingerprints.

### **Header Analysis**

Each protection service leaves traces in HTTP headers:

```python
# Cloudflare detection patterns
CLOUDFLARE_HEADERS = [
    'cf-ray', 'cf-cache-status', 'cf-request-id',
    'cf-visitor', 'cf-connecting-ip'
]

# AWS WAF patterns  
AWS_WAF_HEADERS = [
    'x-amzn-requestid', 'x-amzn-trace-id',
    'x-amz-cf-id', 'x-amz-cf-pop'
]
```

### **Response Body Fingerprinting**

Some services have unique error pages or response patterns:

```python
# F5 BIG-IP error page signatures
F5_BODY_PATTERNS = [
    'The requested URL was rejected. Please consult with your administrator.',
    'BIG-IP logout page',
    'F5 Networks'
]
```

### **DNS CNAME Analysis**

Perhaps the most reliable detection method is analyzing DNS CNAME chains:

```python
async def _analyze_dns_chain(self, hostname: str) -> List[str]:
    """Trace CNAME chain to identify CDN/WAF services."""
    cname_chain = []
    current = hostname
    
    while len(cname_chain) < 10:  # Prevent infinite loops
        try:
            answers = await resolver.resolve(current, 'CNAME')
            cname = str(answers[0].target).rstrip('.')
            cname_chain.append(cname)
            current = cname
        except (NXDOMAIN, NoAnswer):
            break
    
    return cname_chain
```

If a domain points to `something.cloudflare.com` or `something.amazonaws.com`, that's a strong indicator of protection.

## Lessons Learned: From Script to Package

### **Project Structure Matters**

I started with a simple script structure but quickly realized that doesn't scale. The final structure follows Python packaging best practices:

```
simple-port-checker/
├── src/simple_port_checker/    # Source code in src layout
│   ├── __init__.py            # Package initialization
│   ├── __main__.py            # python -m support
│   ├── cli.py                 # Click-based CLI
│   ├── core/                  # Core business logic
│   │   ├── scanner.py         # Port scanning
│   │   └── l7_detector.py     # Protection detection
│   └── models/                # Pydantic data models
├── tests/                     # Tests at top level
├── pyproject.toml            # Modern Python packaging
└── README.md
```

### **CLI Design Philosophy**

I wanted a unified CLI that's both powerful and intuitive. Using Click, I created subcommands that can be used independently or chained:

```bash
# Quick port scan
port-checker scan example.com

# L7 protection check
port-checker l7-check example.com

# Everything at once
port-checker full-scan example.com

# DNS analysis
port-checker dns-trace example.com
```

Each command has sensible defaults but allows customization:

```bash
# Custom ports and timeout
port-checker scan example.com --ports 80,443,8080 --timeout 5

# Multiple targets
port-checker scan google.com stackoverflow.com --output results.json
```

### **Testing in the Real World**

Testing network tools is tricky because you need real targets. I developed a strategy using known good/bad examples:

```python
# Test with known protected sites
@pytest.mark.asyncio
async def test_cloudflare_detection():
    detector = L7Detector()
    result = await detector.detect("cloudflare.com")
    assert result.primary_protection
    assert result.primary_protection.service == ProtectionService.CLOUDFLARE

# Test with unprotected sites  
@pytest.mark.asyncio
async def test_no_protection():
    detector = L7Detector()
    result = await detector.detect("httpbin.org")
    assert not result.primary_protection
```

## Deployment and Distribution

### **PyPI Publishing**

Getting the package on PyPI was straightforward with modern tooling:

```toml
# pyproject.toml with build system
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "simple-port-checker"
dynamic = ["version"]
description = "A comprehensive tool for checking firewall ports and L7 protection services"
dependencies = [
    "aiohttp>=3.9.0",
    "click>=8.1.0",
    "rich>=13.0.0",
    "pydantic>=2.0.0",
    # ... more deps
]

[project.scripts]
port-checker = "simple_port_checker.cli:main"
```

### **CI/CD Pipeline**

I set up GitHub Actions for automated testing and publishing:

```yaml
# .github/workflows/publish.yml
name: Publish to PyPI
on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      - name: Build package
        run: python -m build
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```

## Performance and Real-World Usage

The async architecture really pays off in practice:

```bash
# Scanning 20 common ports on 5 hosts takes ~3 seconds
$ time port-checker scan google.com github.com stackoverflow.com cloudflare.com httpbin.org
# ... results ...
port-checker scan    0.12s user 0.05s system 5% cpu 3.127 total
```

Compare that to sequential scanning which would take 15+ seconds.

## What's Next

I'm already planning v0.3.0 with exciting features:

- **Certificate analysis**: SSL/TLS certificate inspection and validation
- **Response time metrics**: Latency measurements for performance analysis  
- **Export formats**: CSV, XML, and YAML output options
- **Plugin system**: Allow custom protection service detectors
- **Web interface**: Optional web UI for teams who prefer browsers

## Key Takeaways for Fellow Developers

1. **Start with good structure**: Even for "simple" projects, proper package structure saves time later
2. **Type hints are worth it**: They catch bugs early and improve the development experience
3. **Async for I/O**: Network operations should always be async in Python
4. **Beautiful CLI matters**: Users appreciate well-designed terminal interfaces
5. **Test with real data**: Network tools need real-world testing scenarios
6. **PyPI is your friend**: Modern Python packaging makes distribution easy

## Try It Yourself

Want to give it a spin? It's just a pip install away:

```bash
pip install simple-port-checker

# Quick test
port-checker scan google.com
port-checker l7-check cloudflare.com
```

The source code is available on [GitHub](https://github.com/htunn/simple-port-checker), and I'd love to hear your feedback or see your contributions!

---

Building Simple Port Checker taught me that even "simple" tools can benefit from modern software practices. By focusing on clean architecture, good user experience, and production-ready packaging, what started as a personal utility became something the broader community can benefit from.

The best part? It actually solves real problems I face daily, and based on the early adoption, I'm not alone in needing these capabilities.

*What network tools do you find yourself building repeatedly? Let me know in the comments – maybe there's an opportunity for the next useful package!*

---

*Published on September 15, 2025 | Tags: #python #networking #security #cli #async #opensource*
