# offensive-ai

Offensive-security toolkit for authorized red-team engagements — port scanning, L7/WAF detection, mTLS and SSL/TLS certificate analysis, OWASP Top 10 (with optional LLM judge), AI/LLM OWASP Top 10 black-box probing, MCP endpoint security scanning/attacking, OpenClaw gateway assessment, Kubernetes cluster security scanning, OIDC/OAuth2/SAML auth protocol testing, A2A agent security scanning, Postman Collection API security testing, and blockchain JSON-RPC node scanning/attacking.

> **Legal notice**: active attack commands (`mcp-attack`, `openclaw-attack`, `k8s-attack`, `auth-attack`, `a2a-attack`, `postman-attack`, `blockchain-attack`, deep mode) require the `--i-have-authorization` flag. Only use against systems you own or have explicit written permission to test.

## Quick Start

```bash
docker run --rm htunnthuthu/offensive-ai:latest --help

# Port + L7 + certificate scan
docker run --rm htunnthuthu/offensive-ai:latest full-scan example.com --ports 443

# OWASP Top 10 web scan
docker run --rm htunnthuthu/offensive-ai:latest owasp-scan https://example.com

# AI/LLM endpoint probing (OWASP LLM Top 10)
docker run --rm htunnthuthu/offensive-ai:latest ai-owasp-scan https://api.example.com/v1/chat/completions

# MCP server scan (passive, no auth)
docker run --rm htunnthuthu/offensive-ai:latest mcp-scan https://mcp.example.com/mcp

# Mount a volume to save JSON/PDF reports
docker run --rm -v $(pwd):/work htunnthuthu/offensive-ai:latest \
  owasp-scan https://example.com --format json --output /work/report.json
```

Set `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY` via `-e` to enable `--llm-judge` enrichment on any scan command.

## Tags

- `latest` — most recent tagged release
- `X.Y.Z` / `X.Y` / `X` — semantic version pins
- Multi-arch: `linux/amd64`, `linux/arm64`

## Links

- Source: https://github.com/Htunn/offensive-ai
- Docs: https://docs.offensive-ai.org
- PyPI: https://pypi.org/project/offensive-ai/
- License: MIT
