```
 ██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗██╗██╗   ██╗███████╗
██╔═══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██║██║   ██║██╔════╝
██║   ██║█████╗  █████╗  █████╗  ██╔██╗ ██║███████╗██║██║   ██║█████╗
██║   ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██║╚██╗ ██╔╝██╔══╝
╚██████╔╝██║     ██║     ███████╗██║ ╚████║███████║██║ ╚████╔╝ ███████╗
 ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝  ╚══════╝-AI
  Offensive-Security Toolkit · AI/LLM · MCP · A2A · Postman · Blockchain · Red-Team
```

<p align="center">
  <a href="https://github.com/Htunn/offensive-ai/actions/workflows/test.yml"><img src="https://github.com/Htunn/offensive-ai/actions/workflows/test.yml/badge.svg?branch=develop" alt="Test and Build"/></a>
  <a href="https://github.com/Htunn/offensive-ai/actions/workflows/publish.yml"><img src="https://github.com/Htunn/offensive-ai/actions/workflows/publish.yml/badge.svg" alt="Publish to PyPI"/></a>
  <a href="https://github.com/Htunn/offensive-ai/actions/workflows/docker.yml"><img src="https://github.com/Htunn/offensive-ai/actions/workflows/docker.yml/badge.svg" alt="Docker Build"/></a>
  <a href="https://github.com/Htunn/offensive-ai/actions/workflows/codeql.yml"><img src="https://github.com/Htunn/offensive-ai/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"/></a>
</p>

<p align="center">
  <a href="https://pypi.org/project/offensive-ai/"><img src="https://img.shields.io/pypi/v/offensive-ai" alt="PyPI Version"/></a>
  <a href="https://pepy.tech/project/offensive-ai"><img src="https://static.pepy.tech/badge/offensive-ai" alt="PyPI Download"/></a>
  <a href="https://pypi.org/project/offensive-ai/"><img src="https://img.shields.io/pypi/pyversions/offensive-ai" alt="Python Version"/></a>
  <a href="https://hub.docker.com/r/htunnthuthu/offensive-ai"><img src="https://img.shields.io/docker/pulls/htunnthuthu/offensive-ai" alt="Docker Pulls"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"/></a>
</p>

**Offensive-security toolkit for authorized red-team engagements.**

`offensive-ai` is a Python library and CLI that combines classic network reconnaissance with modern AI/LLM security testing. It probes live AI/LLM endpoints for the [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/), scans and actively attacks [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers for known CVEs, and performs full-stack infrastructure security assessments.

> **Legal Notice**: Active attack features (`mcp-attack`, `openclaw-attack`, `k8s-attack`, `auth-attack`, `a2a-attack`, `postman-attack`, `blockchain-attack`, deep mode) require the `--i-have-authorization` flag. Only use against systems you own or have explicit written permission to test.

---

## Features

### New in v2.9.0 — Blockchain Node Security

| Feature | Description |
|---------|-------------|
| ⛓️ **Blockchain Scanner** | Fingerprints Ethereum/EVM-compatible JSON-RPC nodes (Geth, Erigon, Besu, Nethermind, bor) and their chain (Ethereum, Polygon, BSC, Arbitrum, Optimism, Avalanche); checks whether admin/debug/wallet RPC namespaces are reachable without authentication |
| 🔑 **Wallet & Admin Exposure Detection** | Flags disclosed wallet addresses (`eth_accounts`), an unauthenticated `admin_*` namespace, and a reachable `debug_*`/`txpool_*` namespace, each mapped to a dedicated advisory in `BLOCKCHAIN_CVE_DB` |
| ⚔️ **Blockchain Attacker** | Authorization-gated active testing with **safe mode** (read-only admin/peer probes) and **deep mode** (adds debug/txpool leak checks + unrestricted `eth_sign`/`eth_sendTransaction` tests against discovered accounts) — every payload is engineered to be non-destructive |
| 🧐 **Smart Contract Static Analysis** | `blockchain-contract-audit` runs offline, heuristic opcode/ABI-shape analysis (self-destruct, delegatecall, re-entrancy pattern, unchecked arithmetic) mapped to the OWASP Smart Contract Top 10 / SWC Registry — no network calls, no authorization flag required |
| 🤖 **Optional LLM Judge** | Enriches MEDIUM/LOW findings with provider reasoning, consistent with every other `--llm-judge` command |

### New in v2.8.0 — Internal Consistency & Maintainability Pass

| Feature | Description |
|---------|-------------|
| 🧱 **Shared base classes** | `BaseScanner` / `BaseAttacker` (`core/_base.py`) centralise constructor boilerplate, the HTTP client factory, and the authorization guard previously duplicated across every protocol module (MCP, A2A, Auth, K8s, OpenClaw, Postman, multi-turn LLM) |
| 🩹 **Dynamic `User-Agent`** | Fixed stale hardcoded version strings (`offensive-ai/2.0.1`, `offensive-ai/2.3.0`, `offensive-ai/2.7.0`) sent by MCP, A2A, Auth, K8s, OpenClaw, AI-OWASP, and Postman scanners/attackers — all now send `offensive-ai/<installed-version>` |
| 🗂️ **Shared vulnerability model** | `VulnSeverity` and `BaseVulnerability` (`models/severity.py`, `models/vulnerability.py`) are now the single source of truth for severity levels and common finding fields across every protocol-specific vulnerability class |
| 🔇 **Cleaner stdout** | Attacker authorization banners are now emitted once via structured logging instead of a mix of `print()` and `logger.warning()`, so piping JSON/report output to a file or another tool no longer gets polluted with banner text |

### New in v2.7.0 — Postman Collection Security Scanner & Attacker

| Feature | Description |
|---------|-------------|
| 📬 **Postman Scanner** | Parses Postman Collection v2.x exports, resolves `{{variables}}` from environment files, probes every endpoint, and runs static analysis: missing auth on sensitive routes, unresolved variables, verbose error disclosure, secrets in responses, wildcard CORS |
| 🔑 **Secret Detection** | 10 regex patterns scan response bodies for leaked credentials — AWS keys, OpenAI keys, GitHub PATs, JWTs, generic bearer tokens, Slack webhooks, and more |
| ⚔️ **Postman Attacker** | Authorization-gated active OWASP API Top 10 testing: **safe mode** (auth bypass only) and **deep mode** (auth bypass + BOLA/IDOR + mass assignment + injection + SSRF) against every endpoint in the collection |
| 🧩 **Variable Resolution** | `{{baseUrl}}`, `{{token}}`, and custom variables resolved from both collection-level and environment file; unresolved placeholders flagged as `PM-ADV-CFG-001` |
| 🎯 **Target Override** | `--target/-T` rewrites the host/scheme of every endpoint so a single collection can be aimed at any environment (dev / staging / prod) |
| 🤖 **LLM Judge Integration** | Optional judge enriches LOW/MEDIUM findings with provider reasoning and synthesises an `exploit_chain_summary` across all triggered attacks |

### New in v2.6.0 — A2A (Agent-to-Agent) Protocol Security

| Feature | Description |
|---------|-------------|
| 🤝 **A2A Scanner** | Fetches the Agent Card (`/.well-known/agent-card.json`), parses declared skills/capabilities/security schemes, probes authentication posture, and runs 8-phase static analysis against 10 A2A security advisories |
| 🔐 **Auth Posture Check** | Sends an unauthenticated `SendMessage` JSON-RPC probe to detect open task endpoints; maps `securitySchemes` to OAuth2/OIDC/Bearer/mTLS/apiKey/none |
| 💀 **Dangerous Skill Detection** | Flags skills whose descriptions contain shell execution keywords (`exec`, `bash`, `eval`, `kubectl`, `docker run`, etc.) — CRITICAL severity |
| 🔑 **Secret Scanning** | Regex-based scan of the Agent Card JSON for leaked API keys, tokens, and credentials (OpenAI `sk-`, AWS `AKIA`, GitHub `ghp_`, Slack, etc.) |
| 📋 **10 A2A Advisories** | A2A-ADV-2025-001 through 010 — from missing `securitySchemes` and unauthenticated task access to unsigned Agent Cards, SSRF via push-notification webhooks, and plaintext HTTP endpoints |
| ⚔️ **A2A Attacker** | Authorized red-team module with **safe mode** (auth-bypass probes) and **deep mode** (auth bypass + SSRF webhook + message injection + task enumeration + JSON-RPC manipulation) |
| 🤖 **Optional LLM Judge** | Enriches MEDIUM/LOW findings with provider reasoning; shows `LLM Judge: gemini` in the results panel and footer |

### New in v2.5.0 — Universal LLM Judge "Powered By" + OWASP Web Scanner Judge Support

| Feature | Description |
|---------|-------------|
| 🔍 **OWASP Web Scanner LLM Judge** | `owasp-scan` now accepts `--llm-judge`; enriches MEDIUM/LOW findings with provider reasoning; upgrades LOW→MEDIUM when confidence > 0.7; verbose mode shows per-finding `LLM (X%): ...` |
| 📢 **"Powered by" display everywhere** | Every `--llm-judge` command now shows `LLM Judge: gemini` (or `openai` / `anthropic`) inside the result panel **and** prints `LLM Judge powered by: gemini` as a footer — consistent across all 9 modules |
| 🐛 **k8s-scan / k8s-attack bug fix** | Both commands previously used `LLMJudge()` directly (bypassing `is_available()`), which could crash with no API key. Fixed to use `LLMJudge.from_env()` + `is_available()` — the same safe pattern used by all other commands |
| 📋 **`OwaspFinding` enrichment** | Two new optional fields: `llm_reasoning: str | None`, `llm_confidence: float | None` — populated by the LLM judge triage phase |

### New in v2.4.0 — OIDC / OAuth 2.0 / SAML Auth Protocol Security

| Feature | Description |
|---------|-------------|
| 🔑 **Auth Protocol Scanner** | Passive detection of OIDC, OAuth 2.0, and SAML endpoints; fingerprints provider (Google, Entra ID, Keycloak, Auth0, Okta, Cognito, etc.); parses discovery documents and SAML metadata |
| 📋 **Auth CVE Database** | 14 advisories (`AUTH-ADV-###`) + real CVEs: CVE-2019-3778 (Spring), CVE-2017-11427 / CVE-2018-0489 (SAML XSW), CVE-2023-34462 (Keycloak/Netty), CVE-2023-41900 (OpenSAML) |
| 🛡️ **Security Posture Checks** | PKCE enforcement, implicit flow, state parameter, alg=none in JWT, JWKS cache-control, SAML signing certificates, XML Signature Wrapping surface |
| 🤖 **Optional LLM Judge** | Triages MEDIUM/LOW auth findings; shows `LLM Judge: gemini` (or `openai` / `anthropic`) in every scan/attack panel; falls back to rule-based when no API key is set |
| ⚔️ **Auth Attacker** | Authorized red-team probes — **safe mode**: open redirect, state bypass, PKCE bypass; **deep mode** adds JWT alg=none, scope escalation, authorization code replay, SAML XSW (5 variants), JWKS confusion |

### New in v2.3.0 — Kubernetes Cluster Security

| Feature | Description |
|---------|-------------|
| ☸️ **Kubernetes Scanner** | Five-phase black-box scan of exposed K8s components: kube-apiserver (6443/8080), kubelet (10250/10255), etcd (2379), scheduler, controller-manager, cAdvisor, dashboard |
| 📋 **OWASP K8s Top 10 (2025)** | Findings mapped to K01–K10; 10+ advisories (`K8S-ADV-###`) + real CVEs (CVE-2018-1002105, CVE-2019-11253, CVE-2020-8558, CVE-2021-25741, CVE-2022-3294) |
| 🤖 **Optional LLM Judge** | `LLMJudge` triages ambiguous findings and generates remediation advice; supports OpenAI, Anthropic, and Google Gemini; rule-based fallback when no API key is set |
| ⚔️ **Kubernetes Attacker** | Authorized red-team probes: anonymous API reads, kubelet `/exec` command execution, Secret extraction, SelfSubjectAccessReview privilege audit, etcd key dump, cloud metadata SSRF (K08) |

### New in v2.1.0 — OpenClaw Gateway Security

| Feature | Description |
|---------|-------------|
| 🦞 **OpenClaw Scanner** | Six-phase passive assessment of [OpenClaw](https://github.com/openclaw/openclaw) AI-gateway deployments: fingerprint (including HTML-based detection for OpenClaw 2026.x), endpoint enumeration, auth posture, config review, CVE/misconfiguration matching, optional LLM triage |
| 🔟 **10 Advisory Checks** | OCL-ADV-001 through OCL-ADV-010 — from unauthenticated REST/WebSocket access to insecure sandbox modes, DM policy exposure, and API-key leakage via config endpoint |
| ⚔️ **OpenClaw Attacker** | Authorized active exploitation: prompt injection, SSRF via webhook, session history dump, WebSocket message injection; optional `--llm-judge` for attack-path narrative |

### New in v2.0.0 — AI / LLM Security

| Feature | Description |
|---------|-------------|
| 🤖 **AI OWASP Top 10 Scanner** | Black-box probing of live LLM/chat API endpoints for all 10 OWASP LLM categories |
| 🔬 **Rule-based + LLM Judge** | Pattern-based detection + optional LLM judge (OpenAI / Anthropic / Gemini) via `[ai]` extra |
| 🔌 **MCP Security Scanner** | Enumerate tools/resources/prompts, detect CVEs, check auth posture (HTTP, SSE, stdio) |
| ⚔️ **MCP Attacker** | Authorized active testing: auth bypass, path traversal, tool injection, command injection; optional `--llm-judge` for attack-path narrative |
| 🛡️ **Authorization Gating** | `MCPAttacker(authorized=False)` raises `AuthorizationRequired`; `--i-have-authorization` flag required at CLI |

### Infrastructure Security

| Feature | Description |
|---------|-------------|
| 🔍 **Port Scanning** | Async concurrent scanning of well-known and custom ports |
| 🌐 **L7 Protection Detection** | Identify WAF/CDN services (Cloudflare, AWS WAF, Azure, F5, Akamai, etc.) |
| 🔐 **mTLS Checker** | Test mutual TLS support, client certificate requirements, handshake validation |
| 🔒 **Certificate Analysis** | Full chain analysis, trust path, issuer identification, expiry, missing intermediates |
| 🏛️ **Hybrid Identity Detection** | Azure AD / ADFS federation endpoint discovery (same method as Azure Portal) |
| 🕵️ **OWASP Top 10 Web Scanner** | Web OWASP Top 10 2021 & 2025 with safe/deep modes, PDF/JSON/CSV reports |
| 🛡️ **Security Headers** | Grade HTTP headers (HSTS, CSP, X-Frame-Options, Referrer-Policy, etc.) |
| 📄 **Multi-format Reporting** | Export to PDF, JSON, CSV with tech-specific remediation (Nginx, Apache, IIS, Cloudflare) |

---

## Installation

```bash
# Core toolkit
pip install offensive-ai

# With optional LLM judge (OpenAI / Anthropic / Gemini)
pip install "offensive-ai[ai]"
```

### From Source

```bash
git clone https://github.com/htunn/offensive-ai.git
cd offensive-ai
pip install -e ".[dev]"
```

### Docker

```bash
docker run --rm htunnthuthu/offensive-ai:latest --help
# or from GitHub Container Registry
docker run --rm ghcr.io/htunn/offensive-ai:latest --help
```

---

## Quick Start

```
 ██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗██╗██╗   ██╗███████╗
██╔═══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██║██║   ██║██╔════╝
██║   ██║█████╗  █████╗  █████╗  ██╔██╗ ██║███████╗██║██║   ██║█████╗
██║   ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██║╚██╗ ██╔╝██╔══╝
╚██████╔╝██║     ██║     ███████╗██║ ╚████║███████║██║ ╚████╔╝ ███████╗
 ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝  ╚══════╝-AI
  Offensive-Security Toolkit · AI/LLM · MCP · A2A · Postman · Blockchain · Red-Team
```

### CLI

```bash
# Blockchain JSON-RPC node security
offensive-ai blockchain-scan node.example.com --port 8545
offensive-ai blockchain-scan node.example.com --llm-judge
offensive-ai blockchain-attack node.example.com --i-have-authorization --mode deep
offensive-ai blockchain-contract-audit --abi ./MyToken.json --bytecode ./MyToken.bin

# Postman collection security
offensive-ai postman-scan collection.json -T https://api.example.com
offensive-ai postman-scan collection.json -e env.json --llm-judge --output report.json
offensive-ai postman-attack collection.json --i-have-authorization -T https://api.example.com
offensive-ai postman-attack collection.json --i-have-authorization --mode deep -e env.json --llm-judge

# A2A (Agent-to-Agent) protocol security
offensive-ai a2a-scan https://agent.example.com
offensive-ai a2a-scan https://agent.example.com --llm-judge
offensive-ai a2a-scan https://agent.example.com --format json --output a2a-report.json
offensive-ai a2a-attack https://agent.example.com --i-have-authorization
offensive-ai a2a-attack https://agent.example.com --i-have-authorization --mode deep --llm-judge

# Auth / identity protocol security
offensive-ai auth-scan https://auth.example.com
offensive-ai auth-scan https://idp.example.com --protocol saml
offensive-ai auth-scan https://accounts.google.com --llm-judge
offensive-ai auth-scan https://mocksaml.com/api/saml/metadata --protocol saml --llm-judge
offensive-ai auth-attack https://auth.example.com --i-have-authorization
offensive-ai auth-attack https://auth.example.com --i-have-authorization --mode deep --llm-judge

# AI / LLM security
offensive-ai ai-owasp-scan https://api.example.com/v1/chat/completions
offensive-ai mcp-scan https://mcp.example.com/mcp
offensive-ai mcp-attack https://mcp.example.com/mcp --i-have-authorization

# OpenClaw gateway security
offensive-ai openclaw-scan 192.168.1.10
offensive-ai openclaw-scan gateway.example.com --port 18789 --tls
offensive-ai openclaw-scan 192.168.1.10 --llm-judge
offensive-ai openclaw-attack 192.168.1.10 --i-have-authorization --mode deep
offensive-ai openclaw-attack 192.168.1.10 --i-have-authorization --mode deep --llm-judge

# Kubernetes cluster security
offensive-ai k8s-scan 192.168.1.100
offensive-ai k8s-scan k8s.example.com --port 6443 --port 10250 --llm-judge
# kubectl proxy makes the API server reachable on plain HTTP locally:
offensive-ai k8s-scan 127.0.0.1 --port 8001 --llm-judge
offensive-ai k8s-attack 192.168.1.100 --i-have-authorization --mode deep
offensive-ai k8s-attack 127.0.0.1 --port 8001 --i-have-authorization --llm-judge

# Infrastructure
offensive-ai scan example.com
offensive-ai l7-check example.com
offensive-ai cert-check example.com
offensive-ai owasp-scan example.com
offensive-ai owasp-scan example.com --llm-judge   # shows "LLM Judge: gemini" in panel + footer
offensive-ai hybrid-identity example.com
offensive-ai mtls-check example.com
```

### Python API

```python
import asyncio
from offensive_ai import LLMOwaspScanner, MCPScanner, MCPAttacker, AuthorizationRequired
from offensive_ai import AuthScanner, AuthAttacker, AuthProtocol
from offensive_ai import A2AScanner, A2AAttacker
from offensive_ai import PostmanScanner, PostmanAttacker

async def main():
    # Postman collection security scan
    pm = PostmanScanner(
        collection_path="collection.json",
        environment_path="env.json",
        target_override="https://api.example.com",
    )
    pm_result = await pm.scan()
    print(f"Endpoints: {pm_result.endpoints_scanned}  Vulns: {len(pm_result.all_vulns)}  Critical: {pm_result.has_critical}")

    # A2A agent security scan
    a2a = A2AScanner("https://agent.example.com")
    a2a_result = await a2a.scan()
    print(f"Agent: {a2a_result.agent_card.name}  Skills: {len(a2a_result.agent_card.skills)}")
    print(f"Auth: {a2a_result.auth_posture.auth_type}  Unauthed: {a2a_result.auth_posture.unauthenticated_access}")
    print(f"Vulnerabilities: {len(a2a_result.all_vulns)}  Critical: {a2a_result.has_critical}")

    # Auth protocol scan (OIDC / OAuth2 / SAML)
    auth = AuthScanner("https://accounts.google.com")
    auth_result = await auth.scan()
    print(f"Protocol: {auth_result.protocol.value}  Provider: {auth_result.provider_info.name}")
    print(f"Vulnerabilities: {len(auth_result.all_vulns)}")

    # SAML scan
    saml = AuthScanner("https://mocksaml.com/api/saml/metadata", protocol="saml")
    saml_result = await saml.scan()
    print(f"SAML issuer: {saml_result.provider_info.issuer}")

    # Auth attack (requires explicit authorization)
    attacker = AuthAttacker(authorized=True)
    report = await attacker.attack(
        target="https://auth.example.com",
        mode="safe",
    )
    print(f"Attacks run: {report.attacks_run}, triggered: {report.attacks_triggered}")

    # AI OWASP scan
    scanner = LLMOwaspScanner("https://api.example.com/v1/chat/completions")
    result = await scanner.scan()
    print(f"Grade: {result.overall_grade}  Score: {result.total_score}")
    for cat_id, cat in result.categories.items():
        if cat.findings:
            print(f"  {cat_id}: {len(cat.findings)} finding(s) — grade {cat.grade}")

    # MCP scan
    mcp = MCPScanner("https://mcp.example.com/mcp")
    mcp_result = await mcp.scan()
    print(f"MCP vulnerabilities: {len(mcp_result.vulnerabilities)}")

    # MCP attack (requires explicit authorization)
    try:
        attacker = MCPAttacker(authorized=True)   # must be True
        report = await attacker.attack(
            target="https://mcp.example.com/mcp",
            transport="http",
            mode="safe",
        )
        print(f"Attacks run: {report.attacks_run}, triggered: {len(report.triggered_results)}")
    except AuthorizationRequired:
        print("Provide authorized=True to unlock attack mode")

asyncio.run(main())
```

---

## A2A (Agent-to-Agent) Protocol Security

Scans and actively tests [A2A protocol](https://a2a-protocol.org) agent endpoints for security vulnerabilities. The A2A protocol (Google, 2025) is an open standard enabling AI agents to communicate via JSON-RPC 2.0 over HTTP. Agents publish an **Agent Card** at `/.well-known/agent-card.json` declaring their capabilities, skills, and security schemes.

### Security Checks Performed

| Check ID | Severity | Description |
|----------|----------|-------------|
| OAI-A2A-AUTH-001 | **High** | No `securitySchemes` declared in Agent Card |
| OAI-A2A-AUTH-003 | **High** | Unauthenticated `SendMessage` task accepted |
| OAI-A2A-INT-001 | Medium | Agent Card not cryptographically signed |
| OAI-A2A-SEC-001 | **Critical** | Secrets / API keys found in Agent Card JSON |
| OAI-A2A-SKILL-001 | **Critical** | Skill description contains dangerous execution keywords |
| OAI-A2A-SSRF-001 | **High** | Push-notification webhooks enabled — SSRF attack surface |
| OAI-A2A-TLS-001 | **High** | JSON-RPC endpoint served over plaintext HTTP |
| OAI-A2A-EXT-001 | **High** | Extended Agent Card accessible without authentication |

### Advisory Database

| ID | Severity | Finding |
|----|----------|---------|
| A2A-ADV-2025-001 | **High** | No `securitySchemes` — agent accepts unauthenticated requests |
| A2A-ADV-2025-002 | **High** | Unauthenticated task execution on `tasks/send` |
| A2A-ADV-2025-003 | Medium | Unsigned Agent Card — integrity not verifiable |
| A2A-ADV-2025-004 | **Critical** | Secrets / credentials found in Agent Card JSON |
| A2A-ADV-2025-005 | **Critical** | Dangerous skill keywords (shell execution, kubectl, eval) |
| A2A-ADV-2025-006 | **High** | Push-notification webhook SSRF risk |
| A2A-ADV-2025-007 | **High** | JSON-RPC endpoint uses plaintext HTTP |
| A2A-ADV-2025-008 | **High** | Extended Agent Card accessible without auth |
| A2A-ADV-2025-009 | Low | No A2A protocol version enforcement |
| A2A-ADV-2025-010 | Medium | Task IDs predictable — IDOR attack surface |

### CLI Usage

```bash
# Passive scan — fetch Agent Card and analyze security posture
offensive-ai a2a-scan https://agent.example.com

# Non-standard port
offensive-ai a2a-scan https://agent.example.com --port 8443

# With bearer token (authenticated scan)
offensive-ai a2a-scan https://agent.example.com \
  --header 'Authorization: Bearer <token>'

# LLM judge enrichment (shows "LLM Judge: gemini" in output)
offensive-ai a2a-scan https://agent.example.com --llm-judge

# JSON output
offensive-ai a2a-scan https://agent.example.com --format json --output a2a-scan.json

# Authorized active attack — safe mode (auth-bypass probes)
offensive-ai a2a-attack https://agent.example.com --i-have-authorization

# Deep mode — auth bypass + SSRF webhook + message injection + task enum + JSON-RPC
offensive-ai a2a-attack https://agent.example.com \
  --i-have-authorization --mode deep

# With LLM judge and JSON output
offensive-ai a2a-attack https://agent.example.com \
  --i-have-authorization --mode deep --llm-judge \
  --format json --output a2a-attack.json
```

### Attack Suite

| Attack | Safe Mode | Deep Mode | Description |
|--------|-----------|-----------|-------------|
| Auth Bypass | ✅ | ✅ | No auth header, null/empty Bearer, invalid JWT, X-Forwarded-For spoof, JWT alg=none |
| SSRF via Webhook | ❌ | ✅ | Push-notification webhook pointed at localhost/IMDS/internal ranges |
| Message Injection | ❌ | ✅ | Prompt injection payloads in `SendMessage` body |
| Task Enumeration | ❌ | ✅ | Sequential/predictable task IDs via `GetTask` (IDOR) |
| JSON-RPC Manipulation | ❌ | ✅ | Oversized `pageSize`, SQL injection in task ID, path-traversal method names |

### Python API

```python
import asyncio
from offensive_ai import A2AScanner, A2AAttacker, A2AVulnSeverity
from offensive_ai.core.llm_judge import LLMJudge
from offensive_ai.exceptions import AuthorizationRequired

async def main():
    # Optional LLM judge
    judge = LLMJudge.from_env()   # reads GEMINI_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY

    # Passive scan
    scanner = A2AScanner(
        target="https://agent.example.com",
        port=None,              # override port (optional)
        headers={},             # extra HTTP headers
        timeout=15.0,
        verify_tls=True,
        judge=judge,            # None = rule-based only
    )
    result = await scanner.scan()

    print(f"Agent          : {result.agent_card.name} v{result.agent_card.version}")
    print(f"Provider       : {result.agent_card.provider_organization}")
    print(f"Skills         : {len(result.agent_card.skills)}")
    print(f"Auth type      : {result.auth_posture.auth_type}")
    print(f"Unauthed access: {result.auth_posture.unauthenticated_access}")
    print(f"Push webhooks  : {result.agent_card.capabilities.push_notifications}")
    print(f"Card signed    : {result.agent_card.is_signed}")
    print(f"Vulnerabilities: {len(result.all_vulns)}  Critical: {result.has_critical}")

    for vuln in result.all_vulns:
        print(f"  [{vuln.severity.value}] {vuln.vuln_id}: {vuln.title}")
        if vuln.evidence:
            print(f"    Evidence: {vuln.evidence[:80]}")
        if vuln.llm_reasoning:
            print(f"    LLM ({vuln.llm_confidence:.0%}): {vuln.llm_reasoning[:100]}")

    # Authorized active attack
    try:
        attacker = A2AAttacker(authorized=True, judge=judge)
        report = await attacker.attack(
            target="https://agent.example.com",
            mode="deep",         # "safe" | "deep"
            scan_result=result,  # guides SSRF probe (push_notifications check)
        )
        print(f"Attacks run     : {report.attacks_run}")
        print(f"Attacks triggered: {report.attacks_triggered}")
        for r in report.successful_attacks:
            print(f"  [{r.severity.value}] {r.attack_id} ({r.attack_type}): {r.title}")
            if r.evidence:
                print(f"    Evidence: {r.evidence[:80]}")
    except AuthorizationRequired:
        print("Pass authorized=True to unlock attack mode")

asyncio.run(main())
```

---

## Postman Collection Security

Scans and actively attacks every API endpoint defined in a [Postman Collection v2.x](https://learning.postman.com/collection-format/) export. Supports variable resolution from Postman environment files, target override for cross-environment testing, and optional LLM judge enrichment.

### Security Checks Performed

| Check ID | Severity | Description |
|----------|----------|-------------|
| PM-ADV-AUTH-001 | **High** | No auth header/scheme on a sensitive endpoint (admin, user, payment, …) |
| PM-ADV-CFG-001 | Medium | Unresolved `{{variable}}` placeholders in URL or headers |
| PM-ADV-MISC-001 | Medium | Verbose error disclosure in response (Python traceback, SQL error, Java stack trace) |
| PM-ADV-SEC-001 | **High** | Secret / credential found in response body (AWS key, OpenAI key, GitHub PAT, JWT, …) |
| PM-ADV-MISC-002 | Medium | Wildcard CORS (`Access-Control-Allow-Origin: *`) on an authenticated endpoint |

### Attack Suite

| Attack | Safe Mode | Deep Mode | Description |
|--------|-----------|-----------|-------------|
| Auth Bypass | ✅ | ✅ | Strip auth header, null Bearer, empty Bearer, JWT alg=none, invalid token |
| BOLA / IDOR | ❌ | ✅ | Mutate numeric path segments (`/users/42` → `/users/43`, `/users/41`, `/users/1`) |
| Mass Assignment | ❌ | ✅ | Inject privileged fields into JSON body (`role: admin`, `isAdmin: true`, `is_staff: true`) |
| Injection | ❌ | ✅ | SQLi, NoSQLi, command injection, path traversal, XSS in query parameters |
| SSRF | ❌ | ✅ | Replace URL-like fields with cloud IMDS, Redis, and `file://` payloads |

### CLI Usage

```bash
# Passive scan — probe every endpoint in the collection
offensive-ai postman-scan collection.json

# Point the collection at a specific environment
offensive-ai postman-scan collection.json -T https://api.example.com

# Use a Postman environment file for variable resolution
offensive-ai postman-scan collection.json -e env.json -T https://api.example.com

# Add custom auth header
offensive-ai postman-scan collection.json \
  -T https://api.example.com \
  --header 'Authorization: Bearer <token>'

# LLM judge enrichment
offensive-ai postman-scan collection.json -T https://api.example.com --llm-judge

# JSON output
offensive-ai postman-scan collection.json -T https://api.example.com \
  --format json --output postman-scan.json

# Authorized active attack — safe mode (auth bypass only)
offensive-ai postman-attack collection.json --i-have-authorization \
  -T https://api.example.com

# Deep mode — all 5 OWASP API attack categories
offensive-ai postman-attack collection.json \
  --i-have-authorization --mode deep \
  -T https://api.example.com -e env.json --llm-judge

# Export attack report
offensive-ai postman-attack collection.json \
  --i-have-authorization --mode deep \
  --format json --output postman-attack.json
```

### Python API

```python
import asyncio
from offensive_ai import PostmanScanner, PostmanAttacker, PostmanVulnSeverity
from offensive_ai.core.llm_judge import LLMJudge
from offensive_ai.exceptions import AuthorizationRequired

async def main():
    judge = LLMJudge.from_env()   # reads GEMINI_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY

    # Passive scan
    scanner = PostmanScanner(
        collection_path="collection.json",
        environment_path="env.json",   # optional
        target_override="https://api.example.com",
        headers={"X-Custom-Header": "value"},
        timeout=10.0,
        verify_tls=True,
        max_endpoints=50,
        judge=judge,
    )
    result = await scanner.scan()

    print(f"Collection      : {result.collection_name}")
    print(f"Endpoints scanned: {result.endpoints_scanned}")
    print(f"Vulnerabilities : {len(result.all_vulns)}  Critical: {result.has_critical}")
    for vuln in result.all_vulns:
        print(f"  [{vuln.severity.value}] {vuln.check_id}: {vuln.title}")
        if vuln.evidence:
            print(f"    Evidence: {vuln.evidence[:80]}")
        if vuln.llm_reasoning:
            print(f"    LLM ({vuln.llm_confidence:.0%}): {vuln.llm_reasoning[:100]}")

    # Authorized active attack
    try:
        attacker = PostmanAttacker(authorized=True, judge=judge)
        report = await attacker.attack(
            collection_path="collection.json",
            environment_path="env.json",
            target_override="https://api.example.com",
            mode="deep",   # "safe" | "deep"
        )
        print(f"Attacks run     : {report.attacks_run}")
        print(f"Attacks triggered: {len(report.successful_attacks)}")
        if report.exploit_chain_summary:
            print(f"Exploit chain   : {report.exploit_chain_summary}")
        for r in report.successful_attacks:
            print(f"  [{r.severity.value}] {r.attack_id} ({r.attack_type}): {r.title}")
    except AuthorizationRequired:
        print("Pass authorized=True to unlock attack mode")

asyncio.run(main())
```

---

## AI OWASP Top 10 Scanner

Probes a live LLM/chat endpoint for the [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/). Designed for black-box testing — no model access required.

### Categories Covered

| ID | Category | Safe Mode | Deep Mode |
|----|----------|-----------|-----------|
| LLM01 | Prompt Injection | ✅ | ✅ |
| LLM02 | Sensitive Information Disclosure | ✅ | ✅ |
| LLM03 | Supply Chain | 🚫 | 🚫 |
| LLM04 | Data & Model Poisoning | 🚫 | 🚫 |
| LLM05 | Improper Output Handling (XSS/SQLi) | ✅ | ✅ |
| LLM06 | Excessive Agency | ✅ | ✅ |
| LLM07 | System Prompt Leakage | ✅ | ✅ |
| LLM08 | Vector & Embedding Weaknesses | 🚫 | 🚫 |
| LLM09 | Misinformation | ✅ | ✅ |
| LLM10 | Unbounded Consumption | ✅ | ✅ |

🚫 = Not externally testable via black-box probing

### CLI Usage

```bash
# Basic scan (safe mode, OpenAI-compatible endpoint)
offensive-ai ai-owasp-scan https://api.example.com/v1/chat/completions

# Deep mode with all probes
offensive-ai ai-owasp-scan https://api.example.com/v1/chat/completions --mode deep

# Specific categories only
offensive-ai ai-owasp-scan https://api.example.com/v1/chat/completions \
  --categories LLM01,LLM02,LLM07

# Generic/custom API format (non-OpenAI)
offensive-ai ai-owasp-scan https://chat.example.com/api/chat --api-format generic

# With authentication header
offensive-ai ai-owasp-scan https://api.example.com/v1/chat/completions \
  --header "Authorization: Bearer sk-..."

# JSON output
offensive-ai ai-owasp-scan https://api.example.com/v1/chat/completions --output results.json

# Enable LLM judge (requires OPENAI_API_KEY, ANTHROPIC_API_KEY, or GEMINI_API_KEY env var)
offensive-ai ai-owasp-scan https://api.example.com/v1/chat/completions --llm-judge
```

### Python API

```python
import asyncio
from offensive_ai import LLMOwaspScanner, LLMScanMode, LLMJudge

async def main():
    # Optional: enable LLM judge for smarter detection
    judge = LLMJudge.from_env()  # reads OPENAI_API_KEY / ANTHROPIC_API_KEY

    scanner = LLMOwaspScanner(
        endpoint="https://api.example.com/v1/chat/completions",
        mode=LLMScanMode.DEEP,
        categories=["LLM01", "LLM02", "LLM07"],
        api_format="openai",
        headers={"Authorization": "Bearer sk-..."},
        judge=judge,                # None = rule-based only
    )

    result = await scanner.scan()
    print(f"Grade: {result.overall_grade}  ({result.total_score} pts)")

    for cat_id, cat in result.categories.items():
        if cat.findings:
            print(f"\n{cat_id}: {cat.category_name}")
            for finding in cat.findings:
                print(f"  [{finding.severity.value}] {finding.title}")
                print(f"  Evidence: {finding.evidence[:80]}...")

asyncio.run(main())
```

### Severity & Grading

| Severity | Points |
|----------|--------|
| CRITICAL | 15 |
| HIGH | 10 |
| MEDIUM | 5 |
| LOW | 1 |

Grade: A (0–10), B (11–25), C (26–50), D (51–100), F (>100 or any CRITICAL finding).

### LLM Judge (Optional)

Install the `[ai]` extra and set an API key to enable smarter semantic detection:

```bash
pip install "offensive-ai[ai]"
export GEMINI_API_KEY="AIza..."       # Google Gemini  (1st priority)
export ANTHROPIC_API_KEY="sk-ant-..." # or Anthropic   (2nd priority)
export OPENAI_API_KEY="sk-..."        # or OpenAI      (3rd priority)
```

If multiple keys are set, Gemini is used first, then Anthropic, then OpenAI.
Without the extra, detection falls back to rule-based pattern matching.

---

## MCP Security Scanner

Scans [Model Context Protocol](https://modelcontextprotocol.io) servers for security vulnerabilities. Supports HTTP/SSE transports (remote URL) and stdio transport (local subprocess).

### CVEs / Checks Performed

| Check | Description |
|-------|-------------|
| Unauthenticated Exposure | Server accessible without credentials |
| Tool Poisoning | Malicious instructions hidden in tool descriptions |
| Path Traversal in Resources | `../` patterns in resource URIs |
| Command Injection | Shell metacharacters in tool params |
| Secrets in Descriptions | API keys, passwords leaked in tool/resource descriptions |
| Excessive Agency | Unrestricted file system or network tools |
| Prompt Injection via Tool Response | LLM instruction injection through tool output |
| Rug-pull / Tool Shadowing | Tool behavior changed post-trust-establishment |

### CLI Usage

```bash
# Scan HTTP/SSE MCP endpoint
offensive-ai mcp-scan https://mcp.example.com/mcp

# Scan local stdio server
offensive-ai mcp-scan --transport stdio --cmd "npx @example/mcp-server"

# With authentication
offensive-ai mcp-scan https://mcp.example.com/mcp \
  --header "Authorization: Bearer token"

# JSON output
offensive-ai mcp-scan https://mcp.example.com/mcp --output mcp-scan.json

# With LLM judge for enriched triage
offensive-ai mcp-scan https://mcp.example.com/mcp --llm-judge
offensive-ai mcp-attack https://mcp.example.com/mcp --i-have-authorization --llm-judge
```

### Python API

```python
import asyncio
from offensive_ai import MCPScanner, MCPTransport

async def main():
    # HTTP transport
    scanner = MCPScanner(
        target="https://mcp.example.com/mcp",
        transport=MCPTransport.HTTP,
        headers={"Authorization": "Bearer token"},
        judge=LLMJudge.from_env(),  # optional: enriches MEDIUM/LOW findings
    )
    result = await scanner.scan()

    print(f"Server: {result.server_info.name} v{result.server_info.version}")
    print(f"Tools: {len(result.tools)}, Resources: {len(result.resources)}")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")

    for vuln in result.vulnerabilities:
        print(f"  [{vuln.severity.value}] {vuln.title}: {vuln.description}")

    # Stdio transport
    scanner = MCPScanner(
        target="stdio://local",
        transport=MCPTransport.STDIO,
        cmd=["npx", "@example/mcp-server"],
    )
    result = await scanner.scan()

asyncio.run(main())
```

---

## MCP Attacker

Performs active security testing against MCP servers. **Requires explicit authorization.**

### Attack Suite

| Attack | Safe Mode | Deep Mode | Description |
|--------|-----------|-----------|-------------|
| Auth Bypass | ✅ | ✅ | Null token, empty bearer, X-Forwarded-For injection |
| Path Traversal | ❌ | ✅ | `/etc/passwd`, `.env`, `shadow` file read attempts |
| Tool Injection | ❌ | ✅ | Malicious payload in tool call arguments |
| Command Injection | ❌ | ✅ | Shell metacharacter injection in tool params |

### CLI Usage

```bash
# Safe mode (auth bypass only) — must provide --i-have-authorization
offensive-ai mcp-attack https://mcp.example.com/mcp --i-have-authorization

# Deep mode (all attacks)
offensive-ai mcp-attack https://mcp.example.com/mcp \
  --i-have-authorization --mode deep

# JSON output
offensive-ai mcp-attack https://mcp.example.com/mcp \
  --i-have-authorization --output attack-report.json
```

### Python API

```python
import asyncio
from offensive_ai import MCPAttacker, MCPScanner, AuthorizationRequired

async def main():
    # Authorization is enforced at instantiation
    try:
        bad = MCPAttacker()               # raises AuthorizationRequired
    except AuthorizationRequired:
        pass

    attacker = MCPAttacker(authorized=True)

    # Optional: use scan result to guide attacks
    scanner = MCPScanner("https://mcp.example.com/mcp")
    scan_result = await scanner.scan()

    report = await attacker.attack(
        target="https://mcp.example.com/mcp",
        transport="http",
        mode="deep",
        scan_result=scan_result,
    )

    print(f"Attacks run: {report.attacks_run}")
    print(f"Triggered: {len(report.triggered_results)}")
    for r in report.triggered_results:
        print(f"  [{r.severity.value}] {r.title}")

asyncio.run(main())
```

---

## OIDC / OAuth 2.0 / SAML Auth Protocol Security

Passive scanner and authorized attacker for identity provider endpoints across OIDC, OAuth 2.0, and SAML 2.0. Requires no credentials — all probes are passive HTTP requests unless attack mode is explicitly enabled.

### Security Checks

| Check ID | Protocol | Severity | Description |
|----------|----------|----------|-------------|
| OAI-AUTH-PKCE-001 | OIDC/OAuth2 | HIGH | PKCE not supported |
| OAI-AUTH-PKCE-002 | OIDC/OAuth2 | MEDIUM | PKCE supported but not required |
| OAI-AUTH-IMPL-001 | OIDC/OAuth2 | HIGH | Implicit flow enabled |
| OAI-AUTH-JWTALGN-001 | OIDC | HIGH | alg=none accepted in JWKS |
| OAI-AUTH-STATE-001 | OIDC/OAuth2 | MEDIUM | State parameter not enforced |
| OAI-AUTH-JWKS-001 | OIDC | LOW | JWKS endpoint lacks cache-control |
| OAI-AUTH-SAML-NOSIG | SAML | HIGH | No signing certificate in metadata |
| OAI-AUTH-SAML-NOACS | SAML | MEDIUM | No AssertionConsumerService endpoint |
| OAI-AUTH-SAML-XSW | SAML | INFO | XML Signature Wrapping attack surface |

### CVE Database (sample)

| CVE | Severity | Description |
|-----|----------|-------------|
| CVE-2019-3778 | CRITICAL | Spring Security OAuth — open redirect via malformed redirect_uri |
| CVE-2017-11427 | HIGH | SAML XSW — Shibboleth/OneLogin signature wrapping |
| CVE-2018-0489 | HIGH | SAML XSW — Shibboleth SP unsigned assertion acceptance |
| CVE-2023-41900 | HIGH | Keycloak — session fixation via OIDC back-channel logout |
| AUTH-ADV-PKCE | HIGH | Missing PKCE enables authorization code interception |
| AUTH-ADV-IMPLICIT | HIGH | Implicit flow exposes tokens in browser history |
| AUTH-ADV-STATE | HIGH | Missing state parameter enables CSRF on authorization code |
| AUTH-ADV-ALGNONE | CRITICAL | alg=none JWT accepted — authentication bypass |

### CLI Usage

```bash
# Auto-detect protocol (OIDC/OAuth2/SAML)
offensive-ai auth-scan https://auth.example.com

# Explicitly probe SAML metadata
offensive-ai auth-scan https://idp.example.com --protocol saml

# Use public test IdP
offensive-ai auth-scan https://mocksaml.com/api/saml/metadata --protocol saml

# OIDC scan with LLM judge (shows "LLM Judge: gemini" in output)
offensive-ai auth-scan https://accounts.google.com --llm-judge

# Custom auth headers / TLS skip
offensive-ai auth-scan https://internal-idp.corp.example.com \
  --header "Authorization: Bearer token" --no-tls-verify

# JSON output
offensive-ai auth-scan https://auth.example.com --format json --output auth-scan.json

# Active attack — safe mode (open redirect, state bypass, PKCE bypass)
offensive-ai auth-attack https://auth.example.com --i-have-authorization

# Deep mode (adds JWT alg=none, scope escalation, token replay, SAML XSW, JWKS confusion)
offensive-ai auth-attack https://auth.example.com \
  --i-have-authorization --mode deep --llm-judge

# Export attack report
offensive-ai auth-attack https://auth.example.com \
  --i-have-authorization --mode deep --format json --output auth-attack.json
```

### Python API

```python
import asyncio
from offensive_ai import AuthScanner, AuthAttacker, AuthProtocol, LLMJudge
from offensive_ai.exceptions import AuthorizationRequired

async def main():
    # Optional LLM judge
    judge = LLMJudge.from_env()   # reads GEMINI_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY

    # --- Passive scan (OIDC/OAuth2 auto-detect) ---
    scanner = AuthScanner(
        target="https://accounts.google.com",
        protocol="auto",           # "auto" | "oidc" | "oauth2" | "saml"
        judge=judge,               # None = rule-based only
        timeout=15.0,
        verify_tls=True,
    )
    result = await scanner.scan()
    print(f"Protocol  : {result.protocol.value}")
    print(f"Provider  : {result.provider_info.name}")
    print(f"Issuer    : {result.provider_info.issuer}")
    print(f"PKCE req  : {result.provider_info.pkce_required}")
    print(f"Implicit  : {result.provider_info.implicit_flow_enabled}")
    for vuln in result.all_vulns:
        print(f"  [{vuln.severity.value}] {vuln.vuln_id}: {vuln.title}")
        if vuln.cve_id:
            print(f"    CVE: {vuln.cve_id}")

    # --- Passive SAML scan ---
    saml_scanner = AuthScanner(
        target="https://mocksaml.com/api/saml/metadata",
        protocol="saml",
    )
    saml_result = await saml_scanner.scan()
    print(f"SAML entityID : {saml_result.provider_info.issuer}")
    print(f"Signing certs : {saml_result.provider_info.raw.get('signing_cert_count', 0)}")

    # --- Authorized active attack ---
    try:
        attacker = AuthAttacker(authorized=True)
        report = await attacker.attack(
            target="https://auth.example.com",
            mode="safe",           # "safe" | "deep"
            judge=judge,
        )
        print(f"Attacks run     : {report.attacks_run}")
        print(f"Attacks triggered: {report.attacks_triggered}")
        for r in report.triggered_results:
            print(f"  [{r.severity.value}] {r.title}")
            print(f"    Evidence: {r.evidence[:80]}...")
    except AuthorizationRequired:
        print("Pass authorized=True to unlock attack mode")

asyncio.run(main())
```

See [auth.md](https://docs.offensive-ai.org/auth) for the full guide including CVE detail, remediation advice, and SAML testing tips.

---

## OpenClaw Gateway Security

[OpenClaw](https://github.com/openclaw/openclaw) is a self-hosted AI-assistant gateway that bridges messaging platforms (Telegram, Discord, Slack, etc.) to LLM backends. Because OpenClaw instances are often internet-exposed, misconfigurations lead to unauthenticated LLM access, conversation history disclosure, SSRF, and prompt injection surfaces.

### Scanner (`openclaw-scan`)

Five-phase **passive** assessment — no exploitation:

| Phase | What it does |
|-------|--------------|
| 1 — Fingerprint | Probe `/health`, `/status`, `/api/v1/status`; match headers/body against OpenClaw signatures; extract version and gateway ID |
| 2 — Endpoint Enumeration | Probe all known API paths (`/api/v1/*`, `/ws/*`, `/webhooks`); flag endpoints leaking API keys or tokens in response bodies |
| 3 — Authentication Posture | Detect unauthenticated REST API access; probe for unauthenticated WebSocket upgrade on `/ws` and `/api/v1/ws` |
| 4 — Configuration Assessment | Parse `/api/v1/config` for DM policy and sandbox mode settings |
| 5 — CVE / Misconfiguration | Cross-reference findings against advisory database; produce severity-ranked vulnerability list |

### Advisory Database

| ID | Severity | Finding |
|----|----------|---------|
| OCL-ADV-001 | **Critical** | Unauthenticated REST API access |
| OCL-ADV-002 | **High** | Open DM policy — all channels accepted |
| OCL-ADV-003 | **High** | Sandbox mode disabled |
| OCL-ADV-004 | **High** | Unauthenticated WebSocket connection |
| OCL-ADV-005 | Medium | Health/status endpoint information disclosure |
| OCL-ADV-006 | Medium | Webhook automation SSRF risk |
| OCL-ADV-007 | Medium | Session history and message log exposure |
| OCL-ADV-008 | Medium | Model API key leakage via config endpoint |
| OCL-ADV-009 | Low | Gateway version fingerprinting |
| OCL-ADV-010 | Info | OpenClaw instance fingerprint |

### CLI Usage

```bash
# Passive scan — fingerprint and report misconfigurations
offensive-ai openclaw-scan 192.168.1.10

# Custom port / TLS
offensive-ai openclaw-scan gateway.example.com --port 18789 --tls

# With bearer token (authenticated scan)
offensive-ai openclaw-scan gateway.example.com \
    --header "Authorization: Bearer <token>"

# Export JSON report
offensive-ai openclaw-scan 192.168.1.10 --format json --output report.json

# Active attack (requires explicit authorization flag)
offensive-ai openclaw-attack 192.168.1.10 --i-have-authorization

# Deep mode — message injection + WebSocket + SSRF probes
offensive-ai openclaw-attack 192.168.1.10 --i-have-authorization --mode deep

# Export attack report
offensive-ai openclaw-attack 192.168.1.10 --i-have-authorization \
    --mode deep --format json --output attack.json
```

### Python API

```python
import asyncio
from offensive_ai.core.openclaw_scanner import OpenClawScanner
from offensive_ai.core.openclaw_attacker import OpenClawAttacker
from offensive_ai.exceptions import AuthorizationRequired

async def main():
    # Passive scan
    scanner = OpenClawScanner(
        target="192.168.1.10",
        port=18789,
        use_tls=False,
    )
    result = await scanner.scan()

    print(f"OpenClaw detected : {result.openclaw_detected}")
    print(f"Version           : {result.version}")
    print(f"Unauthenticated   : {result.unauthenticated_access}")
    print(f"Vulnerabilities   : {len(result.vulnerabilities)}")
    for v in result.vulnerabilities:
        print(f"  [{v.severity}] {v.advisory_id}: {v.title}")

    # Authorized active attack
    try:
        attacker = OpenClawAttacker(authorized=True)
        report = await attacker.attack(
            target="192.168.1.10",
            port=18789,
            mode="safe",   # "safe" | "deep"
        )
        print(f"Attacks triggered : {len(report.triggered_results)}")
        for r in report.triggered_results:
            print(f"  [{r.severity}] {r.title}")
    except AuthorizationRequired as exc:
        print(exc)

asyncio.run(main())
```

See [openclaw.md](https://docs.offensive-ai.org/openclaw) for the full guide including remediation advice.

---

## Kubernetes Cluster Security

Black-box scanning and authorized red-team testing of exposed Kubernetes cluster components, aligned with the [OWASP Kubernetes Top 10 (2025)](https://owasp.org/www-project-kubernetes-top-ten/). No `kubernetes` SDK or kubeconfig required — all probes are over the network via `httpx`.

### Component Surface

| Component | Default Ports | Key Probes |
|-----------|--------------|------------|
| kube-apiserver | 6443, 443, 8080 | `/version`, `/healthz`, `/api`, anon `/api/v1/secrets`/`/pods`, `SelfSubjectAccessReview` |
| kubelet | 10250 (rw), 10255 (ro) | `/pods`, `/runningpods`, `/stats/summary`, `/spec`; `/exec` `/run` (attack) |
| etcd | 2379, 2380 | `/version`, `/health`, v2/v3 keys |
| scheduler / controller-mgr | 10259 / 10257 | `/healthz`, `/metrics` |
| kube-proxy / cAdvisor | 10249 / 4194 | `/healthz`, metrics |
| Dashboard | 8001, 30000–32767 | UI accessibility, auth posture |

### OWASP K8s Top 10 Coverage

| ID | Category | Black-box coverage |
|----|----------|-----------------|
| K01 | Insecure Workload Configurations | ⚠️ via kubelet `/pods` spec (privileged, hostPath, hostNetwork) |
| K02 | Overly Permissive Authorization | ⚠️ via anonymous `SelfSubjectAccessReview` (deep mode) |
| K03 | Secrets Management Failures | ⚠️ via anon apiserver `/api/v1/secrets` + kubelet env exposure |
| K04 | Lack of Cluster Policy Enforcement | 🔎 informational (admission webhook hints) |
| K05 | Missing Network Segmentation | 🔎 informational (exposed NodePort / internal services) |
| K06 | Overly Exposed Components | ✅ PRIMARY — all component ports probed for accessibility |
| K07 | Misconfigured / Vulnerable Components | ✅ `/version` → CVE match; insecure port 8080 detection |
| K08 | Cluster → Cloud Lateral Movement | ⚠️ cloud IMDS SSRF probes (deep mode) |
| K09 | Broken Authentication Mechanisms | ✅ anonymous-auth detection on apiserver + kubelet |
| K10 | Inadequate Logging and Monitoring | 🔎 informational only |

✅ Full coverage · ⚠️ Partial (deep mode or limited by anon access) · 🔎 Informational

### Advisory Database

| ID | CVE | Severity | Finding |
|----|-----|----------|---------|
| K8S-ADV-001 | — | **Critical** | kube-apiserver exposed without authentication |
| K8S-ADV-002 | — | **Critical** | Kubelet read-write port (10250) exposed without auth |
| K8S-ADV-003 | — | **High** | Kubelet read-only port (10255) accessible |
| K8S-ADV-004 | — | **Critical** | etcd accessible without authentication |
| K8S-ADV-005 | — | Medium | Kubernetes Dashboard exposed without auth |
| K8S-ADV-006 | — | **High** | Scheduler / controller-manager metrics port exposed |
| CVE-2018-1002105 | CVE-2018-1002105 | **Critical** | API server privilege escalation via API aggregation |
| CVE-2019-11253 | CVE-2019-11253 | **High** | API server DoS via malformed YAML/JSON |
| CVE-2020-8558 | CVE-2020-8558 | **High** | NodePort services reachable via loopback interface |
| CVE-2021-25741 | CVE-2021-25741 | **High** | Symlink + hardlink in volume path traversal |
| CVE-2022-3294 | CVE-2022-3294 | **High** | Node address bypass for node restriction admission plugin |

### CLI Usage

```bash
# Passive scan — probe all default K8s component ports
offensive-ai k8s-scan 192.168.1.100

# Target specific ports
offensive-ai k8s-scan k8s.example.com --port 6443 --port 10250

# With authentication header (semi-auth scan)
offensive-ai k8s-scan k8s.example.com \
    --header "Authorization: Bearer <token>"

# Enable LLM judge for finding triage and remediation advice
offensive-ai k8s-scan 192.168.1.100 --llm-judge

# Export JSON report
offensive-ai k8s-scan 192.168.1.100 --format json --output k8s-scan.json

# Authorized active attack (safe mode — anon reads + RBAC review)
offensive-ai k8s-attack 192.168.1.100 --i-have-authorization

# Deep mode — kubelet /exec, secret extraction, etcd dump, cloud IMDS SSRF
offensive-ai k8s-attack 192.168.1.100 --i-have-authorization --mode deep

# Export attack report
offensive-ai k8s-attack 192.168.1.100 --i-have-authorization \
    --mode deep --format json --output k8s-attack.json
```

### Python API

```python
import asyncio
from offensive_ai.core.k8s_scanner import K8sScanner
from offensive_ai.core.k8s_attacker import K8sAttacker
from offensive_ai.core.llm_judge import LLMJudge
from offensive_ai.exceptions import AuthorizationRequired

async def main():
    # Optional LLM judge — auto-detects OPENAI/ANTHROPIC/GEMINI key from env
    judge = LLMJudge()   # rule-based fallback when no key is set

    # Passive scan
    scanner = K8sScanner(
        target="192.168.1.100",
        ports=[6443, 10250, 2379],
        judge=judge,
    )
    result = await scanner.scan()

    print(f"Kubernetes detected : {result.is_kubernetes}")
    print(f"Version             : {result.server_info.git_version}")
    print(f"Exposed components  : {[c.component.value for c in result.exposed_components]}")
    print(f"OWASP coverage      : {result.owasp_coverage}")
    print(f"Vulnerabilities     : {len(result.vulnerabilities)}")
    for v in result.vulnerabilities:
        print(f"  [{v.severity.value}] {v.owasp_id} {v.vuln_id}: {v.title}")
        if v.llm_reasoning:
            print(f"    LLM: {v.llm_reasoning}")

    # Authorized active attack
    try:
        attacker = K8sAttacker(authorized=True, judge=judge)
        report = await attacker.attack(
            target="192.168.1.100",
            mode="safe",           # "safe" | "deep"
            scan_result=result,   # guides attack selection
        )
        print(f"Attacks run       : {len(report.attack_results)}")
        print(f"Succeeded         : {len(report.successful_attacks)}")
        for r in report.successful_attacks:
            print(f"  [{r.severity.value}] {r.owasp_id} {r.attack_id}: {r.description}")
    except AuthorizationRequired as exc:
        print(exc)

asyncio.run(main())
```

See [k8s.md](https://docs.offensive-ai.org/k8s) for the full guide including OWASP K8s Top 10 mapping, CVE database, attack sequences, and remediation advice.

---

## Infrastructure Scanning

### Port Scanner

```bash
offensive-ai scan example.com
offensive-ai scan example.com --ports 80,443,8080,8443
offensive-ai scan example.com google.com --output results.json
```

```python
from offensive_ai import PortChecker
import asyncio

async def main():
    checker = PortChecker()
    result = await checker.scan_host("example.com", ports=[80, 443, 8080])
    open_ports = [p for p in result.ports if p.is_open]
    print(f"Open: {[p.port for p in open_ports]}")

asyncio.run(main())
```

### L7 Protection Detection

```bash
offensive-ai l7-check example.com
offensive-ai l7-check example.com --trace-dns
offensive-ai full-scan example.com
```

### SSL/TLS Certificate Analysis

```bash
offensive-ai cert-check example.com
offensive-ai cert-chain github.com
offensive-ai cert-info google.com
```

```python
from offensive_ai import CertificateAnalyzer
import asyncio

async def main():
    analyzer = CertificateAnalyzer()
    chain = await analyzer.analyze_certificate_chain("example.com", 443)
    print(f"Subject: {chain.server_cert.subject}")
    print(f"Issuer: {chain.server_cert.issuer}")
    print(f"Chain complete: {chain.chain_complete}")
    print(f"Days until expiry: {chain.server_cert.days_until_expiry}")

asyncio.run(main())
```

### mTLS Checker

```bash
offensive-ai mtls-check example.com
offensive-ai mtls-check example.com --client-cert client.crt --client-key client.key
offensive-ai mtls-gen-cert test-client.example.com
offensive-ai mtls-validate-cert client.crt client.key
```

### OWASP Top 10 Web Scanner (2021 & 2025)

```bash
offensive-ai owasp-scan example.com
offensive-ai owasp-scan example.com --deep
offensive-ai owasp-scan example.com -c A02,A05,A07 -t nginx --verbose

# With LLM judge — enriches MEDIUM/LOW findings, shows "LLM Judge: gemini" in panel
offensive-ai owasp-scan example.com --llm-judge
offensive-ai owasp-scan example.com --deep --llm-judge --verbose

offensive-ai owasp-scan example.com -f pdf -o report.pdf
```

### Hybrid Identity Detection

```bash
offensive-ai hybrid-identity example.com
offensive-ai hybrid-identity example.com --verbose --output results.json
```

---

## All CLI Commands

```
offensive-ai --help

Commands:
  ai-owasp-scan       Probe a live LLM/AI endpoint for AI OWASP Top 10
  mcp-scan            Scan an MCP endpoint for security vulnerabilities
  mcp-attack          Perform authorized active testing against an MCP server
  a2a-scan            Scan an A2A (Agent-to-Agent) protocol agent for security vulnerabilities
  a2a-attack          Authorized active attack against an A2A agent endpoint
  openclaw-scan       Five-phase passive security scan of an OpenClaw AI gateway
  openclaw-attack     Authorized active attack against an OpenClaw gateway
  k8s-scan            Black-box Kubernetes cluster security scan (OWASP K8s Top 10)
  k8s-attack          Authorized active red-team attack against Kubernetes components
  auth-scan           Passive OIDC / OAuth 2.0 / SAML auth protocol security scan
  auth-attack         Authorized active attack against auth/identity endpoints
  blockchain-scan     Scan a blockchain JSON-RPC endpoint (Ethereum/EVM) for security issues
  blockchain-attack   Authorized active attack against a blockchain JSON-RPC node
  blockchain-contract-audit  Heuristic static analysis of a smart contract ABI/bytecode
  postman-scan        Passively scan every API endpoint defined in a Postman Collection v2.x
  postman-attack      Perform authorized active security testing against a Postman Collection
  scan                Scan target hosts for open ports
  l7-check            Check for L7 protection services (WAF, CDN, etc.)
  full-scan           Port scan + L7 protection detection
  cert-check          Analyze SSL/TLS certificate chain
  cert-chain          Analyze complete certificate chain and trust path
  cert-info           Show detailed certificate information
  dns-trace           Trace DNS records and analyze L7 protection
  owasp-scan          OWASP Top 10 2021/2025 vulnerability scanner (--llm-judge supported)
  hybrid-identity     Check for Azure AD/ADFS hybrid identity setup
  mtls-check          Check for mTLS authentication support
  mtls-gen-cert       Generate a self-signed certificate for mTLS testing
  mtls-validate-cert  Validate client certificate and private key files
  service-detect      Detect service version and information
```

---

## Docker

The image is published to two registries on every version tag:

| Registry | Image |
|----------|-------|
| Docker Hub | `htunnthuthu/offensive-ai` |
| GitHub Container Registry | `ghcr.io/htunn/offensive-ai` |

```bash
# Docker Hub
docker run --rm htunnthuthu/offensive-ai:latest ai-owasp-scan https://api.example.com/v1/chat/completions
docker run --rm htunnthuthu/offensive-ai:latest mcp-scan https://mcp.example.com/mcp
docker run --rm htunnthuthu/offensive-ai:latest a2a-scan https://agent.example.com
docker run --rm htunnthuthu/offensive-ai:latest scan example.com
docker run --rm htunnthuthu/offensive-ai:latest owasp-scan example.com
# Mount a local collection for postman-scan / postman-attack
docker run --rm -v $(pwd):/work htunnthuthu/offensive-ai:latest \
  postman-scan /work/collection.json -T https://api.example.com
docker run --rm -v $(pwd):/work htunnthuthu/offensive-ai:latest \
  postman-attack /work/collection.json --i-have-authorization --mode deep -T https://api.example.com

# GitHub Container Registry (ghcr.io) — no Docker Hub account required
docker run --rm ghcr.io/htunn/offensive-ai:latest ai-owasp-scan https://api.example.com/v1/chat/completions
docker run --rm ghcr.io/htunn/offensive-ai:latest a2a-scan https://agent.example.com
docker run --rm ghcr.io/htunn/offensive-ai:latest scan example.com
docker run --rm -v $(pwd):/work ghcr.io/htunn/offensive-ai:latest \
  postman-scan /work/collection.json -T https://api.example.com

# Save output to host
docker run --rm -v $(pwd):/app/output ghcr.io/htunn/offensive-ai:latest \
  ai-owasp-scan https://api.example.com/v1/chat/completions \
  --output /app/output/llm-report.json

# LLM Judge — openai, anthropic, or gemini key auto-detected; no extra install needed
docker run --rm \
  -e OPENAI_API_KEY=sk-... \
  ghcr.io/htunn/offensive-ai:latest \
  ai-owasp-scan https://api.example.com/v1/chat/completions --llm-judge

# Custom OpenAI-compatible backend (Ollama, LM Studio, Azure OpenAI…)
docker run --rm \
  -e OFFENSIVE_AI_LLM_BASE_URL=http://host.docker.internal:11434/v1 \
  -e OFFENSIVE_AI_LLM_MODEL=llama3 \
  ghcr.io/htunn/offensive-ai:latest \
  ai-owasp-scan https://api.example.com/v1/chat/completions --llm-judge
```

See [Docker documentation](https://docs.offensive-ai.org) for the full Docker reference including CI/CD integration, Kubernetes jobs, Makefile publish targets, and troubleshooting.

---

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | Enable OpenAI-based LLM judge |
| `ANTHROPIC_API_KEY` | Enable Anthropic-based LLM judge |
| `OFFENSIVE_AI_LLM_BASE_URL` | Custom OpenAI-compatible base URL for LLM judge |

### Optional Extras

```bash
pip install "offensive-ai[ai]"   # Adds openai + anthropic for LLM judge
```

---

## Security & Ethics

This tool is designed for **authorized security assessments only**.

- Active attack features display an authorization banner and require `--i-have-authorization`
- `MCPAttacker(authorized=False)` raises `AuthorizationRequired` at instantiation — cannot be bypassed
- Default scan modes are passive (safe mode) and will not modify target systems
- Do not use against systems you do not own or lack explicit written permission to test

Please review [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md) before contributing.

---

## Requirements

- Python 3.12+
- See [requirements.txt](requirements.txt) for full dependency list

---

## License

MIT — see [LICENSE](LICENSE)
