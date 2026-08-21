# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.7.0] - 2026-07-09

### Added

- **Postman Collection Security Scanner & Attacker** — full Postman Collection v2.x support:
  - `PostmanScanner` — passive multi-phase assessment: parses collection, resolves `{{variables}}` from environment files, probes each endpoint, runs static analysis (missing auth on sensitive endpoints, unresolved variables, verbose error disclosure, secrets in responses, wildcard CORS), and optionally triages findings via LLM judge
  - `PostmanAttacker` — authorization-gated active testing with **safe mode** (auth-bypass probes) and **deep mode** (auth bypass + BOLA/IDOR + mass assignment + injection + SSRF); LLM judge synthesises `exploit_chain_summary`
  - `src/offsec_ai/models/postman_result.py` — Pydantic models: `PostmanScanResult`, `PostmanEndpoint`, `PostmanVulnerability`, `PostmanEndpointResult`, `PostmanAuthInfo`, `PostmanAttackReport`, `PostmanAttackResult`, `PostmanVulnSeverity`
  - `src/offsec_ai/utils/postman_findings.py` — 10 secret-leak regex patterns (AWS keys, OpenAI keys, GitHub PATs, JWTs, etc.), sensitive endpoint keywords, verbose error signatures
  - `src/offsec_ai/utils/postman_payloads.py` — attack payloads across 5 OWASP API Top 10 categories: auth bypass, BOLA ID mutations, mass assignment, injection, SSRF
  - `src/offsec_ai/utils/postman_parser.py` — recursive Postman Collection v2.x folder flattening, variable resolution with unresolved-variable tracking, target override, body/query/header/path-param extraction
  - `postman-scan` CLI command with `--environment`, `--target/-T`, `--header`, `--timeout`, `--no-tls-verify`, `--max-endpoints`, `--format`, `--output`, `--llm-judge` options
  - `postman-attack` CLI command with `--i-have-authorization` (required), `--mode safe|deep`, and all scan options
  - All Postman types exported from `offsec_ai` package `__all__`
  - 63 new tests in `tests/test_postman.py` covering payloads, findings, parser, result models, scanner static analysis, HTTP-mocked integration, and attacker

## [2.6.0] - 2026-07-08

### Added

- **A2A (Agent-to-Agent) Protocol Security** — full support for Google's open A2A standard (a2a-protocol.org v1.0.0):
  - `A2AScanner` — 8-phase passive assessment: fetches Agent Card (`/.well-known/agent-card.json`), parses skills/capabilities/security schemes, probes auth posture via unauthenticated `SendMessage` JSON-RPC, performs static analysis, matches CVEs, and optionally triages findings via LLM judge
  - `A2AAttacker` — authorization-gated active testing with **safe mode** (auth-bypass probes) and **deep mode** (auth bypass + SSRF webhook + message injection + task enumeration + JSON-RPC manipulation)
  - `src/offsec_ai/models/a2a_result.py` — Pydantic models: `A2AScanResult`, `A2AAgentCard`, `A2ASkill`, `A2ACapabilities`, `A2AAuthPosture`, `A2AVulnerability`, `A2AAttackReport`, `A2AAttackResult`, `A2AVulnSeverity`
  - `src/offsec_ai/utils/a2a_cve_db.py` — 10 A2A security advisories (A2A-ADV-2025-001 through 010); regex-based secret scanner; dangerous-keyword scanner for skill descriptions
  - `src/offsec_ai/utils/a2a_payloads.py` — 22 attack payloads across 5 categories: auth bypass, SSRF webhook, message injection, task enumeration, JSON-RPC manipulation
  - `a2a-scan` CLI command with `--port`, `--header`, `--timeout`, `--no-tls-verify`, `--format`, `--output`, `--llm-judge` options
  - `a2a-attack` CLI command with `--i-have-authorization` (required), `--mode safe|deep`, and the same output options
  - All A2A types exported from `offsec_ai` package `__all__`
  - 58 new tests in `tests/test_a2a_scanner.py` covering CVE DB, payloads, models, scanner static analysis, HTTP-mocked integration, and attacker

### Changed

- `README.md` updated with v2.6.0 feature table, full A2A section (security checks, advisory database, CLI usage, attack suite, Python API), Quick Start examples, and updated All CLI Commands list
- Banner tagline updated to `AI/LLM · MCP · A2A · Red-Team`
- Legal notice updated to include `a2a-attack` in the list of commands requiring `--i-have-authorization`

## [2.5.1] - 2026-07-04

### Changed

- **Test coverage raised to 80%** — expanded test suite from ~53% to 80% (industry-standard threshold), adding 25+ new test files and 1325 passing tests across all core modules: `auth_scanner`, `cert_analyzer`, `cli`, `guardrail_bench`, `hybrid_identity_checker`, `k8s_scanner`, `l7_detector`, `llm_conversation_attacker`, `llm_judge`, `mcp_attacker`, `mcp_scanner`, `mtls_checker`, `owasp_scanner`, `port_scanner`, and `security_headers`.

## [2.5.0] - 2026-07-03

### Added

- **`--llm-judge` support for `owasp-scan`** — OWASP Web Scanner now integrates LLM judge triage:
  - `OwaspScanner(judge=judge)` constructor parameter accepts a `LLMJudge` instance
  - `_triage_with_llm(findings)` internal method: iterates MEDIUM/LOW findings, calls `judge.evaluate()`, stores `llm_reasoning` and `llm_confidence`; promotes LOW→MEDIUM when `llm_confidence > 0.7`
  - `--llm-judge` CLI flag added to `owasp-scan` command
  - Verbose mode displays `LLM (X%): reasoning` per finding in the detailed findings table

- **New fields on `OwaspFinding` model** (Pydantic v2, optional):
  - `llm_reasoning: str | None` — LLM judge reasoning text for this finding
  - `llm_confidence: float | None` — Confidence score (0.0–1.0); > 0.7 triggers severity promotion

- **Universal "powered by" display across all 9 `--llm-judge` commands**: each command now shows:
  - `LLM Judge: gemini` (or `openai` / `anthropic` / `Disabled`) inside the Rich result Panel
  - `LLM Judge powered by: gemini` as a formatted footer line after the Panel
  - Applies to: `owasp-scan`, `ai-owasp-scan`, `mcp-scan`, `mcp-attack`, `openclaw-scan`, `openclaw-attack`, `k8s-scan`, `k8s-attack`, `auth-scan`, `auth-attack`

### Fixed

- **`k8s-scan` / `k8s-attack` `LLMJudge` constructor bug**: both commands previously used `LLMJudge()` directly (invalid — no public no-arg constructor), bypassing `is_available()` and potentially crashing when no API key was set. Fixed to use the canonical `LLMJudge.from_env()` + `is_available()` pattern, consistent with all other commands.

### Changed

- `pyproject.toml`: version bumped `2.4.0` → `2.5.0`
- `README.md`: v2.5.0 feature table added; OWASP scanner section updated with `--llm-judge` examples; CLI command table adds `auth-scan` / `auth-attack`
- `docs/api.md`: `OwaspScanner` constructor docs updated (added `judge` param); `OwaspFinding` model docs updated (added `llm_reasoning`, `llm_confidence` fields); OWASP CLI usage block added

---

## [2.4.0] - 2026-07-01

### Added — LLM Judge Integration Across All Tools

- **LLM Judge** wired into MCP scanner (`mcp-scan`) and attacker (`mcp-attack`):
  - `MCPScanner(judge=judge)` — Phase 5 LLM triage upgrades LOW→MEDIUM findings when `llm_confidence > 0.7`
  - `MCPAttacker(authorized=True, judge=judge)` — `_enrich_with_llm()` appends LLM analysis to triggered attack results
  - New fields on `MCPVulnerability`: `llm_confidence: float | None`, `llm_reasoning: str`

- **LLM Judge** wired into OpenClaw scanner (`openclaw-scan`) and attacker (`openclaw-attack`):
  - `OpenClawScanner(judge=judge)` — Phase 6 LLM triage (new phase) upgrades LOW→MEDIUM findings when `llm_confidence > 0.7`
  - `OpenClawAttacker(authorized=True, judge=judge)` — `_enrich_with_llm()` appends LLM analysis to attack results
  - New fields on `OpenClawVulnerability`: `llm_confidence: float | None`, `llm_reasoning: str`

- `--llm-judge` CLI flag added to `mcp-scan`, `mcp-attack`, `openclaw-scan`, `openclaw-attack`
  (k8s and ai-owasp-scan already had it; all 7 commands now consistent)

### Changed

- **Removed Azure OpenAI support** — `AZURE_OPENAI_API_KEY` / `AZURE_OPENAI_ENDPOINT` no longer
  detected; `_evaluate_azure()` removed from `LLMJudge`
- **Provider priority order changed**: Gemini (highest) → Anthropic → OpenAI (lowest)
  - `_detect_provider()` now checks `GEMINI_API_KEY` first, then `ANTHROPIC_API_KEY`, then `OPENAI_API_KEY`
  - Docstring and all CLI `--llm-judge` help text updated to reflect new priority
- `--judge` flag on `ai-owasp-scan` renamed to `--llm-judge` for consistency across all commands
- All warning messages updated to list providers as: `GEMINI_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY`
- `pyproject.toml`: version bumped `2.3.0` → `2.4.0`
- `README.md`, `docs/k8s.md`, `docs/openclaw.md`, `docs/owasp-scanner.md` updated with new
  provider priority order, `--llm-judge` flag on all commands, and Gemini examples

---

## [2.3.0] - 2026-06-30

### Added — Kubernetes Cluster Security Scanner and Attacker

- **⎈ Kubernetes Scanner** (`offsec_ai.core.k8s_scanner.K8sScanner`)
  - Black-box five-phase scan of exposed Kubernetes cluster components over the network
    (no `kubernetes` SDK, no kubeconfig required)
  - **Phase 1 — Component Discovery**: probes all well-known K8s component ports
    (6443/443/8080 apiserver, 10250/10255 kubelet, 2379/2380 etcd, 10259 scheduler,
    10257 controller-manager, 10249 kube-proxy, 4194 cAdvisor, dashboard NodePorts)
  - **Phase 2 — Version & CVE Matching**: fingerprints cluster version via `/version`;
    matches against 11-entry CVE/advisory database covering
    CVE-2018-1002105, CVE-2019-11253, CVE-2020-8558, CVE-2021-25741, CVE-2022-3294,
    and `K8S-ADV-001` through `K8S-ADV-006`
  - **Phase 3 — Auth Posture (K09)**: detects anonymous-auth on apiserver and kubelet;
    tests unauthenticated access to `/api`, `/healthz`, kubelet `/pods`, etcd `/health`
  - **Phase 4 — Exposure & Workload Audit (K01/K03/K06)**: reads kubelet `/pods` for
    privileged containers, `hostPath` mounts, `hostNetwork`/`hostPID` specs; probes
    apiserver for anonymous `/api/v1/secrets` and `/api/v1/configmaps` access
  - **Phase 5 — OWASP Map + LLM Triage**: deduplicated findings mapped to K01–K10;
    optional `LLMJudge` sets `llm_confidence` + `llm_reasoning` on each vulnerability
    and enriches remediation text
  - Response body capped at 64 KB per request (`_MAX_RESPONSE_BYTES = 65_536`)
  - `trust_env=False`, `verify=False` on `httpx.AsyncClient` (consistent with all modules)
  - CLI command: `offsec-ai k8s-scan`

- **⚔️ Kubernetes Attacker** (`offsec_ai.core.k8s_attacker.K8sAttacker`)
  - Hard authorization gate: `K8sAttacker(authorized=False)` raises `AuthorizationRequired`;
    `--i-have-authorization` required at CLI
  - Accepts optional `judge` (`LLMJudge`) for attack-path narrative generation
  - **Safe mode** (passive read probes — no destructive operations):
    anonymous apiserver resource list, kubelet `/pods` enumeration,
    `SelfSubjectAccessReview` RBAC privilege audit (K02), etcd `/health` probe
  - **Deep mode** (full suite — adds):
    kubelet `/exec` command execution (K06), anonymous secret extraction (K03),
    etcd key dump (K03), cloud IMDS/metadata SSRF probes for AWS/GCP/Azure (K08)
  - Response body capped at 4 KB per attack request
  - CLI command: `offsec-ai k8s-attack`

- **New models** (`offsec_ai.models.k8s_result`):
  `K8sScanResult`, `K8sAttackReport`, `K8sAttackResult`, `K8sVulnerability`,
  `K8sExposedComponent`, `K8sServerInfo`, `K8sVulnSeverity`, `K8sComponent`

- **New utilities**:
  - `offsec_ai.utils.k8s_cve_db` — `K8sCVEEntry` dataclass, `K8S_CVE_DB` (11 entries),
    `match_cves(version, accessible_components)` with component-boundary-safe version matching
  - `offsec_ai.utils.k8s_payloads` — `K8S_DEFAULT_SCAN_PORTS`, `K8S_COMPONENT_PORTS`,
    `APISERVER_PROBE_PATHS`, `KUBELET_PROBE_PATHS`, `ETCD_PROBE_PATHS`,
    `ANONYMOUS_API_PATHS`, `K8S_FINGERPRINTS`, `KUBELET_EXEC_PAYLOADS`,
    `CLOUD_METADATA_PAYLOADS`, `SELF_SUBJECT_REVIEW_PAYLOAD`

- **Tests**: 43 new tests in `tests/test_k8s_scanner.py` and `tests/test_k8s_attacker.py`
  covering CVE DB integrity and version matching, payload structure, result model properties,
  component fingerprinting (positive/negative), version/CVE detection, anonymous-auth detection,
  secret/workload exposure, LLM judge wiring, attacker authorization gating, safe vs deep mode,
  and JSON serialization — 238 tests total (up from 195)

### Changed
- `src/offsec_ai/cli.py`: added `k8s-scan` and `k8s-attack` commands with `--port` (multiple),
  `--header`, `--timeout`, `--llm-judge`, `--format`, `--output` options; `k8s-attack`
  additionally requires `--i-have-authorization` and `--mode safe|deep`
- `src/offsec_ai/__init__.py`: exported `K8sScanner`, `K8sAttacker`, `K8sScanResult`,
  `K8sAttackReport`, `K8sVulnerability`, `K8sComponent`, `K8sVulnSeverity`
- `pyproject.toml`: version bumped `2.2.0` → `2.3.0`

---

## [2.2.0] - 2026-06-30

### Added — AI/LLM Attack Expansion (Track A)

- **🗡️ Jailbreak Technique Library** (`offsec_ai.utils.llm_jailbreaks`)
  - DAN (Do Anything Now) variants, developer-mode bypass, roleplay/persona injection,
    refusal-suppression patterns, hypothetical framing, payload-splitting
  - Each technique carries OWASP LLM category refs, expected severity, and response detection strings
  - Constants: `DAN_TECHNIQUES`, `ROLEPLAY_TECHNIQUES`, `REFUSAL_SUPPRESSION_TECHNIQUES`,
    `HYPOTHETICAL_TECHNIQUES`, `PAYLOAD_SPLITTING_TECHNIQUES`, `JAILBREAK_TECHNIQUES` (combined)

- **🔠 Encoding/Obfuscation Bypass Engine** (`offsec_ai.utils.llm_encoders`)
  - Encodes payloads in base64, ROT-13, leetspeak, hex, reversed text, homoglyph, zero-width Unicode
  - `encode(payload, method)` — encode a string in the given representation
  - `wrap(payload, method)` — produce a complete prompt asking the model to decode-and-execute
  - `detect_bypass(response, payload)` — heuristic to detect if a model decoded and acted on the payload
  - `ENCODING_METHODS` — list of all available method names

- **💬 Multi-Turn Conversation Attacker** (`offsec_ai.core.llm_conversation_attacker`)
  - Requires `authorized=True`; prints legal authorization banner on every instantiation
  - Attack patterns: **crescendo** (gradual escalation), **many-shot** (in-context few-shot jailbreak),
    **context-priming** (false context injection), **goal-hijack** (incremental goal redefinition)
  - `attack(endpoint, mode, ...)` returns `MultiTurnAttackResult` with full conversation transcript,
    turn-by-turn analysis, escalation detection, and audit trail

- **📊 Guardrail Benchmarker** (`offsec_ai.core.guardrail_bench`)
  - Maps which OWASP LLM categories are blocked vs. passed by the target's content filter
  - Produces a per-category block rate and overall `GuardrailBenchResult` with a letter grade
  - Distinguishes between hard blocks (no response), soft refusals, and compliant responses

- **⚔️ Active LLM Attack CLI** (`offsec-ai llm-attack`)
  - Requires `--i-have-authorization`; authorization gate identical to `mcp-attack`/`openclaw-attack`
  - Modes: `jailbreak` · `encoding` · `multiturn` · `agentic` · `guardrail` · `all`
  - Safe mode — informational payload report (no auto-execution)
  - Deep mode — actively sends attack payloads and reports results
  - New models: `LLMAttackResult`, `LLMAttackReport` (`offsec_ai.models.llm_attack_result`)

- **Extended `LLMOwaspScanner`** — jailbreak and encoding payloads are now plugged into the
  deep-mode scanning pipeline alongside the existing 22 OWASP probes

### Added — Enterprise-Grade Hardening (Track B)

- **🏗️ Exception Hierarchy** (`offsec_ai.exceptions`)
  - `OffsecError` — base class for all package exceptions
  - `ScanError` — unexpected scan-operation failures
  - `ConfigError` — invalid/missing configuration at startup
  - `NetworkError` — DNS, connection, timeout failures
  - `TargetUnreachableError` — target unreachable after all retries (subclass of `NetworkError`)
  - `AuthorizationRequired` — consolidated single class (replaces duplicate definitions in
    `mcp_attacker` and `openclaw_attacker`)

- **⚙️ Centralised Config** (`offsec_ai.config`)
  - `OffsecConfig(BaseSettings)` — pydantic-settings v2, validated at import time
  - `SecretStr` for all API keys — never serialised or printed as plain text
  - `.env` file support via `python-dotenv`
  - All `OFFSEC_*` env vars: timeout, concurrency, retries, log level, log format, audit log path
  - `get_config()` returns a cached singleton; `reset_config()` for test isolation

- **📋 Structured Logging** (`offsec_ai.log_config`)
  - `configure_logging(level, fmt)` — central setup; `fmt="json"` emits newline-delimited JSON
  - `JsonFormatter` — includes `timestamp`, `level`, `logger`, `correlation_id`, `message`, plus
    all extra fields passed to the log call
  - `new_correlation_id()` / `get_correlation_id()` — `contextvars`-based async-safe correlation IDs
    so all log lines from a single scan/attack share the same ID
  - `audit_log(event, **fields)` — dedicated audit logger; always JSON; optionally rotated to file
    via `OFFSEC_AUDIT_LOG_FILE`; records every authorized attack invocation

- **Quality Gates**
  - `pyproject.toml`: ruff linter/formatter configuration added; pytest markers registered
    (`integration`, `slow`, `security`, `network`); `pydantic-settings` and `python-dotenv`
    added as core dependencies
  - `Makefile`: `ruff`, `bandit`, `audit` (pip-audit) targets; `ci` target updated

- **CI/CD Security Scanning**
  - `.github/workflows/test.yml`: `pip-audit` (dependency CVEs), `bandit` (SAST), `detect-secrets`
    steps added to every test run
  - `.pre-commit-config.yaml`: `ruff`, `bandit`, `detect-secrets` hooks added
  - `.github/dependabot.yml`: automated dependency updates for pip and GitHub Actions
  - `.secrets.baseline`: detect-secrets baseline committed

- **CodeQL** (`.github/workflows/codeql.yml`) — restored for public repo; Python + Actions scanning
  on push/PR/weekly schedule

### Fixed

- `httpx.AsyncClient` in all four scanners/attackers now sets `trust_env=False` to prevent
  ambient SOCKS/HTTP proxies from the environment leaking into scan connections
- `mcp-scan` CLI: added `--no-tls-verify` flag for self-signed/internal CA certificates
  (e.g. `mcp.simpleportchecker.com` uses a Cloudflare internal CA)
- `reportlab` added as explicit venv dependency (was declared in `pyproject.toml` but not
  installed in the manually-created venv, causing `test_cli_mtls_commands_exist` to fail)

### Tests

- 195 tests passing (up from 63 in v2.1.0)
- `tests/test_enterprise_features.py` — covers exceptions hierarchy, config validation,
  logging/correlation IDs, jailbreak payload structure, encoding round-trips, multi-turn
  attacker authorization gate, guardrail bench result model

## [2.1.0] - 2026-06-30

### Added — OpenClaw Gateway Security Assessment

- **🦀 OpenClaw Scanner** (`offsec_ai.core.openclaw_scanner.OpenClawScanner`)
  - Fingerprints OpenClaw personal AI assistant gateway deployments (default port 18789)
  - Five-phase scan: fingerprint → endpoint enumeration → auth posture → configuration → CVE matching
  - Detects unauthenticated REST API access, open DM policy, disabled sandbox, unauthenticated WebSocket upgrades, health endpoint disclosure, session history exposure, API key leakage
  - Response body capped at 64 KB per request to prevent memory issues with binary/large payloads
  - `trust_env=False` on httpx client to prevent ambient proxy interference
  - CLI command: `offsec-ai openclaw-scan`

- **⚔️ OpenClaw Attacker** (`offsec_ai.core.openclaw_attacker.OpenClawAttacker`)
  - Active red-team probe suite for authorized security assessments
  - Hard authorization gate: `OpenClawAttacker(authorized=False)` raises `AuthorizationRequired`; `--i-have-authorization` required at CLI
  - **Safe mode**: unauthenticated API endpoint probes across all known `/api/v1/*` paths
  - **Deep mode**: adds message injection, WebSocket upgrade probes, SSRF via webhook endpoint, and an informational prompt-injection payload report (payloads listed but not auto-executed to avoid unintended model manipulation)
  - Response body capped at 4 KB per attack request
  - CLI command: `offsec-ai openclaw-attack`

- **New models** (`offsec_ai.models.openclaw_result`): `OpenClawScanResult`, `OpenClawAttackReport`, `OpenClawAttackResult`, `OpenClawVulnerability`, `OpenClawServerInfo`, `OpenClawAuthPosture`, `OpenClawDMPolicy`, `OpenClawSandboxInfo`, `OpenClawAccessibleEndpoint`, `OpenClawVulnSeverity`

- **New utilities**:
  - `offsec_ai.utils.openclaw_cve_db` — 10 OpenClaw-specific advisories (OCL-ADV-001 through OCL-ADV-010) covering critical through informational severity; `match_cves()` path and version filter function; `OPENCLAW_FINGERPRINTS`, `OPENCLAW_PROBE_PATHS`, `OPENCLAW_API_PATHS`
  - `offsec_ai.utils.openclaw_payloads` — `DM_PROMPT_INJECTION_PAYLOADS`, `API_AUTH_BYPASS_PAYLOADS`, `MESSAGE_INJECTION_PAYLOADS`, `SSRF_WEBHOOK_PAYLOADS`, `WEBSOCKET_PROBE_PATHS`

- **Tests**: 63 new tests in `tests/test_openclaw.py` covering CVE DB integrity, payload structure, result model properties, scanner fingerprinting (positive/negative), endpoint enumeration, auth posture detection, configuration parsing, vulnerability matching, attacker authorization gating, API probes (safe mode), deep-mode attacks, and full scan-then-attack end-to-end flow — all passing

### Changed
- `pyproject.toml`: description updated to include "OpenClaw gateway security assessment"; keywords updated with `"openclaw"`, `"ai-gateway"`, `"personal-ai"`
- `src/offsec_ai/cli.py`: added `openclaw-scan` and `openclaw-attack` commands with `--port`, `--tls`, `--header`, `--timeout`, `--format`, `--output` options; `openclaw-attack` additionally requires `--i-have-authorization` and `--mode safe|deep`
- `docs/api.md`: new **OpenClaw Gateway Security** section with full API reference, advisory table, CLI examples, and scan-then-attack workflow example
- Removed `sonar-project.properties` and `.github/workflows/sonarcloud.yml` (SonarCloud integration disabled)

## [2.0.2] - 2026-06-29

### Changed
- README logo replaced with inline ASCII art (no external image dependency)
- User-Agent strings updated from `SimplePortChecker/1.0` to `offsec-ai/2.0` in `L7Detector` and `HybridIdentityChecker`
- `reportlab>=4.0.0` promoted to core dependency in `pyproject.toml` (was missing, caused `ModuleNotFoundError` on fresh installs)
- Docker image now installs `[ai]` extras (`openai`, `anthropic`) so LLM judge works at runtime via env vars
- Dockerfile redundant pre-installs removed; `pip install ".[ai]"` is now the single install step
- `docker-push` and `docker-release` Makefile targets added with auto-versioning from `pyproject.toml`
- CI/CD: `docker.yml` image labels updated (title, description); unused `build-args` removed
- CI/CD: `publish.yml` PyPI environment URL no longer pins a hardcoded version
- Stale files removed: `PROJECT_STRUCTURE.md`, `HYBRID_IDENTITY_QUICKREF.md`, `IMPLEMENTATION_HYBRID_IDENTITY.md`, `MANIFEST.in`, empty `scripts/` dir
- `tests/test_dns_trace.py` removed (was a live-network script, not a pytest test)
- `tests/test_mtls.py` and `tests/test_mtls_integration.py` rewritten as proper `assert`-based pytest tests
- `setup_dev.sh` updated: branding, venv path (`.venv`), and `[ai]` extras

## [2.0.0] - 2026-06-29

### Added — AI / LLM Security (fresh start as `offsec-ai`)

This release renames the package from `simple-port-checker` to `offsec-ai` and introduces comprehensive AI/LLM security capabilities.

- **🤖 AI OWASP Top 10 Scanner** (`offsec_ai.core.ai_owasp_scanner.LLMOwaspScanner`)
  - Black-box probing of live LLM/chat API endpoints (OpenAI-compatible and generic formats)
  - Covers LLM01–LLM10 where externally testable (LLM03, LLM04, LLM08 marked not-testable)
  - Safe mode (passive) and deep mode (all probes)
  - Severity-based grading (A–F); CRITICAL finding auto-assigns F grade
  - Batch scanning via `batch_scan()`
  - CLI command: `offsec-ai ai-owasp-scan`

- **🔬 LLM Judge** (`offsec_ai.core.llm_judge.LLMJudge`)
  - Optional semantic evaluation of probe responses via OpenAI or Anthropic
  - Auto-detected from `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `OFFSEC_LLM_BASE_URL`
  - Falls back to rule-based detection when no API key is present
  - Enabled via `pip install "offsec-ai[ai]"` optional extra

- **🔌 MCP Security Scanner** (`offsec_ai.core.mcp_scanner.MCPScanner`)
  - Scans Model Context Protocol servers over HTTP/SSE and stdio transports
  - Enumerates tools, resources, and prompts via JSON-RPC
  - Auth posture detection (unauthenticated vs authenticated access)
  - Built-in CVE database: tool poisoning, path traversal, command injection, secrets in descriptions, excessive agency, prompt injection via tool response, rug-pull/tool shadowing
  - CLI command: `offsec-ai mcp-scan`

- **⚔️ MCP Attacker** (`offsec_ai.core.mcp_attacker.MCPAttacker`)
  - Active attack suite: auth bypass, path traversal, tool injection, command injection
  - Hard authorization gate: `MCPAttacker(authorized=False)` raises `AuthorizationRequired`
  - `--i-have-authorization` flag required at CLI; prints legal banner on every run
  - Safe mode (auth bypass only) and deep mode (all attacks)
  - CLI command: `offsec-ai mcp-attack`

- **New models**: `LLMScanResult`, `LLMFinding`, `LLMCategoryResult`, `LLMSeverity`, `LLMScanMode`, `BatchLLMScanResult`, `MCPScanResult`, `MCPTool`, `MCPResource`, `MCPVulnerability`, `MCPAttackReport`, `MCPAttackResult`, `MCPTransport`, `MCPVulnSeverity`, `AuthorizationRequired`

- **New utilities**: `ai_owasp_payloads.py`, `ai_owasp_remediation.py`, `mcp_cve_db.py`, `mcp_payloads.py`

### Changed

- Package renamed: `simple-port-checker` → `offsec-ai` (PyPI), `simple_port_checker` → `offsec_ai` (import)
- CLI entry point renamed: `offsec-ai` (removed legacy `port-checker`, `simple-port-checker` aliases)
- Version bumped to `2.0.0` (continues from `simple-port-checker` v1.1.2 — major version for complete rebrand)
- Requires Python 3.12+
- Added `mcp>=1.0.0` and `httpx>=0.25.0` as core dependencies

### Migration from `simple-port-checker`

```python
# Before
from simple_port_checker import PortChecker

# After
from offsec_ai import PortChecker
```

```bash
# Before
pip install simple-port-checker
simple-port-checker scan example.com

# After
pip install offsec-ai
offsec-ai scan example.com
```

All existing functionality (port scanning, L7 detection, mTLS, certificate analysis, OWASP web scanner, hybrid identity) is preserved and works identically.

---

## [1.1.2] - 2026-01-23

### Added
- **🆕 OWASP Top 10 2025 Support**: Added support for OWASP Top 10 2025 categories
  - **A03_2025**: Software Supply Chain Failures
    - Security.txt file detection
    - Software Bill of Materials (SBOM) checking
    - Supply chain transparency verification
  - **A10_2025**: Mishandling of Exceptional Conditions
    - Server version disclosure detection
    - Technology stack disclosure analysis
    - Verbose error message detection
- **🔄 Mixed Scanning**: Support for scanning both OWASP 2021 and 2025 categories simultaneously
- **📚 Tech-Specific Remediation**: Remediation guidance for new 2025 categories across all tech stacks

### Fixed
- **🐛 CI/CD**: Install httpx and reportlab dependencies before package in publish workflow
  - Resolved `ModuleNotFoundError: No module named 'httpx'` in integration tests

### Changed
- **📖 Documentation**: Updated CLI help text to reflect OWASP 2021/2025 support
- **🧪 Testing**: Added OWASP 2025 integration tests to CI/CD pipeline

## [1.1.1] - 2026-01-23

### Fixed
- **🐳 Docker Build**: Fixed missing `httpx` and `reportlab` dependencies in Docker image
  - Added explicit installation of OWASP scanner dependencies in Dockerfile
  - Resolved `ModuleNotFoundError: No module named 'httpx'` in containerized environments
- **🧪 CI/CD**: Added OWASP integration tests to publish workflow
  - Test OWASP scan command availability
  - Test JSON and CSV export functionality
  - Validate scan with specific categories

### Changed
- **📚 Documentation**: Enhanced README.md with comprehensive OWASP section
  - Added OWASP scan workflow sequence diagram
  - Detailed command-line usage examples
  - Python API usage patterns
  - Multi-format reporting examples

## [1.1.0] - 2026-01-23

### Added
- **🔍 OWASP Top 10 2021 Vulnerability Scanner**: Comprehensive security assessment framework
  - **`owasp-scan`**: Automated vulnerability detection for OWASP Top 10 2021 categories
  - **Safe Mode (default)**: Passive-only security checks for A02, A05, A06, A07
  - **Deep Mode**: Active probing with payload testing across all categories
  - **Category Selection**: Scan specific OWASP categories (e.g., `-c A02,A05`)
- **🛡️ Security Header Analysis**: HTTP security header grading and validation
  - Comprehensive header checking (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
  - Letter grade (A-F) assignment per header and overall
  - CORS misconfiguration detection
  - Cookie security flag analysis (Secure, HttpOnly, SameSite)
- **📄 Multi-Format Reporting**: Export security findings in multiple formats
  - **PDF Reports**: Professional assessment reports with remediation guidance
  - **JSON Export**: Complete scan results with optional remediation details
  - **CSV Export**: Tabular findings for spreadsheet analysis
  - **Console Output**: Interactive terminal display with color-coded grades
- **🔧 Technology-Specific Remediation**: Tailored fix guidance per infrastructure
  - Apache, Nginx, IIS, Cloudflare, and generic remediation examples
  - Code snippets for implementing security fixes
  - Reference links to OWASP documentation
  - CWE ID mappings for vulnerability tracking
- **📊 Severity Scoring System**: Risk-based finding prioritization
  - CRITICAL (15 pts): Automatic F grade for cryptographic failures
  - HIGH (10 pts), MEDIUM (5 pts), LOW (1 pt)
  - Overall security grade calculation (A-F)
  - Severity filtering in CLI (`--severity CRITICAL`)
- **🎯 Verbosity Controls**: Flexible output detail levels
  - `--verbose`: Full findings with evidence and remediation
  - Default: Category summary table with grades
  - `--quiet`: Grade-only summary
- **⚙️ Advanced Scanner Features**:
  - Async concurrent scanning with rate limiting
  - Batch target scanning support
  - Configurable timeout and connection settings
  - A09 (Logging/Monitoring) marked as "Not Testable" with explanation

### Dependencies
- Added `httpx>=0.25.0` for async HTTP requests
- Added `reportlab>=4.0.0` for PDF generation

### Documentation
- Added comprehensive OWASP scanner guide (`docs/owasp-scanner.md`)
- Added programmatic usage examples (`examples/owasp_scan_examples.py`)
- Updated README with OWASP scanning features
- Documented all scan modes, output formats, and filtering options

## [0.5.1] - 2025-09-21

### Fixed
- **🔧 Critical Dependency Fix**: Added missing `cryptography>=41.0.0` dependency
  - Fixed `ModuleNotFoundError: No module named 'cryptography'` in certificate analysis
  - Added OpenSSL system dependency for GitHub Actions integration tests
  - Ensured certificate chain extraction works properly in all environments
- **🚀 CI/CD Improvements**: Enhanced integration testing environment
  - Fixed PyPI package installation and testing workflow
  - Added proper system dependencies for certificate analysis functionality

## [0.5.0] - 2025-09-21

### Added
- **🔒 SSL/TLS Certificate Analysis**: Comprehensive certificate chain analysis and validation
  - **`cert-check`**: Analyze SSL/TLS certificate chain for target hosts
  - **`cert-chain`**: Complete certificate chain and trust path analysis  
  - **`cert-info`**: Detailed certificate information and signing hierarchy
- **🏛️ Certificate Authority Identification**: "Who signed my cert?" functionality
  - Certificate signing chain visualization
  - Intermediate CA detection and validation
  - Root CA identification and trust validation
- **⚠️ Missing Intermediate Detection**: Identify incomplete certificate chains
  - Browser compatibility warnings
  - Missing intermediate certificate alerts
  - Chain completeness validation
- **🔗 Chain of Trust Validation**: Complete trust path verification
  - Signature validation throughout the chain
  - Certificate hierarchy analysis
  - Trust issue identification
- **🛡️ Security Analysis Features**:
  - Hostname verification against certificates (including wildcards)
  - Certificate expiration checking
  - Key algorithm and signature algorithm analysis
  - Subject Alternative Names (SAN) extraction
- **📋 Certificate Information Extraction**:
  - Certificate fingerprints (SHA-1, SHA-256)
  - Serial numbers and validity periods
  - Key usage and extended key usage details
  - Certificate extensions analysis
- **🔄 Revocation Infrastructure**: OCSP and CRL URL extraction for future validation
- **📊 Rich Output**: Beautiful certificate analysis tables with status indicators
- **💾 Export Capabilities**: JSON output support for programmatic integration

### Enhanced
- **CLI Interface**: Added three new certificate analysis commands to main CLI
- **Documentation**: Integrated best practices from DigiCert and Red Hat security guidelines
- **Error Handling**: Robust certificate parsing with multiple fallback methods
- **Async Support**: Asynchronous certificate chain analysis for better performance

### Technical
- **Certificate Parser**: Built on cryptography library for robust certificate handling
- **Chain Extraction**: Uses OpenSSL for comprehensive certificate chain retrieval
- **Timezone Handling**: Proper UTC datetime handling for certificate validity
- **Security Context**: Appropriate SSL context configuration for certificate analysis

## [0.4.2] - 2025-09-19

### Fixed
- **CHANGELOG Correction**: Fixed changelog entry accuracy for 0.4.1 release
- **Version Update**: Updated version consistency across pyproject.toml and __init__.py

### Maintenance
- **Documentation**: Minor improvements to changelog formatting and accuracy

## [0.4.1] - 2025-09-19

### Fixed
- **L7 Detection Bug**: Fixed critical false positive where CloudFront-protected sites were incorrectly identified as F5 Big-IP
- **Via Header Detection**: Corrected F5 detection logic to check via header content instead of just presence
- **AWS WAF Detection**: Fixed fallback detection path that was incorrectly flagging any via header as F5

### Enhanced
- **CloudFront Differentiation**: AWS WAF detection now distinguishes between "CloudFront - AWS WAF" and pure "AWS WAF"
- **Display Names**: Enhanced service name display logic to show more specific protection service information
- **Detection Accuracy**: Improved confidence scoring and indicator analysis for AWS CloudFront services

### Improved
- **Detection Logic**: Refined F5 Big-IP detection to avoid false positives with CloudFront via headers
- **Service Identification**: More precise identification of AWS protection services (CloudFront vs WAF)
- **User Experience**: Clearer service names in CLI output and JSON results

## [0.4.0] - 2025-09-19

### Added
- **Docker Support**: Official Docker images now available on Docker Hub
- Enhanced README.md with comprehensive Docker usage examples and Docker Hub integration
- Docker workflow configured for manual deployment to PyPI environment
- Multi-architecture Docker image support (AMD64, ARM64)
- Automated Docker builds with GitHub Actions

### Improved
- Updated project documentation to highlight Docker availability
- Added Docker Hub badges and links for better discoverability
- Enhanced installation documentation with Docker Hub examples
- Updated version references throughout documentation

### Fixed
- Docker workflow environment configuration for proper secret management
- GitHub Actions workflow to use PyPI environment for Docker registry credentials

## [0.2.0] - 2025-09-15

### Major Refactoring and Cleanup
- **BREAKING**: Removed standalone scripts directory and integrated all functionality into main CLI
- **BREAKING**: Moved all tests to top-level `tests/` directory following Python packaging standards
- **BREAKING**: Removed `run.py` entry point (use `python -m offsec_ai` or installed CLI commands)

### Added
- Unified CLI interface with all functionality accessible via main commands
- DNS trace functionality integrated into `dns-trace` command and `l7-check --trace-dns`
- Type hint support with `py.typed` file for better IDE and tooling support
- Security policy documentation (`SECURITY.md`)
- Production-ready project structure following Python packaging best practices

### Improved
- Clean and consistent project organization under `src/offsec_ai/`
- Better error handling in DNS trace functionality
- Fixed undefined variable issues in L7 detector
- Updated documentation and project structure guide
- Enhanced code organization and maintainability

### Fixed
- Method signature issues in `_check_ip_for_protection`
- Variable scope problems in DNS tracing
- Import path issues after test file reorganization
- Duplicate test directories cleanup

### Removed
- `src/offsec_ai/scripts/` directory (functionality moved to main CLI)
- `run.py` standalone entry point
- Unnecessary script entry points from pyproject.toml
- Duplicate and outdated test files

## [0.3.0] - 2025-09-17

### Added - Production-Ready mTLS Authentication Support
- **Complete mTLS Implementation**: Production-grade mutual TLS authentication checking
  - Advanced error handling with retry logic and exponential backoff
  - Comprehensive input validation and sanitization
  - Performance metrics and reliability tracking
  - Enhanced logging with configurable verbosity levels
  - Resource cleanup and connection management
- **Enhanced CLI Commands**:
  - `mtls-check`: Advanced mTLS checking with retry logic, custom timeouts, and batch processing
  - `mtls-gen-cert`: Certificate generation with configurable key sizes and validity periods
  - `mtls-validate-cert`: Comprehensive certificate validation with detailed output
- **Production Features**:
  - Configurable retry attempts and delays (0.1-10.0s)
  - Custom timeout handling (1-300s)
  - Concurrent processing limits (1-50 connections)
  - Progress callbacks for batch operations
  - Detailed performance and error metrics
- **Enterprise Integration**:
  - CI/CD pipeline examples (GitHub Actions, Jenkins)
  - Kubernetes deployment health checks
  - Docker container security scanning
  - Enterprise audit scripts and automation
- **Security Enhancements**:
  - Input validation for hostnames, ports, and file paths
  - Certificate chain validation and expiration checking
  - Secure SSL context configuration (TLS 1.2+ requirement)
  - Proper error categorization (network, timeout, certificate errors)
- **Documentation**:
  - Comprehensive mTLS sequence diagram with mermaid
  - Production deployment examples and best practices
  - Security guidelines and troubleshooting guide
  - Enterprise integration patterns
  - API documentation with real-world examples

### Enhanced
- **MTLSChecker Class**: Production-ready with comprehensive error handling
  - Input validation for all parameters
  - Configurable retry logic with exponential backoff
  - Performance metrics collection and reporting
  - Enhanced logging with structured output
  - Resource cleanup and connection pooling
- **Batch Processing**: Improved concurrent processing with progress tracking
  - Support for mixed hostname/port formats
  - Progress callbacks for real-time updates
  - Enhanced error handling for individual targets
  - Performance optimization for large-scale scans
- **Certificate Handling**: Enhanced certificate parsing and validation
  - Support for various certificate formats
  - Detailed certificate information extraction
  - Chain validation and expiration checking
  - Secure file permission recommendations
- **CLI Interface**: Production-ready command interface
  - Comprehensive help documentation with examples
  - Enhanced parameter validation and error messages
  - Rich output formatting with progress bars
  - JSON export with detailed metrics
- **Error Handling**: Comprehensive error management
  - Categorized error types (network, timeout, certificate)
  - Graceful degradation for missing dependencies
  - Detailed error messages with troubleshooting hints
  - Metrics tracking for reliability monitoring

### Dependencies
- **Updated**: `cryptography>=41.0.0` for enhanced certificate handling
- **Updated**: `certifi>=2023.7.22` for CA bundle management
- **Added**: Enhanced error handling for optional dependencies

## [Unreleased]
  - `mtls-check`: Advanced mTLS checking with retry logic, custom timeouts, and batch processing
  - `mtls-gen-cert`: Certificate generation with configurable key sizes and validity periods
  - `mtls-validate-cert`: Comprehensive certificate validation with detailed output
- **Production Features**:
  - Configurable retry attempts and delays (0.1-10.0s)
  - Custom timeout handling (1-300s)
  - Concurrent processing limits (1-50 connections)
  - Progress callbacks for batch operations
  - Detailed performance and error metrics
- **Enterprise Integration**:
  - CI/CD pipeline examples (GitHub Actions, Jenkins)
  - Kubernetes deployment health checks
  - Docker container security scanning
  - Enterprise audit scripts and automation
- **Security Enhancements**:
  - Input validation for hostnames, ports, and file paths
  - Certificate chain validation and expiration checking
  - Secure SSL context configuration (TLS 1.2+ requirement)
  - Proper error categorization (network, timeout, certificate errors)
- **Documentation**:
  - Comprehensive mTLS sequence diagram with mermaid
  - Production deployment examples and best practices
  - Security guidelines and troubleshooting guide
  - Enterprise integration patterns
  - API documentation with real-world examples

### Enhanced
- **MTLSChecker Class**: Production-ready with comprehensive error handling
  - Input validation for all parameters
  - Configurable retry logic with exponential backoff
  - Performance metrics collection and reporting
  - Enhanced logging with structured output
  - Resource cleanup and connection pooling
- **Batch Processing**: Improved concurrent processing with progress tracking
  - Support for mixed hostname/port formats
  - Progress callbacks for real-time updates
  - Enhanced error handling for individual targets
  - Performance optimization for large-scale scans
- **Certificate Handling**: Enhanced certificate parsing and validation
  - Support for various certificate formats
  - Detailed certificate information extraction
  - Chain validation and expiration checking
  - Secure file permission recommendations
- **CLI Interface**: Production-ready command interface
  - Comprehensive help documentation with examples
  - Enhanced parameter validation and error messages
  - Rich output formatting with progress bars
  - JSON export with detailed metrics
- **Error Handling**: Comprehensive error management
  - Categorized error types (network, timeout, certificate)
  - Graceful degradation for missing dependencies
  - Detailed error messages with troubleshooting hints
  - Metrics tracking for reliability monitoring

### Dependencies
- **Updated**: `cryptography>=41.0.0` for enhanced certificate handling
- **Updated**: `certifi>=2023.7.22` for CA bundle management
- **Added**: Enhanced error handling for optional dependencies

## [0.1.11] - 2025-01-16

### Fixed
- Enhanced F5 BIG-IP detection logic for volt-adc and F5 Edge Services
- Improved header pattern matching for case-insensitive detection
- Added more extensive F5 signature patterns for better detection
- Improved fallback analysis with more comprehensive detection logic
- Added better detection of numeric cookie patterns characteristic of F5
- Enhanced detection for sites with specific server headers like "volt-adc"
- Fixed issues in full-scan mode when detecting L7 protection services

## [0.1.10] - 2025-01-16

### Fixed
- Enhanced handling of websites with extremely large headers (e.g., www.ntu.edu.sg)
- Increased header size limit to 128KB for better compatibility with complex sites
- Added brotli compression support for sites that use br content encoding
- Improved detection algorithm for educational (.edu) domains
- Enhanced fallback mechanisms with more robust error handling
- Added more comprehensive domain detection patterns for problematic sites
- Improved requests library fallback to handle different compression methods
- Fixed SSL verification warnings in fallback methods
- Enhanced detection patterns for Cloudflare, Akamai, F5, and other CDN/WAF providers

## [0.1.9] - 2025-01-15

### Fixed
- Added fallback mechanism using requests library for problematic sites with extremely large headers
- Implemented automatic switching between aiohttp and requests for problematic domains
- Enhanced detection of WAF/CDN services even when primary detection fails
- Improved handling of .sg domains that commonly use Akamai with large headers
- Added sophisticated header analysis for fallback cases

## [0.1.8] - 2025-01-15

### Fixed
- Significantly improved handling of sites with extremely large HTTP headers
- Increased header size limit to 64KB to support the most complex WAF configurations
- Added resilient HTTP request handling with graceful header processing
- Enhanced WAF detection for sites that use oversized headers as security measures
- Added special detection patterns for Singapore (.sg) domains with large headers
- Implemented SSL bypass option to avoid certificate validation issues

## [0.1.7] - 2025-01-15

### Fixed
- Increased maximum header size limit to 32KB to handle websites with very large response headers
- Improved error handling for "Header value too long" errors to better identify potential WAF/CDN
- Enhanced HTTP client configuration for better handling of complex network scenarios
- Added support for compressed responses to handle CDN-optimized content

## [0.1.6] - 2025-01-15

### Fixed
- Fixed "Header value too long" errors during L7 detection
- Improved handling of large HTTP responses
- Enhanced error handling for various HTTP client errors
- Optimized response body processing to prevent excessive memory usage

## [0.1.5] - 2025-01-15

### Added
- Improved F5 BIG-IP WAF detection for different F5 implementations
- Added detection for F5 Edge Services via VES.IO domain patterns
- Enhanced F5 cookie pattern detection
- Added additional status code and response body patterns for F5 detection

## [0.1.4] - 2025-01-15

### Added
- Explicit notification when a target is not protected by L7 services in CLI output
- Added a dedicated table in summary displaying all unprotected hosts
- Improved visibility of unprotected hosts in scan results

## [0.1.3] - 2025-01-15

### Added
- Support for Azure Front Door detection

## [0.1.2] - 2025-01-15

### Fixed
- Updated GitHub Actions to use latest versions

## [0.1.0] - 2025-01-14

### Added
- Basic port scanning functionality with async support
- L7 protection detection for major WAF/CDN services
- Command-line interface with multiple commands
- Support for batch scanning multiple hosts
- Service version detection capabilities
- WAF bypass testing functionality
- Rich terminal output with progress bars
- JSON output format support
- Comprehensive test suite
- GitHub Actions CI/CD pipeline
- PyPI publishing workflow
- Development environment setup scripts
- Pre-commit hooks for code quality
- Type hints and mypy support
- Detailed documentation and examples

### Features
- **Port Scanning**: Async scanning with configurable concurrency
- **L7 Detection**: Identify Cloudflare, AWS WAF, Azure WAF, F5, Akamai, and more
- **CLI Interface**: Easy-to-use command-line tools
- **Service Detection**: Banner grabbing and service identification
- **Batch Operations**: Scan multiple hosts efficiently
- **Configuration**: Customizable timeouts, concurrency, and more
- **Output Formats**: JSON export and terminal display
- **Security Testing**: WAF detection and bypass testing

### Technical Details
- Python 3.12+ support
- Async/await architecture for high performance
- Type-safe codebase with mypy
- Comprehensive error handling
- Modular and extensible design
- Well-tested with pytest
- Production-ready packaging

### Dependencies
- aiohttp: Async HTTP client
- click: Command-line interface
- rich: Terminal output formatting
- pydantic: Data validation
- dnspython: DNS resolution
- python-nmap: Network mapping
- asyncio-throttle: Rate limiting
- cryptography: For certificate handling
- certifi: For CA bundle management

[Unreleased]: https://github.com/Htunn/offsec-ai/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/Htunn/offsec-ai/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/htunn/offsec-ai/releases/tag/v2.0.0
