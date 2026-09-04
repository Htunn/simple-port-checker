"""
OpenClaw personal AI assistant gateway security scanner.

Connects to an OpenClaw gateway via HTTP, fingerprints the instance,
enumerates accessible endpoints, detects misconfigurations (open DM policy,
missing sandbox mode, unauthenticated API access), and matches findings
against the OpenClaw CVE and misconfiguration database.

Usage:
    scanner = OpenClawScanner("https://openclaw.example.com", port=18789)
    result = await scanner.scan()

    # Or with API token if the gateway requires authentication:
    scanner = OpenClawScanner("https://openclaw.example.com",
                               headers={"Authorization": "Bearer <token>"})
    result = await scanner.scan()
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any
from urllib.parse import urljoin

import httpx


from ..utils.constants import USER_AGENT
logger = logging.getLogger(__name__)

# Maximum bytes to read from any single response body to prevent memory issues
_MAX_RESPONSE_BYTES = 65_536

from ..models.openclaw_result import (
    OpenClawAccessibleEndpoint,
    OpenClawAuthPosture,
    OpenClawDMPolicy,
    OpenClawSandboxInfo,
    OpenClawScanResult,
    OpenClawServerInfo,
    OpenClawVulnerability,
    OpenClawVulnSeverity,
)
from ..utils.openclaw_cve_db import (
    OPENCLAW_API_PATHS,
    OPENCLAW_CVE_DB,
    OPENCLAW_DEFAULT_PORT,
    OPENCLAW_FINGERPRINTS,
    OPENCLAW_PROBE_PATHS,
    match_cves,
)


class OpenClawScanner:
    """Security scanner for OpenClaw gateway deployments."""

    def __init__(
        self,
        target: str,
        port: int = OPENCLAW_DEFAULT_PORT,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        use_tls: bool = False,
        judge: object | None = None,
    ) -> None:
        """
        Args:
            target:   Hostname or IP address of the OpenClaw gateway.
            port:     Gateway port (default 18789).
            headers:  Extra HTTP headers (e.g. Authorization).
            timeout:  Per-request timeout in seconds.
            use_tls:  Use HTTPS instead of HTTP.
            judge:    Optional LLMJudge instance for AI-assisted triage.
        """
        scheme = "https" if use_tls else "http"
        self.base_url = f"{scheme}://{target}:{port}"
        self.headers = headers or {}
        self.timeout = timeout
        self._target = target
        self._port = port
        self._judge = judge

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self) -> OpenClawScanResult:
        """Fingerprint, enumerate, and assess security posture of the gateway."""
        start = time.monotonic()
        result = OpenClawScanResult(target=self._target, port=self._port)

        try:
            async with httpx.AsyncClient(
                headers={
                    "User-Agent": USER_AGENT,
                    **self.headers,
                },
                timeout=self._timeout_config,
                follow_redirects=True,
                verify=False,  # noqa: S501 — intentional for security scanning
                trust_env=False,
            ) as client:
                # Phase 1: Fingerprint
                result.is_openclaw = await self._fingerprint(client, result)
                if not result.is_openclaw:
                    result.error = "Target does not appear to be an OpenClaw gateway."
                    result.scan_duration = time.monotonic() - start
                    return result

                # Phase 2: Enumerate accessible endpoints
                await self._enumerate_endpoints(client, result)

                # Phase 3: Assess authentication posture
                await self._assess_auth_posture(client, result)

                # Phase 4: Check DM policy and sandbox configuration
                await self._assess_configuration(client, result)

                # Phase 5: Match CVEs and generate vulnerabilities
                self._match_vulnerabilities(result)

                # Phase 6: Optional LLM triage
                if self._judge and getattr(self._judge, "provider", None):
                    self._phase_llm_triage(result)

        except httpx.ConnectError as exc:
            result.error = f"Connection refused or target unreachable: {exc}"
        except httpx.TimeoutException:
            result.error = "Connection timed out."
        except Exception as exc:  # noqa: BLE001
            result.error = f"Unexpected error: {exc}"

        result.scan_duration = time.monotonic() - start
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def _timeout_config(self) -> httpx.Timeout:
        return httpx.Timeout(self.timeout, connect=10.0)

    def _url(self, path: str) -> str:
        return urljoin(self.base_url, path)

    async def _get(
        self, client: httpx.AsyncClient, path: str
    ) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        """Perform GET and return (status_code, json_body | None, headers)."""
        try:
            resp = await client.get(self._url(path))
            body: dict[str, Any] | None = None
            try:
                # Guard against oversized responses (e.g. binary blobs, HTML pages)
                raw = resp.content[:_MAX_RESPONSE_BYTES]
                body = json.loads(raw)
            except Exception:  # noqa: BLE001
                pass
            return resp.status_code, body, dict(resp.headers)
        except (httpx.RequestError, httpx.TimeoutException) as exc:
            logger.debug("GET %s failed: %s", path, exc)
            return 0, None, {}

    async def _get_raw(
        self, client: httpx.AsyncClient, path: str
    ) -> tuple[int, str, dict[str, str]]:
        """Perform GET and return (status_code, raw_text, headers)."""
        try:
            resp = await client.get(self._url(path))
            raw = resp.content[:_MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
            return resp.status_code, raw, dict(resp.headers)
        except (httpx.RequestError, httpx.TimeoutException) as exc:
            logger.debug("GET_RAW %s failed: %s", path, exc)
            return 0, "", {}

    async def _fingerprint(
        self, client: httpx.AsyncClient, result: OpenClawScanResult
    ) -> bool:
        """Probe well-known paths to determine if target is an OpenClaw gateway."""
        for path in OPENCLAW_PROBE_PATHS:
            status, body, headers = await self._get(client, path)
            if status == 0:
                continue

            # Check response headers and body for OpenClaw signatures
            if self._matches_fingerprint(headers, body):
                # Populate basic server info
                if body and isinstance(body, dict):
                    result.server_info = OpenClawServerInfo(
                        version=str(body.get("version", body.get("openclaw_version", ""))),
                        gateway_id=str(body.get("gateway_id", body.get("id", ""))),
                        connected_channels=body.get("channels", []),
                        active_sessions=int(body.get("sessions", 0)),
                        node_count=int(body.get("nodes", 0)),
                        raw=body,
                    )
                return True

        # Fallback: check HTML title of the root page for modern openclaw versions
        root_status, root_text, _ = await self._get_raw(client, "/")
        if root_status not in (0, 404, 502, 503) and self._matches_fingerprint_html(root_text):
            return True

        return False

    def _matches_fingerprint(
        self,
        headers: dict[str, str],
        body: dict[str, Any] | None,
    ) -> bool:
        """Return True if response matches any OpenClaw fingerprint signature."""
        lower_headers = {k.lower(): v.lower() for k, v in headers.items()}

        for fp in OPENCLAW_FINGERPRINTS:
            if "header" in fp:
                hdr = fp["header"].lower()
                if fp["match_type"] == "present" and hdr in lower_headers:
                    return True
                if fp["match_type"] == "contains" and hdr in lower_headers:
                    if fp.get("value", "").lower() in lower_headers[hdr]:
                        return True

            if "body_key" in fp and isinstance(body, dict):
                key = fp["body_key"]
                if fp["match_type"] == "present" and key in body:
                    return True
                if fp["match_type"] == "contains" and key in body:
                    val = str(body[key]).lower()
                    if fp.get("value", "").lower() in val:
                        return True

        # Heuristic: body contains unambiguous OpenClaw-specific fields
        if isinstance(body, dict):
            # Only use high-confidence, OpenClaw-specific key names
            ocl_strong_keys = {"openclaw_version", "openclaw", "molty", "claw_gateway"}
            body_lower_keys = {str(k).lower() for k in body}
            if ocl_strong_keys & body_lower_keys:
                return True
            # Check string values for the product name
            for v in body.values():
                v_str = str(v).lower()
                if "openclaw" in v_str or "molty" in v_str:
                    return True

        return False

    def _matches_fingerprint_html(
        self,
        html_text: str,
    ) -> bool:
        """Return True if raw HTML text contains OpenClaw-specific markers."""
        if not html_text:
            return False
        text_lower = html_text.lower()
        for fp in OPENCLAW_FINGERPRINTS:
            if "html_title" in fp and fp["match_type"] == "present":
                if fp["html_title"].lower() in text_lower:
                    return True
        # Generic product name check in page title
        if "<title>openclaw" in text_lower or "openclaw control" in text_lower:
            return True
        return False

    async def _enumerate_endpoints(
        self, client: httpx.AsyncClient, result: OpenClawScanResult
    ) -> None:
        """Probe known API paths and record accessible endpoints."""
        # Deduplicate while preserving order
        seen: set[str] = set()
        paths: list[str] = []
        for p in OPENCLAW_API_PATHS + OPENCLAW_PROBE_PATHS:
            if p not in seen:
                seen.add(p)
                paths.append(p)
        tasks = [self._probe_endpoint(client, path) for path in paths]
        endpoints = await asyncio.gather(*tasks)
        result.accessible_endpoints = [e for e in endpoints if e is not None]

    async def _probe_endpoint(
        self, client: httpx.AsyncClient, path: str
    ) -> OpenClawAccessibleEndpoint | None:
        status, body, headers = await self._get(client, path)
        if status == 0:
            return None

        accessible = status not in (401, 403, 404, 405, 502, 503)
        if not accessible:
            return None

        sensitive: list[str] = []
        if body and isinstance(body, dict):
            _SENSITIVE_KEYS = {
                "apiKey", "api_key", "token", "botToken", "secret",
                "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "password",
            }
            for key in body:
                if any(sk.lower() in key.lower() for sk in _SENSITIVE_KEYS):
                    sensitive.append(key)

        body_str = json.dumps(body) if body else ""
        return OpenClawAccessibleEndpoint(
            path=path,
            status_code=status,
            response_size=len(body_str),
            requires_auth=False,  # if we got here without auth, it's open
            sensitive_data_found=sensitive,
        )

    async def _assess_auth_posture(
        self, client: httpx.AsyncClient, result: OpenClawScanResult
    ) -> None:
        """Determine whether the API is accessible without credentials."""
        # Check key protected endpoints
        api_accessible = any(
            e.path in ("/api/v1/status", "/api/v1/sessions", "/api/v1/config")
            for e in result.accessible_endpoints
        )
        ws_accessible = await self._probe_websocket_upgrade(client)

        result.auth_posture = OpenClawAuthPosture(
            unauthenticated_api_access=api_accessible,
            unauthenticated_ws_access=ws_accessible,
            auth_type="none" if api_accessible else "unknown",
            auth_header_present=bool(self.headers.get("Authorization")),
        )

    async def _probe_websocket_upgrade(self, client: httpx.AsyncClient) -> bool:
        """Check if the gateway accepts an unauthenticated WebSocket upgrade.

        Sends an HTTP Upgrade request. A 101 Switching Protocols response
        indicates the server accepted the upgrade without authentication.
        Note: httpx does not perform the full WS handshake; we only check
        whether the server responds with 101 to an unauthenticated request.
        """
        ws_headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
        }
        try:
            resp = await client.get(self._url("/"), headers=ws_headers)
            if resp.status_code == 101:
                return True
            # Some implementations return 200 with an Upgrade header set
            upgrade_hdr = resp.headers.get("upgrade", "").lower()
            if upgrade_hdr == "websocket" and resp.status_code == 200:
                return True
            return False
        except Exception:  # noqa: BLE001
            logger.debug("WebSocket probe failed")
            return False

    async def _assess_configuration(
        self, client: httpx.AsyncClient, result: OpenClawScanResult
    ) -> None:
        """Attempt to read DM policy and sandbox configuration from the API."""
        status, body, _ = await self._get(client, "/api/v1/config")

        if status in (200, 201) and isinstance(body, dict):
            # Parse DM policy
            dm_cfg = body.get("channels", {})
            open_channels: list[str] = []
            pairing_channels: list[str] = []
            wildcard_found = False

            for ch_name, ch_cfg in (dm_cfg.items() if isinstance(dm_cfg, dict) else []):
                policy = ""
                if isinstance(ch_cfg, dict):
                    policy = str(ch_cfg.get("dmPolicy", ch_cfg.get("dm", {}).get("policy", "")))
                    allow_from = ch_cfg.get("allowFrom", ch_cfg.get("dm", {}).get("allowFrom", []))
                    if isinstance(allow_from, list) and "*" in allow_from:
                        wildcard_found = True

                if policy == "open":
                    open_channels.append(ch_name)
                elif policy == "pairing":
                    pairing_channels.append(ch_name)

            result.dm_policy = OpenClawDMPolicy(
                policy="open" if open_channels else ("pairing" if pairing_channels else "unknown"),
                has_wildcard_allowlist=wildcard_found,
                channels_with_open_dm=open_channels,
                channels_with_pairing=pairing_channels,
            )

            # Parse sandbox configuration
            agents_cfg = body.get("agents", {})
            defaults = agents_cfg.get("defaults", {}) if isinstance(agents_cfg, dict) else {}
            sandbox = defaults.get("sandbox", {}) if isinstance(defaults, dict) else {}
            sandbox_mode = sandbox.get("mode", "unknown") if isinstance(sandbox, dict) else "unknown"
            sandbox_backend = sandbox.get("backend", "unknown") if isinstance(sandbox, dict) else "unknown"

            result.sandbox_info = OpenClawSandboxInfo(
                sandbox_mode=str(sandbox_mode),
                sandbox_backend=str(sandbox_backend),
                is_sandboxed=sandbox_mode in ("non-main", "all"),
            )

    def _match_vulnerabilities(self, result: OpenClawScanResult) -> None:
        """Match discovered findings against the CVE database and generate vulns."""
        accessible_paths = [e.path for e in result.accessible_endpoints]

        matched = match_cves(
            version=result.server_info.version or None,
            accessible_paths=accessible_paths,
        )

        for entry in matched:
            # Skip info-only fingerprint entry if we already added it
            existing_ids = {v.vuln_id for v in result.vulnerabilities}
            if entry.vuln_id in existing_ids:
                continue

            # Gather evidence
            evidence = self._build_evidence(entry, result, accessible_paths)

            result.vulnerabilities.append(
                OpenClawVulnerability(
                    vuln_id=entry.vuln_id,
                    cve_id=entry.cve_id,
                    severity=OpenClawVulnSeverity(entry.severity),
                    title=entry.title,
                    description=entry.description,
                    evidence=evidence,
                    remediation=entry.remediation,
                    references=entry.references,
                )
            )
            if entry.cve_id:
                result.cve_matches.append(entry.cve_id)

        # Additional heuristic findings based on assessed state
        self._check_dm_policy_vuln(result)
        self._check_sandbox_vuln(result)

    def _build_evidence(
        self,
        entry: Any,
        result: OpenClawScanResult,
        accessible_paths: list[str],
    ) -> str:
        if entry.check_path and entry.check_path in accessible_paths:
            return f"Endpoint {entry.check_path} returned 2xx without authentication."
        if result.auth_posture.unauthenticated_api_access:
            return "One or more API endpoints are accessible without authentication."
        return ""

    def _check_dm_policy_vuln(self, result: OpenClawScanResult) -> None:
        """Add DM policy vulnerability if open DM + wildcard allowlist detected."""
        existing = {v.vuln_id for v in result.vulnerabilities}
        if "OCL-ADV-002" in existing:
            return
        if (
            result.dm_policy.channels_with_open_dm
            or result.dm_policy.has_wildcard_allowlist
        ):
            channels = ", ".join(result.dm_policy.channels_with_open_dm) or "unknown"
            result.vulnerabilities.append(
                OpenClawVulnerability(
                    vuln_id="OCL-ADV-002",
                    severity=OpenClawVulnSeverity.HIGH,
                    title="Open DM Policy Without Allowlist (Prompt Injection via DM)",
                    description=(
                        "The OpenClaw gateway is configured with an open DM policy "
                        "or a wildcard '*' in the channel allowFrom list, allowing "
                        "any user to interact with the AI agent."
                    ),
                    evidence=(
                        f"Channels with open DM policy: {channels}. "
                        f"Wildcard allowlist: {result.dm_policy.has_wildcard_allowlist}."
                    ),
                    remediation=(
                        "Set dmPolicy='pairing' for all channels. Remove '*' from "
                        "allowFrom lists. Run 'openclaw doctor' to surface risky policies."
                    ),
                    references=[
                        "https://docs.openclaw.ai/gateway/security",
                    ],
                )
            )

    def _check_sandbox_vuln(self, result: OpenClawScanResult) -> None:
        """Add sandbox misconfiguration vulnerability if sandbox mode is explicitly off."""
        existing = {v.vuln_id for v in result.vulnerabilities}
        if "OCL-ADV-003" in existing:
            return
        # Only flag when we positively identified sandbox is disabled.
        # Skip when sandbox_mode is 'unknown' (config not accessible) to avoid false positives.
        _INSECURE_MODES = {"disabled", "none", "off", "false", "no", ""}
        if result.sandbox_info.sandbox_mode.lower() in _INSECURE_MODES:
            result.vulnerabilities.append(
                OpenClawVulnerability(
                    vuln_id="OCL-ADV-003",
                    severity=OpenClawVulnSeverity.HIGH,
                    title="Agent Running Outside Sandbox Mode",
                    description=(
                        "Sandbox mode is disabled or not configured. Non-main sessions "
                        "have unrestricted tool access including bash, browser, and file I/O."
                    ),
                    evidence=f"Sandbox mode explicitly set to: '{result.sandbox_info.sandbox_mode}'.",
                    remediation=(
                        "Set 'agents.defaults.sandbox.mode: non-main' in openclaw.json. "
                        "Use Docker as the sandbox backend."
                    ),
                    references=[
                        "https://docs.openclaw.ai/gateway/sandboxing",
                    ],
                )
            )

    def _phase_llm_triage(self, result: OpenClawScanResult) -> None:
        """Use LLM judge to enrich MEDIUM/LOW OpenClaw findings."""
        ambiguous = {OpenClawVulnSeverity.MEDIUM, OpenClawVulnSeverity.LOW}
        for vuln in result.vulnerabilities:
            if vuln.severity not in ambiguous:
                continue
            if not self._judge:
                continue
            try:
                verdict = self._judge.evaluate(
                    category=vuln.vuln_id,
                    probe=vuln.title,
                    response=vuln.evidence or vuln.description,
                )
                vuln.llm_confidence = float(verdict.get("confidence", 0.0))
                vuln.llm_reasoning = str(verdict.get("reason", ""))
                if verdict.get("vulnerable") and vuln.llm_confidence > 0.7:
                    if vuln.severity == OpenClawVulnSeverity.LOW:
                        vuln.severity = OpenClawVulnSeverity.MEDIUM
                        vuln.evidence += " [LLM: upgraded from LOW]"
            except Exception as exc:  # noqa: BLE001
                logger.debug("LLM triage error for %s: %s", vuln.vuln_id, exc)
