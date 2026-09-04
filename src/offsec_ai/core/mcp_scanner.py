"""
MCP (Model Context Protocol) endpoint security scanner.

Connects to an MCP server via HTTP/SSE or stdio, enumerates capabilities,
fingerprints the server, checks authentication posture, and matches against
known CVEs and misconfigurations.

Usage (HTTP):
    scanner = MCPScanner("https://mcp.example.com/mcp")
    result = await scanner.scan()

Usage (stdio):
    scanner = MCPScanner("stdio://localhost", transport="stdio", cmd=["python", "server.py"])
    result = await scanner.scan()
"""

from __future__ import annotations

import asyncio
import json
import logging
import shlex
import subprocess
import time
from typing import Any

import httpx

from ..models.mcp_result import (
    MCPAuthPosture,
    MCPPrompt,
    MCPResource,
    MCPScanResult,
    MCPServerInfo,
    MCPTool,
    MCPTransport,
    MCPVulnerability,
    MCPVulnSeverity,
)
from ..utils.mcp_cve_db import (
    DANGEROUS_TOOL_KEYWORDS,
    MCP_CVE_DB,
    match_cves,
    scan_for_dangerous_keywords,
    scan_for_secrets,
)
from ..utils.constants import MCP_PROTOCOL_VERSION, USER_AGENT

logger = logging.getLogger(__name__)


class MCPScanner:
    """Security scanner for MCP (Model Context Protocol) endpoints."""

    def __init__(
        self,
        target: str,
        transport: str = "http",
        cmd: list[str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        judge: object | None = None,
    ) -> None:
        """
        Args:
            target:     URL for HTTP/SSE transport, or 'stdio://...' for stdio.
            transport:  "http", "sse", or "stdio".
            cmd:        Command list for stdio transport, e.g. ["python", "server.py"].
            headers:    Extra HTTP headers (e.g. Authorization).
            timeout:    Per-request timeout in seconds.
            verify_tls: Verify TLS certificates. Set False for self-signed certs.
            judge:      Optional LLMJudge instance for AI-assisted triage.
        """
        self.target = target
        self.transport = MCPTransport(transport)
        self.cmd = cmd or []
        self.headers = headers or {}
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._judge = judge

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self) -> MCPScanResult:
        """Connect, enumerate, fingerprint, and assess security posture."""
        start = time.monotonic()

        if self.transport in (MCPTransport.HTTP, MCPTransport.SSE):
            result = await self._scan_http()
        else:
            result = await asyncio.to_thread(self._scan_stdio)

        result.scan_duration = time.monotonic() - start
        return result

    # ------------------------------------------------------------------
    # HTTP / SSE scanning
    # ------------------------------------------------------------------

    async def _scan_http(self) -> MCPScanResult:
        result = MCPScanResult(target=self.target, transport=self.transport)

        async with httpx.AsyncClient(
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "User-Agent": USER_AGENT,
                **self.headers,
            },
            timeout=self.timeout,
            trust_env=False,
            verify=self.verify_tls,  # noqa: S501 — intentional for security scanning
        ) as client:
            # 1. Initialize handshake
            server_info, init_error = await self._initialize_http(client)
            if init_error:
                result.error = init_error
                # Still probe auth posture so callers know what auth is needed
                if "401" in init_error or "403" in init_error:
                    result.auth_posture = MCPAuthPosture(
                        requires_auth=True,
                        unauthenticated_access=False,
                        auth_type="bearer" if "401" in init_error else "unknown",
                        notes=init_error,
                    )
                return result
            result.server_info = server_info

            # 2. Auth posture check
            result.auth_posture = await self._check_auth_posture_http(client)

            # 3. Enumerate capabilities in parallel
            tools, resources, prompts = await asyncio.gather(
                self._list_tools_http(client),
                self._list_resources_http(client),
                self._list_prompts_http(client),
                return_exceptions=False,
            )
            result.tools = tools
            result.resources = resources
            result.prompts = prompts

        # 4. Security analysis (no network needed)
        result.vulnerabilities = self._analyze_security(result)
        result.cve_matches = self._match_cves(result.server_info)

        # 5. Optional LLM triage
        if self._judge and getattr(self._judge, "provider", None):
            self._phase_llm_triage(result)

        return result

    @staticmethod
    def _parse_sse_or_json(resp: httpx.Response) -> dict:
        """Parse response body — handles both plain JSON and SSE (text/event-stream)."""
        ct = resp.headers.get("content-type", "")
        if "text/event-stream" in ct or resp.text.startswith("event:") or resp.text.startswith("data:"):
            for line in resp.text.splitlines():
                if line.startswith("data:"):
                    return json.loads(line[5:].strip())
            raise ValueError("SSE response contained no data: line")
        return resp.json()

    async def _initialize_http(
        self, client: httpx.AsyncClient
    ) -> tuple[MCPServerInfo, str | None]:
        """Send MCP initialize request and parse server info."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"roots": {"listChanged": False}},
                "clientInfo": {"name": "offsec-ai", "version": "2.0.0"},
            },
        }
        try:
            resp = await client.post(self.target, json=payload)
            resp.raise_for_status()
            data = self._parse_sse_or_json(resp)
            result_data = data.get("result", {})
            server_info_raw = result_data.get("serverInfo", {})
            capabilities = result_data.get("capabilities", {})
            return MCPServerInfo(
                name=server_info_raw.get("name", ""),
                version=server_info_raw.get("version", ""),
                protocol_version=result_data.get("protocolVersion", ""),
                capabilities=capabilities,
                raw=result_data,
            ), None
        except httpx.HTTPStatusError as exc:
            return MCPServerInfo(), f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
        except Exception as exc:
            return MCPServerInfo(), str(exc)

    async def _check_auth_posture_http(
        self, client: httpx.AsyncClient
    ) -> MCPAuthPosture:
        """Probe auth requirements by sending an unauthenticated request."""
        posture = MCPAuthPosture()

        # Try without any auth header
        no_auth_client = httpx.AsyncClient(
            headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "User-Agent": USER_AGENT},
            timeout=self.timeout,
            trust_env=False,
        )
        async with no_auth_client:
            try:
                payload = {"jsonrpc": "2.0", "id": 99, "method": "initialize",
                           "params": {"protocolVersion": MCP_PROTOCOL_VERSION,
                                      "capabilities": {"roots": {"listChanged": False}},
                                      "clientInfo": {"name": "probe", "version": "2.0.0"}}}
                resp = await no_auth_client.post(self.target, json=payload)
                if resp.status_code == 200:
                    posture.unauthenticated_access = True
                    posture.requires_auth = False
                    posture.auth_type = "none"
                    posture.notes = "Server responded to unauthenticated initialize request."
                elif resp.status_code in (401, 403):
                    posture.requires_auth = True
                    auth_header = resp.headers.get("WWW-Authenticate", "")
                    if "bearer" in auth_header.lower():
                        posture.auth_type = "bearer"
                    elif "basic" in auth_header.lower():
                        posture.auth_type = "basic"
                    else:
                        posture.auth_type = "unknown"
            except Exception:
                pass

        return posture

    async def _list_tools_http(self, client: httpx.AsyncClient) -> list[MCPTool]:
        payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        try:
            resp = await client.post(self.target, json=payload)
            resp.raise_for_status()
            data = self._parse_sse_or_json(resp)
            tools_raw = data.get("result", {}).get("tools", [])
            return [self._parse_tool(t) for t in tools_raw]
        except Exception:
            return []

    async def _list_resources_http(self, client: httpx.AsyncClient) -> list[MCPResource]:
        payload = {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}}
        try:
            resp = await client.post(self.target, json=payload)
            resp.raise_for_status()
            data = self._parse_sse_or_json(resp)
            resources_raw = data.get("result", {}).get("resources", [])
            return [
                MCPResource(
                    uri=r.get("uri", ""),
                    name=r.get("name", ""),
                    description=r.get("description", ""),
                    mime_type=r.get("mimeType", ""),
                )
                for r in resources_raw
            ]
        except Exception:
            return []

    async def _list_prompts_http(self, client: httpx.AsyncClient) -> list[MCPPrompt]:
        payload = {"jsonrpc": "2.0", "id": 4, "method": "prompts/list", "params": {}}
        try:
            resp = await client.post(self.target, json=payload)
            resp.raise_for_status()
            data = self._parse_sse_or_json(resp)
            prompts_raw = data.get("result", {}).get("prompts", [])
            return [
                MCPPrompt(
                    name=p.get("name", ""),
                    description=p.get("description", ""),
                    arguments=p.get("arguments", []),
                )
                for p in prompts_raw
            ]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # stdio scanning (blocking, runs in thread pool)
    # ------------------------------------------------------------------

    def _scan_stdio(self) -> MCPScanResult:
        """Launch MCP server as subprocess and communicate via stdin/stdout."""
        result = MCPScanResult(target=self.target, transport=MCPTransport.STDIO)

        if not self.cmd:
            result.error = "stdio transport requires --cmd to be specified."
            return result

        try:
            proc = subprocess.Popen(
                self.cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception as exc:
            result.error = f"Failed to start MCP server: {exc}"
            return result

        try:
            result.server_info = self._stdio_initialize(proc)
            result.tools = self._stdio_list_tools(proc)
            result.resources = self._stdio_list_resources(proc)
            result.prompts = self._stdio_list_prompts(proc)
            result.auth_posture = MCPAuthPosture(
                requires_auth=False,
                auth_type="none",
                unauthenticated_access=True,
                notes="stdio transport — no network auth layer.",
            )
        except Exception as exc:
            result.error = str(exc)
        finally:
            proc.stdin.close()  # type: ignore[union-attr]
            proc.terminate()
            proc.wait(timeout=5)

        result.vulnerabilities = self._analyze_security(result)
        result.cve_matches = self._match_cves(result.server_info)
        return result

    def _stdio_rpc(self, proc: subprocess.Popen, request: dict) -> dict:
        """Send a JSON-RPC request over stdio and read the response."""
        line = json.dumps(request) + "\n"
        proc.stdin.write(line)  # type: ignore[union-attr]
        proc.stdin.flush()      # type: ignore[union-attr]
        response_line = proc.stdout.readline()  # type: ignore[union-attr]
        return json.loads(response_line)

    def _stdio_initialize(self, proc: subprocess.Popen) -> MCPServerInfo:
        resp = self._stdio_rpc(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": "offsec-ai", "version": "2.0.0"}},
        })
        result_data = resp.get("result", {})
        server_info_raw = result_data.get("serverInfo", {})
        return MCPServerInfo(
            name=server_info_raw.get("name", ""),
            version=server_info_raw.get("version", ""),
            protocol_version=result_data.get("protocolVersion", ""),
            capabilities=result_data.get("capabilities", {}),
            raw=result_data,
        )

    def _stdio_list_tools(self, proc: subprocess.Popen) -> list[MCPTool]:
        resp = self._stdio_rpc(proc, {"jsonrpc": "2.0", "id": 2,
                                      "method": "tools/list", "params": {}})
        return [self._parse_tool(t) for t in resp.get("result", {}).get("tools", [])]

    def _stdio_list_resources(self, proc: subprocess.Popen) -> list[MCPResource]:
        resp = self._stdio_rpc(proc, {"jsonrpc": "2.0", "id": 3,
                                      "method": "resources/list", "params": {}})
        return [
            MCPResource(uri=r.get("uri", ""), name=r.get("name", ""),
                        description=r.get("description", ""),
                        mime_type=r.get("mimeType", ""))
            for r in resp.get("result", {}).get("resources", [])
        ]

    def _stdio_list_prompts(self, proc: subprocess.Popen) -> list[MCPPrompt]:
        resp = self._stdio_rpc(proc, {"jsonrpc": "2.0", "id": 4,
                                      "method": "prompts/list", "params": {}})
        return [
            MCPPrompt(name=p.get("name", ""), description=p.get("description", ""),
                      arguments=p.get("arguments", []))
            for p in resp.get("result", {}).get("prompts", [])
        ]

    # ------------------------------------------------------------------
    # Security analysis (no network)
    # ------------------------------------------------------------------

    def _phase_llm_triage(self, result: MCPScanResult) -> None:
        """Use LLM judge to enrich MEDIUM/LOW MCP findings."""
        ambiguous = {MCPVulnSeverity.MEDIUM, MCPVulnSeverity.LOW}
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
                    if vuln.severity == MCPVulnSeverity.LOW:
                        vuln.severity = MCPVulnSeverity.MEDIUM
                        vuln.evidence += " [LLM: upgraded from LOW]"
            except Exception as exc:  # noqa: BLE001
                logger.debug("LLM triage error for %s: %s", vuln.vuln_id, exc)

    def _parse_tool(self, raw: dict) -> MCPTool:
        desc = raw.get("description", "")
        dangerous_kw = scan_for_dangerous_keywords(desc)
        return MCPTool(
            name=raw.get("name", ""),
            description=desc,
            input_schema=raw.get("inputSchema", {}),
            has_dangerous_keywords=bool(dangerous_kw),
            dangerous_keywords_found=dangerous_kw,
        )

    def _analyze_security(self, result: MCPScanResult) -> list[MCPVulnerability]:
        vulns: list[MCPVulnerability] = []

        # Unauthenticated access
        if result.auth_posture.unauthenticated_access:
            vulns.append(MCPVulnerability(
                vuln_id="OFFSEC-MCP-AUTH-001",
                severity=MCPVulnSeverity.HIGH,
                title="Unauthenticated MCP Endpoint",
                description=(
                    "The MCP server accepted an unauthenticated initialize request. "
                    "Any client can enumerate tools, resources, and prompts without credentials."
                ),
                remediation="Require OAuth 2.0 or API key authentication on the MCP endpoint.",
                references=["https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/"],
                affected_component="initialization",
            ))

        # Tool description analysis
        for tool in result.tools:
            if tool.has_dangerous_keywords:
                vulns.append(MCPVulnerability(
                    vuln_id="OFFSEC-MCP-TI-001",
                    severity=MCPVulnSeverity.HIGH,
                    title=f"Dangerous Keywords in Tool Description: '{tool.name}'",
                    description=(
                        f"Tool '{tool.name}' description contains keywords associated "
                        f"with tool-poisoning or injection attacks: "
                        f"{', '.join(tool.dangerous_keywords_found[:5])}."
                    ),
                    evidence=tool.description[:300],
                    remediation=(
                        "Audit and sanitize tool descriptions. Remove system override instructions "
                        "and shell/eval references. Verify tool implementations."
                    ),
                    affected_component=f"tool:{tool.name}",
                ))

            # Secrets in tool description
            secrets = scan_for_secrets(tool.description)
            if secrets:
                vulns.append(MCPVulnerability(
                    vuln_id="OFFSEC-MCP-SEC-001",
                    severity=MCPVulnSeverity.CRITICAL,
                    title=f"Secret/Credential Pattern in Tool Description: '{tool.name}'",
                    description=(
                        f"Tool '{tool.name}' description may contain credentials or secrets. "
                        f"Patterns matched: {', '.join(secrets[:5])}."
                    ),
                    evidence=tool.description[:300],
                    remediation="Remove all secrets from tool descriptions. Use environment variables.",
                    affected_component=f"tool:{tool.name}",
                ))

        # Resource URI path traversal check
        for resource in result.resources:
            if ".." in resource.uri or resource.uri.startswith("/"):
                vulns.append(MCPVulnerability(
                    vuln_id="OFFSEC-MCP-PT-001",
                    severity=MCPVulnSeverity.HIGH,
                    title=f"Potential Path Traversal in Resource URI: '{resource.uri}'",
                    description=(
                        f"Resource URI '{resource.uri}' contains path traversal indicators "
                        f"('..') or absolute paths that may expose sensitive files."
                    ),
                    evidence=resource.uri,
                    remediation=(
                        "Validate and canonicalize all resource URIs. "
                        "Enforce an allowed-path allowlist."
                    ),
                    affected_component=f"resource:{resource.uri}",
                ))

        # Prompt description secrets check
        for prompt in result.prompts:
            secrets = scan_for_secrets(prompt.description)
            if secrets:
                vulns.append(MCPVulnerability(
                    vuln_id="OFFSEC-MCP-SEC-002",
                    severity=MCPVulnSeverity.HIGH,
                    title=f"Secret Pattern in Prompt Description: '{prompt.name}'",
                    description=(
                        f"Prompt '{prompt.name}' description may contain sensitive data. "
                        f"Patterns matched: {', '.join(secrets[:5])}."
                    ),
                    evidence=prompt.description[:300],
                    remediation="Audit all prompt descriptions for embedded credentials.",
                    affected_component=f"prompt:{prompt.name}",
                ))

        # Overly broad tool scope heuristic
        shell_like = [
            t for t in result.tools
            if any(k in t.name.lower() for k in ["shell", "exec", "run", "bash", "cmd", "terminal"])
        ]
        if shell_like:
            for t in shell_like:
                vulns.append(MCPVulnerability(
                    vuln_id="OFFSEC-MCP-SCOPE-001",
                    severity=MCPVulnSeverity.CRITICAL,
                    title=f"Shell/Execution Tool Exposed: '{t.name}'",
                    description=(
                        f"Tool '{t.name}' appears to provide shell or command execution capabilities. "
                        f"If LLM-accessible, this creates a high-risk command injection vector."
                    ),
                    remediation=(
                        "Remove shell-execution tools unless strictly necessary. "
                        "Implement strict argument allow-lists and subprocess hardening."
                    ),
                    affected_component=f"tool:{t.name}",
                ))

        return vulns

    def _match_cves(self, server_info: MCPServerInfo) -> list[MCPVulnerability]:
        """Match server fingerprint against CVE database."""
        entries = match_cves(server_info.name, server_info.version)
        return [
            MCPVulnerability(
                vuln_id=entry.vuln_id,
                cve_id=entry.cve_id,
                severity=MCPVulnSeverity(entry.severity),
                title=entry.title,
                description=entry.description,
                remediation=entry.remediation,
                references=entry.references,
            )
            for entry in entries
        ]
