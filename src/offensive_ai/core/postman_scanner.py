"""
Postman Collection-driven API security scanner.

Parses a Postman Collection v2.x export (optionally with a Postman
Environment export for variable resolution), sends each request to the
declared or overridden target, and performs passive security analysis:
missing authentication on sensitive-looking endpoints, verbose error
disclosure, exposed secrets in responses, permissive CORS, and unresolved
template variables. Optionally triages ambiguous findings with an LLM judge.

Usage:
    scanner = PostmanScanner("collection.json", environment_path="env.json")
    result = await scanner.scan()
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from ..models.postman_result import (
    PostmanEndpoint,
    PostmanEndpointResult,
    PostmanScanResult,
    PostmanVulnerability,
    PostmanVulnSeverity,
)
from ..utils.postman_findings import (
    SENSITIVE_ENDPOINT_KEYWORDS,
    VERBOSE_ERROR_PATTERNS,
    scan_for_secrets,
)
from ..utils.postman_parser import parse_collection


from ..utils.constants import USER_AGENT
logger = logging.getLogger(__name__)




class PostmanScanner:
    """Passive security scanner for API endpoints defined in a Postman collection."""

    def __init__(
        self,
        collection_path: str,
        environment_path: str | None = None,
        target_override: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        max_endpoints: int | None = None,
        judge: object | None = None,
    ) -> None:
        """
        Args:
            collection_path:  Path to a Postman Collection v2.x JSON export.
            environment_path: Optional path to a Postman Environment JSON export.
            target_override:  Override scheme+host of every request (point the
                               collection at a different target than it was recorded against).
            headers:          Extra headers merged onto every request (e.g. a fresh auth token).
            timeout:          Per-request timeout in seconds.
            verify_tls:       Verify TLS certificates. Set False for self-signed certs.
            max_endpoints:    Limit the number of requests tested (large collections).
            judge:            Optional LLMJudge instance for AI-assisted triage.
        """
        self.collection_path = collection_path
        self.environment_path = environment_path
        self.target_override = target_override
        self.headers = headers or {}
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.max_endpoints = max_endpoints
        self._judge = judge

    async def scan(self) -> PostmanScanResult:
        """Parse the collection, probe each endpoint, and analyze responses."""
        start = time.monotonic()

        try:
            name, endpoints = parse_collection(
                self.collection_path, self.environment_path, self.target_override
            )
        except Exception as exc:
            result = PostmanScanResult(error=f"Failed to parse collection: {exc}")
            result.scan_duration = time.monotonic() - start
            return result

        result = PostmanScanResult(
            collection_name=name,
            target_override=self.target_override or "",
            endpoints_total=len(endpoints),
        )

        if self.max_endpoints is not None:
            endpoints = endpoints[: self.max_endpoints]

        async with httpx.AsyncClient(
            timeout=self.timeout,
            trust_env=False,
            verify=self.verify_tls,  # noqa: S501 — intentional for security scanning
            follow_redirects=True,
        ) as client:
            for endpoint in endpoints:
                endpoint_result = await self._probe_endpoint(client, endpoint)
                result.endpoint_results.append(endpoint_result)
                result.endpoints_tested += 1
                result.vulnerabilities.extend(self._analyze_endpoint(endpoint, endpoint_result))

        if self._judge and getattr(self._judge, "provider", None):
            self._phase_llm_triage(result)

        result.scan_duration = time.monotonic() - start
        return result

    # ------------------------------------------------------------------
    # Request execution
    # ------------------------------------------------------------------

    async def _probe_endpoint(
        self, client: httpx.AsyncClient, endpoint: PostmanEndpoint
    ) -> PostmanEndpointResult:
        req_start = time.monotonic()
        endpoint_result = PostmanEndpointResult(endpoint=endpoint)

        if not endpoint.url or not endpoint.url.startswith(("http://", "https://")):
            endpoint_result.error = f"Unresolvable or non-HTTP URL: {endpoint.raw_url}"
            return endpoint_result

        try:
            merged_headers = {**endpoint.headers, **self.headers, "User-Agent": USER_AGENT}
            kwargs: dict[str, Any] = {"headers": merged_headers}
            if endpoint.body and endpoint.method in ("POST", "PUT", "PATCH", "DELETE"):
                kwargs["content"] = endpoint.body
            resp = await client.request(endpoint.method, endpoint.url, **kwargs)
            endpoint_result.status_code = resp.status_code
            endpoint_result.response_snippet = resp.text[:1000]
            endpoint_result.response_headers = dict(resp.headers)
        except Exception as exc:
            endpoint_result.error = str(exc)

        endpoint_result.duration = time.monotonic() - req_start
        return endpoint_result

    # ------------------------------------------------------------------
    # Static analysis
    # ------------------------------------------------------------------

    def _analyze_endpoint(
        self, endpoint: PostmanEndpoint, endpoint_result: PostmanEndpointResult
    ) -> list[PostmanVulnerability]:
        vulns: list[PostmanVulnerability] = []
        label = f"{endpoint.method} {endpoint.url or endpoint.raw_url}"

        # 1. Missing auth on a sensitive-looking endpoint that responded successfully
        text_to_check = f"{endpoint.name} {endpoint.raw_url} {endpoint.folder_path}".lower()
        is_sensitive = any(kw in text_to_check for kw in SENSITIVE_ENDPOINT_KEYWORDS)
        has_auth = endpoint.auth.type not in ("noauth", "") or any(
            k.lower() == "authorization" for k in endpoint.headers
        )
        if (
            is_sensitive
            and not has_auth
            and endpoint_result.status_code
            and endpoint_result.status_code < 400
        ):
            vulns.append(PostmanVulnerability(
                vuln_id="PM-ADV-AUTH-001",
                severity=PostmanVulnSeverity.HIGH,
                title=f"Sensitive endpoint accessible without authentication: {endpoint.name}",
                description=(
                    "This endpoint's name/path suggests a sensitive operation, has no "
                    "declared Postman auth block or Authorization header, and returned "
                    f"a non-error status ({endpoint_result.status_code})."
                ),
                endpoint=label,
                evidence=f"HTTP {endpoint_result.status_code}, no auth configured",
                remediation="Require authentication/authorization on this endpoint.",
                owasp_api_category="API2:2023 Broken Authentication",
            ))

        # 2. Unresolved template variables — collection not fully configured
        if endpoint.unresolved_variables:
            vulns.append(PostmanVulnerability(
                vuln_id="PM-ADV-CFG-001",
                severity=PostmanVulnSeverity.INFO,
                title=f"Unresolved Postman variables in request: {endpoint.name}",
                description=(
                    f"Variables {endpoint.unresolved_variables} could not be resolved from "
                    "the collection or environment file, so this request may not have been "
                    "sent as intended."
                ),
                endpoint=label,
                remediation="Provide a Postman environment export with these variables defined.",
            ))

        # 3. Verbose error disclosure
        if endpoint_result.response_snippet:
            body_lower = endpoint_result.response_snippet.lower()
            for pattern_desc, needle in VERBOSE_ERROR_PATTERNS:
                if needle in body_lower:
                    vulns.append(PostmanVulnerability(
                        vuln_id="PM-ADV-MISC-001",
                        severity=PostmanVulnSeverity.MEDIUM,
                        title=f"Verbose error disclosure: {endpoint.name}",
                        description=f"Response body appears to contain {pattern_desc}.",
                        endpoint=label,
                        evidence=endpoint_result.response_snippet[:200],
                        remediation="Return generic error messages to clients; log details server-side only.",
                        owasp_api_category="API8:2023 Security Misconfiguration",
                    ))
                    break

        # 4. Secrets leaked in response
        secrets = scan_for_secrets(endpoint_result.response_snippet)
        if secrets:
            vulns.append(PostmanVulnerability(
                vuln_id="PM-ADV-SEC-001",
                severity=PostmanVulnSeverity.CRITICAL,
                title=f"Possible secret exposed in response: {endpoint.name}",
                description=f"Response body matches secret-like patterns: {', '.join(secrets[:3])}.",
                endpoint=label,
                evidence=endpoint_result.response_snippet[:200],
                remediation="Remove credentials/tokens from API responses. Rotate any exposed secrets.",
                owasp_api_category="API3:2023 Broken Object Property Level Authorization",
            ))

        # 5. Permissive CORS
        acao = endpoint_result.response_headers.get(
            "access-control-allow-origin"
        ) or endpoint_result.response_headers.get("Access-Control-Allow-Origin")
        if acao == "*":
            vulns.append(PostmanVulnerability(
                vuln_id="PM-ADV-MISC-002",
                severity=PostmanVulnSeverity.MEDIUM,
                title=f"Wildcard CORS policy: {endpoint.name}",
                description="Access-Control-Allow-Origin is '*', allowing any origin to read responses.",
                endpoint=label,
                evidence="Access-Control-Allow-Origin: *",
                remediation="Restrict CORS to a specific allowlist of trusted origins.",
                owasp_api_category="API8:2023 Security Misconfiguration",
            ))

        return vulns

    # ------------------------------------------------------------------
    # Optional LLM triage
    # ------------------------------------------------------------------

    def _phase_llm_triage(self, result: PostmanScanResult) -> None:
        """Use LLM judge to enrich MEDIUM/LOW findings."""
        ambiguous = {PostmanVulnSeverity.MEDIUM, PostmanVulnSeverity.LOW}
        for vuln in result.vulnerabilities:
            if vuln.severity not in ambiguous:
                continue
            try:
                verdict = self._judge.evaluate(
                    category=vuln.owasp_api_category or vuln.vuln_id,
                    probe=vuln.title,
                    response=vuln.evidence or vuln.description,
                )
                vuln.llm_confidence = float(verdict.get("confidence", 0.0))
                vuln.llm_reasoning = str(verdict.get("reason", ""))
                if verdict.get("vulnerable") and vuln.llm_confidence > 0.7:
                    if vuln.severity == PostmanVulnSeverity.LOW:
                        vuln.severity = PostmanVulnSeverity.MEDIUM
                        vuln.evidence += " [LLM: upgraded from LOW]"
            except Exception as exc:  # noqa: BLE001
                logger.debug("LLM triage error for %s: %s", vuln.vuln_id, exc)
