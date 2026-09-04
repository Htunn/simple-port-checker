"""
Postman-collection attacker module for authorized red-team engagements.

THIS MODULE PERFORMS ACTIVE ATTACKS AGAINST THE API ENDPOINTS DEFINED IN A
POSTMAN COLLECTION. It must ONLY be used against systems for which you have
EXPLICIT WRITTEN AUTHORIZATION. Unauthorized use may violate the Computer
Fraud and Abuse Act, the Computer Misuse Act, and equivalent laws worldwide.

Attacks per endpoint (mirroring the OWASP API Security Top 10 2023):
- auth_bypass       (API2) — strip/mutate Authorization header
- bola              (API1) — mutate numeric IDs found in the URL (IDOR)
- mass_assignment   (API3) — inject privileged fields into JSON bodies
- injection         (—)    — SQLi/NoSQLi/CMDi/path traversal/XSS in query & body
- ssrf              (API7) — replace URL-looking fields with SSRF targets

If an LLMJudge is supplied, triggered findings are synthesized into a single
"exploit chain" narrative describing how the vulnerabilities discovered
across the collection could be chained together.

Usage (requires --i-have-authorization flag via CLI, or authorized=True in code):
    attacker = PostmanAttacker(authorized=True)
    report = await attacker.attack("collection.json", mode="deep")
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..exceptions import AuthorizationRequired
from ..utils.constants import USER_AGENT

from ._base import BaseAttacker
from ..models.postman_result import (
    PostmanAttackReport,
    PostmanAttackResult,
    PostmanEndpoint,
    PostmanVulnSeverity,
)
from ..utils.postman_parser import parse_collection
from ..utils.postman_payloads import (
    AUTH_BYPASS_PAYLOADS,
    BOLA_ID_MUTATIONS,
    INJECTION_PAYLOADS,
    MASS_ASSIGNMENT_FIELDS,
    SSRF_CANDIDATE_FIELD_NAMES,
    SSRF_PAYLOADS,
)

logger = logging.getLogger(__name__)
_ID_SEGMENT_PATTERN = re.compile(r"/(\d+)(?=/|$|\?)")


class PostmanAttacker(BaseAttacker):
    """
    Active attack module for API endpoints defined in a Postman collection.

    Requires authorized=True. Will refuse all operations if not authorized.
    """

    _MODULE_NAME = "POSTMAN"

    def __init__(self, authorized: bool = False, judge: object | None = None) -> None:
        super().__init__(authorized=authorized, judge=judge)

    async def attack(
        self,
        collection_path: str,
        environment_path: str | None = None,
        target_override: str | None = None,
        mode: str = "safe",
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        max_endpoints: int | None = None,
    ) -> PostmanAttackReport:
        """
        Run the attack suite against every endpoint in the collection.

        Args:
            collection_path:  Path to a Postman Collection v2.x JSON export.
            environment_path: Optional Postman Environment JSON export.
            target_override:  Override scheme+host of every request.
            mode:              "safe" (auth bypass probes only) or "deep" (full suite).
            headers:           Extra headers merged onto every request.
            timeout:            Per-request timeout in seconds.
            verify_tls:         Verify TLS certificates.
            max_endpoints:      Limit the number of endpoints attacked.
        """
        logger.warning(
            "Postman collection attack started against collection=%s mode=%s timestamp=%s",
            collection_path,
            mode,
            datetime.now(timezone.utc).isoformat(),
        )

        start = time.monotonic()
        try:
            name, endpoints = parse_collection(collection_path, environment_path, target_override)
        except Exception as exc:
            report = PostmanAttackReport(
                collection_name="",
                target_override=target_override or "",
                authorized=True,
                scan_duration=time.monotonic() - start,
            )
            report.exploit_chain_summary = f"Failed to parse collection: {exc}"
            return report

        if max_endpoints is not None:
            endpoints = endpoints[:max_endpoints]

        headers = headers or {}
        all_results: list[PostmanAttackResult] = []

        for endpoint in endpoints:
            if not endpoint.url or not endpoint.url.startswith(("http://", "https://")):
                continue
            all_results.extend(await self._attack_auth_bypass(endpoint, headers, timeout, verify_tls))

        if mode == "deep":
            for endpoint in endpoints:
                if not endpoint.url or not endpoint.url.startswith(("http://", "https://")):
                    continue
                all_results.extend(await self._attack_bola(endpoint, headers, timeout, verify_tls))
                if endpoint.body_mode == "raw" and endpoint.method in ("POST", "PUT", "PATCH"):
                    all_results.extend(await self._attack_mass_assignment(endpoint, headers, timeout, verify_tls))
                all_results.extend(await self._attack_injection(endpoint, headers, timeout, verify_tls))
                all_results.extend(await self._attack_ssrf(endpoint, headers, timeout, verify_tls))

        triggered = [r for r in all_results if r.triggered]
        report = PostmanAttackReport(
            collection_name=name,
            target_override=target_override or "",
            authorized=True,
            attacks_run=len(all_results),
            attacks_triggered=len(triggered),
            results=all_results,
            scan_duration=time.monotonic() - start,
        )

        if self._judge and getattr(self._judge, "provider", None):
            self._enrich_with_llm(report)

        return report

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_client(self, extra_headers: dict | None, timeout: float, verify_tls: bool) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT, **(extra_headers or {})},
            timeout=timeout,
            trust_env=False,
            verify=verify_tls,  # noqa: S501 — intentional for attack testing
        )

    @staticmethod
    def _label(endpoint: PostmanEndpoint) -> str:
        return f"{endpoint.method} {endpoint.url}"

    # ------------------------------------------------------------------
    # Auth bypass (API2:2023)
    # ------------------------------------------------------------------

    async def _attack_auth_bypass(
        self, endpoint: PostmanEndpoint, headers: dict, timeout: float, verify_tls: bool
    ) -> list[PostmanAttackResult]:
        results: list[PostmanAttackResult] = []
        has_auth = endpoint.auth.type not in ("noauth", "") or any(
            k.lower() == "authorization" for k in endpoint.headers
        )
        if not has_auth:
            return results  # nothing to bypass — already unauthenticated (flagged by scanner)

        for probe in AUTH_BYPASS_PAYLOADS:
            test_headers = dict(endpoint.headers)
            if probe["mutation"] == "strip_auth":
                test_headers = {k: v for k, v in test_headers.items() if k.lower() != "authorization"}
            else:
                test_headers.update(probe.get("headers", {}))
            test_headers.update(headers)

            triggered = False
            response_text = ""
            try:
                kwargs: dict[str, Any] = {"headers": test_headers}
                if endpoint.body and endpoint.method in ("POST", "PUT", "PATCH", "DELETE"):
                    kwargs["content"] = endpoint.body
                async with self._make_client(None, timeout, verify_tls) as client:
                    resp = await client.request(endpoint.method, endpoint.url, **kwargs)
                    response_text = resp.text[:500]
                    if resp.status_code < 400:
                        triggered = True
            except Exception as exc:
                response_text = str(exc)

            results.append(PostmanAttackResult(
                attack_id=probe["id"],
                endpoint=self._label(endpoint),
                attack_type="auth_bypass",
                payload=str(probe.get("headers", probe["mutation"])),
                response=response_text,
                triggered=triggered,
                severity=PostmanVulnSeverity(probe["severity"]) if triggered else PostmanVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=response_text if triggered else "",
            ))
        return results

    # ------------------------------------------------------------------
    # BOLA / IDOR (API1:2023)
    # ------------------------------------------------------------------

    async def _attack_bola(
        self, endpoint: PostmanEndpoint, headers: dict, timeout: float, verify_tls: bool
    ) -> list[PostmanAttackResult]:
        results: list[PostmanAttackResult] = []
        match = _ID_SEGMENT_PATTERN.search(endpoint.url)
        if not match:
            return results
        original_id = int(match.group(1))

        for probe in BOLA_ID_MUTATIONS:
            if probe["strategy"] == "increment":
                mutated_id = original_id + 1
            elif probe["strategy"] == "decrement":
                mutated_id = max(original_id - 1, 0)
            else:  # "one"
                mutated_id = 1
            if mutated_id == original_id:
                continue

            mutated_url = (
                endpoint.url[: match.start(1)] + str(mutated_id) + endpoint.url[match.end(1):]
            )
            triggered = False
            response_text = ""
            try:
                test_headers = {**endpoint.headers, **headers}
                async with self._make_client(None, timeout, verify_tls) as client:
                    resp = await client.request(endpoint.method, mutated_url, headers=test_headers)
                    response_text = resp.text[:500]
                    if resp.status_code == 200 and response_text.strip():
                        triggered = True
            except Exception as exc:
                response_text = str(exc)

            results.append(PostmanAttackResult(
                attack_id=probe["id"],
                endpoint=self._label(endpoint),
                attack_type="bola",
                payload=mutated_url,
                response=response_text,
                triggered=triggered,
                severity=PostmanVulnSeverity(probe["severity"]) if triggered else PostmanVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=f"HTTP 200 for object id={mutated_id} (needs manual ownership verification)" if triggered else "",
            ))
        return results

    # ------------------------------------------------------------------
    # Mass assignment (API3:2023)
    # ------------------------------------------------------------------

    async def _attack_mass_assignment(
        self, endpoint: PostmanEndpoint, headers: dict, timeout: float, verify_tls: bool
    ) -> list[PostmanAttackResult]:
        results: list[PostmanAttackResult] = []
        try:
            base_obj = json.loads(endpoint.body) if endpoint.body else {}
        except (json.JSONDecodeError, TypeError):
            return results
        if not isinstance(base_obj, dict):
            return results

        for probe in MASS_ASSIGNMENT_FIELDS:
            mutated = dict(base_obj)
            mutated[probe["field"]] = probe["value"]
            mutated_body = json.dumps(mutated)

            triggered = False
            response_text = ""
            try:
                test_headers = {**endpoint.headers, **headers, "Content-Type": "application/json"}
                async with self._make_client(None, timeout, verify_tls) as client:
                    resp = await client.request(
                        endpoint.method, endpoint.url, headers=test_headers, content=mutated_body
                    )
                    response_text = resp.text[:500]
                    if resp.status_code < 400 and (
                        str(probe["value"]).lower() in response_text.lower() or probe["field"] in response_text
                    ):
                        triggered = True
            except Exception as exc:
                response_text = str(exc)

            results.append(PostmanAttackResult(
                attack_id=probe["id"],
                endpoint=self._label(endpoint),
                attack_type="mass_assignment",
                payload=f"{probe['field']}={probe['value']}",
                response=response_text,
                triggered=triggered,
                severity=PostmanVulnSeverity(probe["severity"]) if triggered else PostmanVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=f"Server echoed injected field '{probe['field']}'" if triggered else "",
            ))
        return results

    # ------------------------------------------------------------------
    # Injection (query params + JSON body fields)
    # ------------------------------------------------------------------

    async def _attack_injection(
        self, endpoint: PostmanEndpoint, headers: dict, timeout: float, verify_tls: bool
    ) -> list[PostmanAttackResult]:
        results: list[PostmanAttackResult] = []
        if not endpoint.query_params:
            return results
        target_param = next(iter(endpoint.query_params))

        for probe in INJECTION_PAYLOADS:
            mutated_params = dict(endpoint.query_params)
            mutated_params[target_param] = probe["payload"]

            triggered = False
            response_text = ""
            evidence = ""
            try:
                test_headers = {**endpoint.headers, **headers}
                async with self._make_client(None, timeout, verify_tls) as client:
                    resp = await client.request(
                        endpoint.method, endpoint.url, headers=test_headers, params=mutated_params
                    )
                    response_text = resp.text[:800]
                    for signal in probe.get("detect_in_response", []):
                        if signal.lower() in response_text.lower():
                            triggered = True
                            evidence = f"Injection signal '{signal}' found in response"
                            break
            except Exception as exc:
                response_text = str(exc)

            results.append(PostmanAttackResult(
                attack_id=probe["id"],
                endpoint=self._label(endpoint),
                attack_type="injection",
                payload=f"{target_param}={probe['payload']}",
                response=response_text,
                triggered=triggered,
                severity=PostmanVulnSeverity(probe["severity"]) if triggered else PostmanVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=evidence,
            ))
        return results

    # ------------------------------------------------------------------
    # SSRF (API7:2023)
    # ------------------------------------------------------------------

    async def _attack_ssrf(
        self, endpoint: PostmanEndpoint, headers: dict, timeout: float, verify_tls: bool
    ) -> list[PostmanAttackResult]:
        results: list[PostmanAttackResult] = []

        ssrf_field = None
        in_query = False
        for key in endpoint.query_params:
            if key.lower() in SSRF_CANDIDATE_FIELD_NAMES:
                ssrf_field = key
                in_query = True
                break
        base_obj: dict | None = None
        if ssrf_field is None and endpoint.body_mode == "raw":
            try:
                parsed_body = json.loads(endpoint.body) if endpoint.body else {}
                if isinstance(parsed_body, dict):
                    for key in parsed_body:
                        if key.lower() in SSRF_CANDIDATE_FIELD_NAMES:
                            ssrf_field = key
                            base_obj = parsed_body
                            break
            except (json.JSONDecodeError, TypeError):
                pass

        if ssrf_field is None:
            return results

        for probe in SSRF_PAYLOADS:
            triggered = False
            response_text = ""
            evidence = ""
            try:
                test_headers = {**endpoint.headers, **headers}
                async with self._make_client(None, timeout, verify_tls) as client:
                    if in_query:
                        mutated_params = dict(endpoint.query_params)
                        mutated_params[ssrf_field] = probe["url"]
                        resp = await client.request(
                            endpoint.method, endpoint.url, headers=test_headers, params=mutated_params
                        )
                    else:
                        mutated_obj = dict(base_obj or {})
                        mutated_obj[ssrf_field] = probe["url"]
                        test_headers["Content-Type"] = "application/json"
                        resp = await client.request(
                            endpoint.method, endpoint.url, headers=test_headers,
                            content=json.dumps(mutated_obj),
                        )
                    response_text = resp.text[:800]
                    for signal in probe.get("detect_in_response", []):
                        if signal.lower() in response_text.lower():
                            triggered = True
                            evidence = f"SSRF signal '{signal}' detected in response"
                            break
            except Exception as exc:
                response_text = str(exc)

            results.append(PostmanAttackResult(
                attack_id=probe["id"],
                endpoint=self._label(endpoint),
                attack_type="ssrf",
                payload=f"{ssrf_field}={probe['url']}",
                response=response_text,
                triggered=triggered,
                severity=PostmanVulnSeverity(probe["severity"]) if triggered else PostmanVulnSeverity.INFO,
                title=probe["description"],
                description=probe["description"],
                evidence=evidence,
            ))
        return results

    # ------------------------------------------------------------------
    # Optional LLM enrichment — exploit-chain synthesis
    # ------------------------------------------------------------------

    def _enrich_with_llm(self, report: PostmanAttackReport) -> None:
        if not self._judge:
            return
        triggered = [r for r in report.results if r.triggered]
        if not triggered:
            return
        try:
            summary = "; ".join(f"{r.attack_type}@{r.endpoint}: {r.title}" for r in triggered[:10])
            verdict = self._judge.evaluate(
                category="Postman collection exploit chain",
                probe=summary,
                response=f"{len(triggered)} attack(s) triggered across {report.collection_name}",
            )
            report.exploit_chain_summary = str(verdict.get("reason", ""))
            for r in triggered:
                r.llm_confidence = float(verdict.get("confidence", 0.0))
        except Exception as exc:  # noqa: BLE001
            logger.debug("LLM enrichment error: %s", exc)
