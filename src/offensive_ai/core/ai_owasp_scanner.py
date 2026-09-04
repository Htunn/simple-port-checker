"""
AI/LLM OWASP Top 10 (2025) black-box scanner.

Sends adversarial probes to a live LLM chat endpoint and evaluates
responses for security misconfigurations. Supports OpenAI-compatible
chat APIs as well as a generic JSON request/response format.

Usage:
    scanner = LLMOwaspScanner(
        endpoint="https://api.example.com/v1/chat/completions",
        mode="safe",
        api_format="openai",
        headers={"Authorization": "Bearer sk-..."},
    )
    result = await scanner.scan()
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from ..models.ai_owasp_result import (
    BatchLLMScanResult,
    LLMCategoryResult,
    LLMFinding,
    LLMScanMode,
    LLMScanResult,
    LLMSeverity,
)
from ..utils.ai_owasp_payloads import (
    ALL_PAYLOADS,
    NOT_TESTABLE_CATEGORIES,
    SAFE_MODE_CATEGORIES,
    get_payloads,
)
from ..utils.ai_owasp_remediation import LLM_CATEGORIES
from ..utils.constants import USER_AGENT


# Default categories for each scan mode
_SAFE_CATEGORIES = ["LLM02", "LLM07", "LLM09"]
_DEEP_CATEGORIES = ["LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM09", "LLM10"]
_ALL_CATEGORIES = list(LLM_CATEGORIES.keys())   # includes non-testable (reported as N/A)


class LLMOwaspScanner:
    """Black-box scanner for LLM OWASP Top 10 (2025) against a live endpoint."""

    def __init__(
        self,
        endpoint: str,
        mode: str = "safe",
        categories: list[str] | None = None,
        api_format: str = "openai",
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        judge: Any | None = None,
        model: str = "gpt-3.5-turbo",
    ) -> None:
        """
        Args:
            endpoint:   Full URL to the chat completions endpoint.
            mode:       "safe" (passive/benign probes) or "deep" (full adversarial).
            categories: Override list of LLM categories to test (e.g. ["LLM01", "LLM02"]).
            api_format: "openai" (default) or "generic" (custom JSON body/response path).
            headers:    Extra HTTP headers — e.g. Authorization.
            timeout:    Per-request timeout in seconds.
            judge:      Optional LLMJudge instance for AI-assisted evaluation.
            model:      Model name forwarded in OpenAI-format requests.
        """
        self.endpoint = endpoint.rstrip("/")
        self.mode = LLMScanMode(mode)
        self.api_format = api_format
        self.headers = headers or {}
        self.timeout = timeout
        self.judge = judge
        self.model = model

        if categories:
            self.categories = [c.upper() for c in categories]
        elif self.mode == LLMScanMode.DEEP:
            self.categories = _DEEP_CATEGORIES
        else:
            self.categories = _SAFE_CATEGORIES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self) -> LLMScanResult:
        """Run all enabled category checks and return a consolidated result."""
        start = time.monotonic()
        category_results: list[LLMCategoryResult] = []

        async with httpx.AsyncClient(
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                **self.headers,
            },
            timeout=self.timeout,
            trust_env=False,
        ) as client:
            # Run all categories — non-testable are handled synchronously
            tasks = []
            for cat_id in _ALL_CATEGORIES:
                tasks.append(self._scan_category(cat_id, client))
            category_results = list(await asyncio.gather(*tasks, return_exceptions=False))

        # Score each category
        for cat in category_results:
            cat.category_score = cat.calculate_score()
            cat.grade = cat.calculate_grade()

        scan_duration = time.monotonic() - start

        result = LLMScanResult(
            target=self.endpoint,
            scan_mode=self.mode,
            api_format=self.api_format,
            enabled_categories=self.categories,
            categories=category_results,
            scan_duration=scan_duration,
            judge_used=self.judge is not None,
        )
        result.overall_score = result.calculate_overall_score()
        result.overall_grade = result.calculate_overall_grade()
        return result

    async def batch_scan(
        self,
        targets: list[dict],
        max_concurrent: int = 3,
    ) -> BatchLLMScanResult:
        """
        Scan multiple endpoints concurrently.

        Args:
            targets: List of dicts with at least {"endpoint": "..."},
                     optionally {"headers": {...}, "model": "..."}.
            max_concurrent: Maximum parallel scans.
        """
        sem = asyncio.Semaphore(max_concurrent)
        start = time.monotonic()

        async def _guarded_scan(target_cfg: dict) -> LLMScanResult:
            async with sem:
                scanner = LLMOwaspScanner(
                    endpoint=target_cfg["endpoint"],
                    mode=self.mode.value,
                    categories=self.categories,
                    api_format=self.api_format,
                    headers=target_cfg.get("headers", self.headers),
                    timeout=self.timeout,
                    judge=self.judge,
                    model=target_cfg.get("model", self.model),
                )
                try:
                    return await scanner.scan()
                except Exception as exc:
                    return LLMScanResult(
                        target=target_cfg["endpoint"],
                        scan_mode=self.mode,
                        error=str(exc),
                    )

        results = await asyncio.gather(*[_guarded_scan(t) for t in targets])
        scan_duration = time.monotonic() - start

        successful = [r for r in results if not r.error]
        failed = [r for r in results if r.error]
        all_findings = [f for r in successful for f in r.all_findings]

        return BatchLLMScanResult(
            results=list(results),
            total_targets=len(targets),
            successful_scans=len(successful),
            failed_scans=len(failed),
            total_findings=len(all_findings),
            critical_count=sum(1 for f in all_findings if f.severity == LLMSeverity.CRITICAL),
            high_count=sum(1 for f in all_findings if f.severity == LLMSeverity.HIGH),
            scan_duration=scan_duration,
        )

    # ------------------------------------------------------------------
    # Category dispatch
    # ------------------------------------------------------------------

    async def _scan_category(
        self,
        category_id: str,
        client: httpx.AsyncClient,
    ) -> LLMCategoryResult:
        cat_meta = LLM_CATEGORIES.get(category_id, {})
        cat_name = cat_meta.get("name", category_id)

        # Non-testable categories
        if category_id in NOT_TESTABLE_CATEGORIES:
            return LLMCategoryResult(
                category_id=category_id,
                category_name=cat_name,
                testable=False,
                not_testable_reason=NOT_TESTABLE_CATEGORIES[category_id],
            )

        # Categories not in the enabled list for this mode
        if category_id not in self.categories:
            return LLMCategoryResult(
                category_id=category_id,
                category_name=cat_name,
                testable=False,
                not_testable_reason=f"Not enabled for {self.mode.value} mode scan.",
            )

        payloads = get_payloads(category_id, self.mode.value)
        if not payloads:
            return LLMCategoryResult(
                category_id=category_id,
                category_name=cat_name,
                testable=False,
                not_testable_reason="No payloads available for the current scan mode.",
            )

        findings: list[LLMFinding] = []
        for probe_def in payloads:
            finding = await self._run_probe(category_id, probe_def, client)
            if finding:
                findings.append(finding)

        return LLMCategoryResult(
            category_id=category_id,
            category_name=cat_name,
            findings=findings,
        )

    # ------------------------------------------------------------------
    # Probe execution
    # ------------------------------------------------------------------

    async def _run_probe(
        self,
        category_id: str,
        probe_def: dict,
        client: httpx.AsyncClient,
    ) -> LLMFinding | None:
        """Send a single probe and evaluate the response. Returns a Finding or None."""
        probe_text: str = probe_def.get("probe", "")
        probe_id: str = probe_def.get("id", "")
        description: str = probe_def.get("description", "")
        severity_str: str = probe_def.get("severity", "medium")
        detect_in: list[str] = probe_def.get("detect_in_response", [])
        detect_fn = probe_def.get("detect_fn")

        try:
            response_text = await self._send_probe(probe_text, client)
        except Exception as exc:
            # Network/timeout errors are not findings, but note them
            return None

        # Rule-based detection
        triggered = False
        evidence = ""
        response_lower = response_text.lower()

        if detect_in:
            for signal in detect_in:
                if signal.lower() in response_lower:
                    triggered = True
                    evidence = f"Response contained indicator '{signal}'"
                    break

        if not triggered and detect_fn:
            try:
                if detect_fn(response_text):
                    triggered = True
                    evidence = f"Response length {len(response_text)} chars exceeded threshold"
            except Exception:
                pass

        # Optional LLM judge pass
        if not triggered and self.judge:
            try:
                verdict = await asyncio.to_thread(
                    self.judge.evaluate,
                    category_id,
                    probe_text,
                    response_text,
                )
                if verdict.get("vulnerable"):
                    triggered = True
                    evidence = verdict.get("reason", "LLM judge flagged response")
            except Exception:
                pass

        if not triggered:
            return None

        # Map category to remediation key
        remediation_key = _REMEDIATION_KEY_MAP.get(probe_id, category_id.lower())
        cwe_id = _CWE_MAP.get(category_id)

        return LLMFinding(
            category=category_id,
            severity=LLMSeverity(severity_str),
            title=description,
            description=(
                f"Probe '{probe_id}' triggered a positive response indicating a potential "
                f"{LLM_CATEGORIES.get(category_id, {}).get('name', category_id)} vulnerability."
            ),
            remediation_key=remediation_key,
            cwe_id=cwe_id,
            owasp_llm_ref=LLM_CATEGORIES.get(category_id, {}).get("ref", ""),
            evidence=evidence[:500],      # truncate
            probe_used=probe_text[:200],  # truncate
        )

    async def _send_probe(self, probe_text: str, client: httpx.AsyncClient) -> str:
        """Send probe to the endpoint and return the response text."""
        if self.api_format == "openai":
            return await self._send_openai_format(probe_text, client)
        return await self._send_generic_format(probe_text, client)

    async def _send_openai_format(self, probe_text: str, client: httpx.AsyncClient) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": probe_text}],
            "max_tokens": 1024,
            "temperature": 0.0,
        }
        resp = await client.post(self.endpoint, json=payload)
        resp.raise_for_status()
        data = resp.json()
        # Standard OpenAI response shape
        return data["choices"][0]["message"]["content"]

    async def _send_generic_format(self, probe_text: str, client: httpx.AsyncClient) -> str:
        """Fallback for non-OpenAI APIs: POST {"prompt": ...}, expect {"response": ...}."""
        payload = {"prompt": probe_text, "max_tokens": 1024}
        resp = await client.post(self.endpoint, json=payload)
        resp.raise_for_status()
        data = resp.json()
        # Try common response field names
        for key in ("response", "text", "output", "content", "generated_text", "answer"):
            if key in data:
                return str(data[key])
        # Fallback: stringify the whole body
        return str(data)


# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

_REMEDIATION_KEY_MAP: dict[str, str] = {
    "LLM01-PI-001": "prompt_injection_direct",
    "LLM01-PI-002": "prompt_injection_direct",
    "LLM01-PI-003": "prompt_injection_direct",
    "LLM01-PI-004": "prompt_injection_direct",
    "LLM01-PI-005": "prompt_injection_direct",
    "LLM02-SD-001": "system_prompt_leakage",
    "LLM02-SD-002": "sensitive_info_disclosure",
    "LLM02-SD-003": "sensitive_info_disclosure",
    "LLM02-SD-004": "sensitive_info_disclosure",
    "LLM05-OH-001": "improper_output_xss",
    "LLM05-OH-002": "improper_output_xss",
    "LLM05-OH-003": "improper_output_xss",
    "LLM06-EA-001": "excessive_agency",
    "LLM06-EA-002": "excessive_agency",
    "LLM06-EA-003": "excessive_agency",
    "LLM07-SPL-001": "system_prompt_leakage",
    "LLM07-SPL-002": "system_prompt_leakage",
    "LLM07-SPL-003": "system_prompt_leakage",
    "LLM09-MI-001": "misinformation_no_guardrail",
    "LLM09-MI-002": "misinformation_no_guardrail",
    "LLM10-UC-001": "unbounded_consumption",
    "LLM10-UC-002": "unbounded_consumption",
}

_CWE_MAP: dict[str, int] = {
    "LLM01": 77,
    "LLM02": 200,
    "LLM05": 79,
    "LLM06": 272,
    "LLM07": 200,
    "LLM09": 1009,
    "LLM10": 400,
}
