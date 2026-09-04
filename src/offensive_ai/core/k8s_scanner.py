"""
Kubernetes cluster black-box security scanner.

Connects to exposed Kubernetes components (kube-apiserver, kubelet, etcd,
scheduler, controller-manager, kube-proxy, cAdvisor, dashboard) via HTTP/HTTPS,
fingerprints the cluster, detects anonymous access and misconfigurations, and
maps findings to the OWASP Kubernetes Top 10 (2025).

An optional LLM judge can triage ambiguous findings and generate remediation.

Usage:
    scanner = K8sScanner("192.168.1.100")
    result = await scanner.scan()

    # With custom ports and LLM judge:
    from offensive_ai import LLMJudge
    judge = LLMJudge()
    scanner = K8sScanner("k8s.example.com", ports=[6443, 10250], judge=judge)
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

from ..exceptions import TargetUnreachableError
from ..models.k8s_result import (
    K8sComponent,
    K8sExposedComponent,
    K8sScanResult,
    K8sServerInfo,
    K8sVulnerability,
    K8sVulnSeverity,
)
from ..utils.k8s_cve_db import K8sCVEEntry, match_cves
from ..utils.k8s_payloads import (
    APISERVER_ANONYMOUS_RESOURCE_PATHS,
    APISERVER_PROBE_PATHS,
    CADVISOR_PROBE_PATHS,
    CONTROL_PLANE_PROBE_PATHS,
    ETCD_PROBE_PATHS,
    K8S_COMPONENT_PORTS,
    K8S_DEFAULT_SCAN_PORTS,
    K8S_FINGERPRINTS,
    KUBELET_PROBE_PATHS,
)


from ..utils.constants import USER_AGENT
logger = logging.getLogger(__name__)

# Maximum bytes to read from any single response body
_MAX_RESPONSE_BYTES = 65_536

# Ports that run TLS by default
_TLS_PORTS = {6443, 443, 10250, 10259, 10257, 2380, 8443}

# Map port → likely component (first match wins)
_PORT_COMPONENT_MAP: dict[int, K8sComponent] = {
    6443: K8sComponent.API_SERVER,
    443: K8sComponent.API_SERVER,
    8080: K8sComponent.API_SERVER,
    10250: K8sComponent.KUBELET,
    10255: K8sComponent.KUBELET,
    2379: K8sComponent.ETCD,
    2380: K8sComponent.ETCD,
    10259: K8sComponent.SCHEDULER,
    10257: K8sComponent.CONTROLLER_MANAGER,
    10249: K8sComponent.KUBE_PROXY,
    4194: K8sComponent.CADVISOR,
    8443: K8sComponent.DASHBOARD,
    30000: K8sComponent.DASHBOARD,
    31000: K8sComponent.DASHBOARD,
    32000: K8sComponent.DASHBOARD,
}

# Insecure sandbox / auth mode strings
_INSECURE_VALUES = frozenset({"disabled", "none", "false", "no", "0", "always", "alwaysallow"})


class K8sScanner:
    """
    Black-box Kubernetes cluster security scanner.

    Probes exposed component ports, fingerprints the cluster version, detects
    anonymous authentication, and maps findings to OWASP Kubernetes Top 10 (2025).
    """

    def __init__(
        self,
        target: str,
        ports: list[int] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        judge: Any | None = None,    # LLMJudge instance (optional)
    ) -> None:
        """
        Args:
            target:  Hostname or IP address of the cluster nodes/control plane.
            ports:   Ports to probe. Defaults to all well-known K8s component ports.
            headers: Extra HTTP headers (e.g. Authorization for semi-auth scans).
            timeout: Per-request timeout in seconds.
            judge:   Optional LLMJudge for finding triage and remediation advice.
        """
        self._target = target
        self._ports = ports or K8S_DEFAULT_SCAN_PORTS
        self.headers = headers or {}
        self.timeout = timeout
        self._judge = judge

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self) -> K8sScanResult:
        """
        Five-phase security assessment of exposed Kubernetes components:

        1. Component discovery & fingerprinting
        2. Version extraction & CVE matching (K07)
        3. Anonymous authentication posture (K09)
        4. Secrets / resource exposure (K03) + workload config (K01) via kubelet
        5. OWASP mapping + optional LLM judge triage
        """
        start = time.monotonic()
        result = K8sScanResult(target=self._target, ports=self._ports)

        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": USER_AGENT, **self.headers},
                timeout=httpx.Timeout(self.timeout, connect=10.0),
                follow_redirects=True,
                verify=False,  # noqa: S501 — intentional; security scanning of self-signed certs
                trust_env=False,
            ) as client:
                # Phase 1: Discover and fingerprint accessible components
                await self._phase_discover(client, result)

                if not result.is_kubernetes:
                    result.error = (
                        "No Kubernetes components detected on the specified ports. "
                        "Try --port 6443, 10250, 2379 or verify the target address."
                    )
                    result.scan_duration = time.monotonic() - start
                    return result

                # Phase 2: Version extraction + CVE matching
                await self._phase_version_and_cves(client, result)

                # Phase 3: Anonymous authentication posture
                await self._phase_auth_posture(client, result)

                # Phase 4: Secrets / resource exposure + workload inspection
                await self._phase_exposure(client, result)

                # Phase 5: Final OWASP mapping + optional LLM judge
                self._phase_owasp_map(result)
                if self._judge and getattr(self._judge, "provider", None):
                    await self._phase_llm_triage(result)

        except httpx.ConnectError as exc:
            result.error = f"Connection refused or target unreachable: {exc}"
        except httpx.TimeoutException:
            result.error = "Connection timed out."
        except TargetUnreachableError as exc:
            result.error = str(exc)
        except Exception as exc:  # noqa: BLE001
            result.error = f"Unexpected error during scan: {exc}"

        result.scan_duration = time.monotonic() - start
        return result

    # ------------------------------------------------------------------
    # Phase 1: Component discovery
    # ------------------------------------------------------------------

    async def _phase_discover(self, client: httpx.AsyncClient, result: K8sScanResult) -> None:
        """Probe each port, determine component type, and fingerprint."""
        tasks = [self._probe_port(client, port) for port in self._ports]
        probe_results = await asyncio.gather(*tasks, return_exceptions=True)

        for port, probe in zip(self._ports, probe_results):
            if isinstance(probe, Exception):
                logger.debug("Port %s probe error: %s", port, probe)
                continue
            if probe is None:
                continue
            exposed, info_update = probe
            result.exposed_components.append(exposed)
            if exposed.accessible:
                result.is_kubernetes = True
                if info_update:
                    # Preserve components already discovered before replacing server_info
                    info_update.components_found = list(result.server_info.components_found)
                    result.server_info = info_update
                if exposed.component not in result.server_info.components_found:
                    result.server_info.components_found.append(exposed.component)

    async def _probe_port(
        self, client: httpx.AsyncClient, port: int
    ) -> tuple[K8sExposedComponent, K8sServerInfo | None] | None:
        """
        Probe a single port.  Returns (K8sExposedComponent, optional updated K8sServerInfo).
        """
        use_tls = port in _TLS_PORTS
        scheme = "https" if use_tls else "http"
        base = f"{scheme}://{self._target}:{port}"
        component = _PORT_COMPONENT_MAP.get(port, K8sComponent.API_SERVER)

        # Choose probe paths by component type
        if component == K8sComponent.API_SERVER:
            probe_paths = ["/version", "/healthz"]
        elif component == K8sComponent.KUBELET:
            probe_paths = ["/healthz", "/pods"]
        elif component == K8sComponent.ETCD:
            probe_paths = ["/health", "/version"]
        elif component in (K8sComponent.SCHEDULER, K8sComponent.CONTROLLER_MANAGER,
                           K8sComponent.KUBE_PROXY):
            probe_paths = ["/healthz", "/metrics"]
        elif component == K8sComponent.CADVISOR:
            probe_paths = ["/healthz", "/metrics"]
        elif component == K8sComponent.DASHBOARD:
            probe_paths = ["/", "/api/v1/csrftoken/login"]
        else:
            probe_paths = ["/healthz"]

        exposed = K8sExposedComponent(component=component, port=port, tls=use_tls)
        server_info_update: K8sServerInfo | None = None

        for path in probe_paths:
            url = f"{base}{path}"
            status, body, resp_headers = await self._get_raw(client, url)
            if status == 0:
                continue
            if status in (200, 401, 403):        # 401/403 = port is live, just auth-required
                exposed.accessible = True
                exposed.anonymous_access = status == 200

                # Fingerprint from body
                if body and self._matches_fingerprint(body, resp_headers, component):
                    if component == K8sComponent.API_SERVER and path == "/version":
                        server_info_update = self._parse_version(body)
                    if component == K8sComponent.KUBELET:
                        exposed.version = ""     # kubelet doesn't expose version in /healthz
                    if component == K8sComponent.ETCD:
                        exposed.version = _safe_str(body, "etcdserver", "")
                    exposed.evidence = f"HTTP {status} on {path}"
                else:
                    # Still reachable even without fingerprint match
                    exposed.evidence = f"HTTP {status} on {path}"
                break
        return exposed, server_info_update

    def _matches_fingerprint(
        self,
        body: dict[str, Any],
        headers: dict[str, str],
        component: K8sComponent,
    ) -> bool:
        """Check body keys or response headers against known K8s fingerprints."""
        for fp in K8S_FINGERPRINTS:
            if fp.get("component") != component.value:
                continue
            if fp["source"] == "body" and fp.get("key") in body:
                return True
            if fp["source"] == "header":
                lower_h = {k.lower(): v for k, v in headers.items()}
                if fp["header"].lower() in lower_h:
                    if "value" not in fp:
                        return True
                    if fp["value"].lower() in lower_h[fp["header"].lower()].lower():
                        return True
        return False

    def _parse_version(self, body: dict[str, Any]) -> K8sServerInfo:
        """Extract K8sServerInfo from an API server /version response body."""
        return K8sServerInfo(
            version=_safe_str(body, "gitVersion", ""),
            git_version=_safe_str(body, "gitVersion", ""),
            platform=_safe_str(body, "platform", ""),
            go_version=_safe_str(body, "goVersion", ""),
            build_date=_safe_str(body, "buildDate", ""),
            raw=body,
        )

    # ------------------------------------------------------------------
    # Phase 2: Version + CVE matching
    # ------------------------------------------------------------------

    async def _phase_version_and_cves(
        self, client: httpx.AsyncClient, result: K8sScanResult
    ) -> None:
        """If we don't have a version yet, re-probe apiserver /version. Then match CVEs."""
        if not result.server_info.git_version:
            for port in self._ports:
                if _PORT_COMPONENT_MAP.get(port) == K8sComponent.API_SERVER:
                    scheme = "https" if port in _TLS_PORTS else "http"
                    status, body, _ = await self._get_raw(
                        client, f"{scheme}://{self._target}:{port}/version"
                    )
                    if status == 200 and body and "gitVersion" in body:
                        result.server_info = self._parse_version(body)
                        break

        version = result.server_info.git_version
        accessible_comps = [c.value for c in result.server_info.components_found]
        matched = match_cves(version, accessible_comps)

        for entry in matched:
            vuln = K8sVulnerability(
                vuln_id=entry.vuln_id,
                owasp_id=entry.owasp_id,
                cve_id=entry.cve_id,
                severity=K8sVulnSeverity(entry.severity),
                title=entry.title,
                description=entry.description,
                component=K8sComponent(entry.check_component) if entry.check_component else None,
                evidence=f"Matched against version '{version}' and components {accessible_comps}",
                remediation=entry.remediation,
                references=entry.references,
            )
            result.vulnerabilities.append(vuln)
            if entry.cve_id:
                result.cve_matches.append(entry.cve_id)

    # ------------------------------------------------------------------
    # Phase 3: Anonymous authentication posture
    # ------------------------------------------------------------------

    async def _phase_auth_posture(
        self, client: httpx.AsyncClient, result: K8sScanResult
    ) -> None:
        """Check whether exposed components accept unauthenticated requests."""
        for exposed in result.exposed_components:
            if not exposed.accessible or not exposed.anonymous_access:
                continue

            scheme = "https" if exposed.port in _TLS_PORTS else "http"
            base = f"{scheme}://{self._target}:{exposed.port}"

            if exposed.component == K8sComponent.API_SERVER:
                await self._check_apiserver_anon(client, base, result)
            elif exposed.component == K8sComponent.KUBELET:
                await self._check_kubelet_anon(client, base, result)
            elif exposed.component == K8sComponent.ETCD:
                self._add_vuln(result, "K8S-ADV-004", "K06", K8sVulnSeverity.CRITICAL,
                               K8sComponent.ETCD,
                               "etcd Accessible Without Authentication",
                               "The etcd datastore is accessible on port "
                               f"{exposed.port} without client certificate authentication. "
                               "Full cluster state including Secrets is exposed.",
                               "Enable etcd client cert auth (--client-cert-auth=true). "
                               "Restrict port 2379 to the control plane only.")

    async def _check_apiserver_anon(
        self, client: httpx.AsyncClient, base: str, result: K8sScanResult
    ) -> None:
        """Probe API server for anonymous access to discovery + resource endpoints."""
        # K09 — anonymous auth detection via /api access without credentials
        status, body, _ = await self._get_raw(client, f"{base}/api")
        if status == 200 and body:
            self._add_vuln(
                result, "K8S-ADV-007", "K09", K8sVulnSeverity.CRITICAL,
                K8sComponent.API_SERVER,
                "Kubernetes API Server Anonymous Authentication Enabled",
                f"Unauthenticated GET {base}/api returned HTTP 200. "
                "Anonymous access is enabled on the API server.",
                "Set --anonymous-auth=false on the API server. "
                "Audit ClusterRoleBindings for system:anonymous and system:unauthenticated.",
            )

        # K03 — anonymous secret access
        status, body, _ = await self._get_raw(client, f"{base}/api/v1/secrets")
        if status == 200 and body and isinstance(body, dict) and body.get("kind") == "SecretList":
            count = len(body.get("items", []))
            self._add_vuln(
                result, "K8S-ADV-009", "K03", K8sVulnSeverity.CRITICAL,
                K8sComponent.API_SERVER,
                "Kubernetes Secrets Accessible Anonymously via API Server",
                f"Unauthenticated GET {base}/api/v1/secrets returned {count} Secret(s). "
                "Credentials, tokens, and TLS certificates may be exposed.",
                "Disable anonymous auth (--anonymous-auth=false). "
                "Enable Secret encryption at rest.",
            )

        # K02 — RBAC permissiveness check
        sar_path = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
        from ..utils.k8s_payloads import SELF_SUBJECT_ACCESS_REVIEW_PAYLOAD
        status, body, _ = await self._post_raw(client, f"{base}{sar_path}",
                                               SELF_SUBJECT_ACCESS_REVIEW_PAYLOAD)
        if status in (200, 201) and body and isinstance(body, dict):
            allowed = body.get("status", {}).get("allowed", False)
            if allowed:
                self._add_vuln(
                    result, "K8S-ADV-014", "K02", K8sVulnSeverity.HIGH,
                    K8sComponent.API_SERVER,
                    "Anonymous SelfSubjectAccessReview Reveals Over-Permissive RBAC",
                    "The anonymous user can list Secrets cluster-wide according to "
                    "SelfSubjectAccessReview. This indicates over-permissive "
                    "ClusterRoleBindings for system:unauthenticated.",
                    "Audit and remove non-trivial RBAC bindings for "
                    "system:anonymous and system:unauthenticated.",
                )

    async def _check_kubelet_anon(
        self, client: httpx.AsyncClient, base: str, result: K8sScanResult
    ) -> None:
        """Check kubelet for anonymous access and workload inspection."""
        # K09 + K06 — anonymous kubelet read-write
        port = int(base.split(":")[-1])
        if port == 10250:
            self._add_vuln(
                result, "K8S-ADV-002", "K06", K8sVulnSeverity.CRITICAL,
                K8sComponent.KUBELET,
                "Kubelet Read-Write Port (10250) Exposed Without Authentication",
                f"Unauthenticated access confirmed on kubelet port 10250 at {base}. "
                "Remote code execution via /exec and /run is possible.",
                "Set --anonymous-auth=false and --authorization-mode=Webhook on kubelet.",
            )
            self._add_vuln(
                result, "K8S-ADV-008", "K09", K8sVulnSeverity.CRITICAL,
                K8sComponent.KUBELET,
                "Kubelet Anonymous Authentication Enabled",
                f"Kubelet at {base} accepted unauthenticated requests (--anonymous-auth=true).",
                "Set --anonymous-auth=false and --authorization-mode=Webhook on kubelet.",
            )
        elif port == 10255:
            self._add_vuln(
                result, "K8S-ADV-003", "K06", K8sVulnSeverity.HIGH,
                K8sComponent.KUBELET,
                "Kubelet Read-Only Port (10255) Accessible Without Authentication",
                f"The deprecated kubelet read-only port 10255 at {base} is accessible. "
                "Pod specs, container names, and environment variables are exposed.",
                "Set --read-only-port=0 to disable the read-only port entirely.",
            )

        # K01 — inspect pod security context
        status, body, _ = await self._get_raw(client, f"{base}/pods")
        if status == 200 and body and isinstance(body, dict):
            items = body.get("items", [])
            self._inspect_pod_specs(result, items)

    # ------------------------------------------------------------------
    # Phase 4: Resource exposure + workload inspection
    # ------------------------------------------------------------------

    async def _phase_exposure(
        self, client: httpx.AsyncClient, result: K8sScanResult
    ) -> None:
        """Check for secrets exposure and additional resource disclosure."""
        for exposed in result.exposed_components:
            if not exposed.accessible:
                continue
            scheme = "https" if exposed.port in _TLS_PORTS else "http"
            base = f"{scheme}://{self._target}:{exposed.port}"

            if exposed.component == K8sComponent.CADVISOR and exposed.anonymous_access:
                self._add_vuln(
                    result, "K8S-ADV-016", "K06", K8sVulnSeverity.MEDIUM,
                    K8sComponent.CADVISOR,
                    "cAdvisor Metrics Port Exposed Without Authentication",
                    f"The cAdvisor endpoint at {base} is accessible without authentication. "
                    "Container resource usage, image names, and labels are exposed.",
                    "Disable standalone cAdvisor port (--cadvisor-port=0). "
                    "Use the authenticated kubelet /metrics/cadvisor endpoint instead.",
                )

            if exposed.component == K8sComponent.DASHBOARD and exposed.anonymous_access:
                self._add_vuln(
                    result, "K8S-ADV-005", "K06", K8sVulnSeverity.MEDIUM,
                    K8sComponent.DASHBOARD,
                    "Kubernetes Dashboard Exposed Without Authentication",
                    f"The Kubernetes Dashboard at {base} is accessible without authentication. "
                    "Cluster resources may be browsable and pods executable.",
                    "Do not expose the dashboard externally. "
                    "Enable dashboard authentication and use minimal RBAC bindings.",
                )

            if exposed.component in (K8sComponent.SCHEDULER,
                                     K8sComponent.CONTROLLER_MANAGER) and exposed.anonymous_access:
                self._add_vuln(
                    result, "K8S-ADV-006", "K07", K8sVulnSeverity.HIGH,
                    exposed.component,
                    "Kube Control Plane Component Metrics Port Exposed",
                    f"The {exposed.component.value} metrics endpoint at {base} is accessible "
                    "from the network, exposing internal cluster state and scheduling data.",
                    "Bind scheduler and controller-manager to localhost. "
                    "Restrict access to monitoring infrastructure only.",
                )

            # K03 — check for etcd secrets exposure
            if exposed.component == K8sComponent.ETCD and exposed.anonymous_access:
                status, body, _ = await self._get_raw(
                    client, f"{base}/v2/keys/?recursive=true"
                )
                if status == 200 and body and isinstance(body, dict):
                    self._add_vuln(
                        result, "K8S-ADV-010", "K03", K8sVulnSeverity.CRITICAL,
                        K8sComponent.ETCD,
                        "etcd Stores Secrets in Plaintext — Unauthenticated Key Dump Possible",
                        f"Unauthenticated etcd v2 key enumeration succeeded at {base}. "
                        "All Kubernetes Secrets are readable in base64 plaintext.",
                        "Enable etcd client cert auth. Enable Secret encryption at rest. "
                        "Restrict etcd port 2379 to the control plane only.",
                    )

    def _inspect_pod_specs(
        self, result: K8sScanResult, items: list[dict[str, Any]]
    ) -> None:
        """Scan pod spec list for K01 insecure workload configurations."""
        privileged_pods: list[str] = []
        root_pods: list[str] = []
        host_network_pods: list[str] = []

        for pod in items:
            meta = pod.get("metadata", {})
            name = meta.get("name", "<unknown>")
            ns = meta.get("namespace", "default")
            pod_label = f"{ns}/{name}"

            spec = pod.get("spec", {})
            if spec.get("hostNetwork") or spec.get("hostPID"):
                host_network_pods.append(pod_label)

            for ctr in spec.get("containers", []) + spec.get("initContainers", []):
                sc = ctr.get("securityContext", {})
                if sc.get("privileged"):
                    privileged_pods.append(f"{pod_label}/{ctr.get('name', 'ctr')}")
                ru = sc.get("runAsUser", -1)
                rr = sc.get("runAsNonRoot", None)
                if ru == 0 or rr is False:
                    root_pods.append(f"{pod_label}/{ctr.get('name', 'ctr')}")

        if privileged_pods:
            self._add_vuln(
                result, "K8S-ADV-011", "K01", K8sVulnSeverity.CRITICAL,
                K8sComponent.KUBELET,
                "Privileged Containers Running in Cluster",
                f"Privileged containers detected: {', '.join(privileged_pods[:5])}. "
                "These have full host kernel access and can escape the container.",
                "Remove privileged: true. Use specific Linux capabilities instead. "
                "Enforce via PodSecurity admission.",
            )
        if root_pods:
            self._add_vuln(
                result, "K8S-ADV-012", "K01", K8sVulnSeverity.HIGH,
                K8sComponent.KUBELET,
                "Containers Running as Root",
                f"Root-user containers detected: {', '.join(root_pods[:5])}. "
                "Root containers increase the blast radius of a container escape.",
                "Set runAsNonRoot: true and runAsUser: <non-zero> for all containers.",
            )
        if host_network_pods:
            self._add_vuln(
                result, "K8S-ADV-013", "K01", K8sVulnSeverity.HIGH,
                K8sComponent.KUBELET,
                "hostNetwork or hostPID Enabled in Pods",
                f"hostNetwork/hostPID pods: {', '.join(host_network_pods[:5])}. "
                "These pods share the node's network/PID namespace.",
                "Remove hostNetwork and hostPID. Enforce via PodSecurity policy.",
            )

    # ------------------------------------------------------------------
    # Phase 5: OWASP mapping + LLM triage
    # ------------------------------------------------------------------

    def _phase_owasp_map(self, result: K8sScanResult) -> None:
        """Deduplicate vulnerabilities and log coverage summary."""
        seen: set[str] = set()
        deduped: list[K8sVulnerability] = []
        for v in result.vulnerabilities:
            if v.vuln_id not in seen:
                seen.add(v.vuln_id)
                deduped.append(v)
        result.vulnerabilities = deduped
        logger.info(
            "K8s scan completed — %d vulnerabilities, OWASP coverage: %s",
            len(result.vulnerabilities),
            result.owasp_coverage,
        )

    async def _phase_llm_triage(self, result: K8sScanResult) -> None:
        """Use LLM judge to triage ambiguous findings and enrich remediation."""
        ambiguous_severities = {K8sVulnSeverity.MEDIUM, K8sVulnSeverity.LOW}
        for vuln in result.vulnerabilities:
            if vuln.severity not in ambiguous_severities:
                continue
            if not self._judge:
                continue
            try:
                verdict = self._judge.evaluate(
                    category=vuln.owasp_id,
                    probe=vuln.title,
                    response=vuln.evidence,
                )
                vuln.llm_confidence = float(verdict.get("confidence", 0.0))
                vuln.llm_reasoning = str(verdict.get("reason", ""))
                if verdict.get("vulnerable") and vuln.llm_confidence > 0.7:
                    if vuln.severity == K8sVulnSeverity.LOW:
                        vuln.severity = K8sVulnSeverity.MEDIUM
                        vuln.evidence += " [LLM: upgraded from LOW]"
            except Exception as exc:  # noqa: BLE001
                logger.debug("LLM triage error for %s: %s", vuln.vuln_id, exc)

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get_raw(
        self, client: httpx.AsyncClient, url: str
    ) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        """GET request; return (status_code, json_body | None, response_headers)."""
        try:
            resp = await client.get(url)
            body: dict[str, Any] | None = None
            try:
                raw = resp.content[:_MAX_RESPONSE_BYTES]
                body = json.loads(raw)
            except Exception:  # noqa: BLE001
                pass
            return resp.status_code, body, dict(resp.headers)
        except (httpx.RequestError, httpx.TimeoutException) as exc:
            logger.debug("GET %s error: %s", url, exc)
            return 0, None, {}

    async def _post_raw(
        self,
        client: httpx.AsyncClient,
        url: str,
        payload: dict[str, Any],
    ) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        """POST JSON request; return (status_code, json_body | None, response_headers)."""
        try:
            resp = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            body: dict[str, Any] | None = None
            try:
                raw = resp.content[:_MAX_RESPONSE_BYTES]
                body = json.loads(raw)
            except Exception:  # noqa: BLE001
                pass
            return resp.status_code, body, dict(resp.headers)
        except (httpx.RequestError, httpx.TimeoutException) as exc:
            logger.debug("POST %s error: %s", url, exc)
            return 0, None, {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _add_vuln(
        result: K8sScanResult,
        vuln_id: str,
        owasp_id: str,
        severity: K8sVulnSeverity,
        component: K8sComponent | None,
        title: str,
        description: str,
        remediation: str = "",
    ) -> None:
        # Avoid duplicates by vuln_id
        if any(v.vuln_id == vuln_id for v in result.vulnerabilities):
            return
        result.vulnerabilities.append(K8sVulnerability(
            vuln_id=vuln_id,
            owasp_id=owasp_id,
            severity=severity,
            title=title,
            description=description,
            component=component,
            evidence=description,
            remediation=remediation,
        ))


def _safe_str(d: dict[str, Any], key: str, default: str = "") -> str:
    val = d.get(key, default)
    return str(val) if val is not None else default
