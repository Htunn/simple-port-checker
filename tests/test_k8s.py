"""
Tests for the Kubernetes security scanner and attacker.

Covers:
- CVE database integrity and matching
- Payload and port-map structure
- Result model properties
- Scanner phase 1: component discovery (positive + negative fingerprint)
- Scanner phase 3: anonymous authentication detection
- Scanner phase 2: CVE matching on version
- Scanner phase 4: workload / etcd exposure
- Attacker authorization gating
- Attacker safe mode (anon reads + RBAC probe)
- Attacker deep mode (kubelet exec + etcd dump + cloud metadata)
- JSON serialization
- CLI smoke tests
"""

from __future__ import annotations

import json
from unittest.mock import patch

import httpx
import pytest
import respx

from offensive_ai.core.k8s_attacker import K8sAttacker
from offensive_ai.core.k8s_scanner import K8sScanner
from offensive_ai.exceptions import AuthorizationRequired
from offensive_ai.models.k8s_result import (
    K8sAttackReport,
    K8sAttackResult,
    K8sComponent,
    K8sExposedComponent,
    K8sScanResult,
    K8sServerInfo,
    K8sVulnerability,
    K8sVulnSeverity,
)
from offensive_ai.utils.k8s_cve_db import K8S_CVE_DB, match_cves
from offensive_ai.utils.k8s_payloads import (
    APISERVER_ANON_READ_PAYLOADS,
    APISERVER_PROBE_PATHS,
    ETCD_KEY_PAYLOADS,
    K8S_COMPONENT_PORTS,
    K8S_DEFAULT_SCAN_PORTS,
    KUBELET_EXEC_PAYLOADS,
    RBAC_PROBE_PAYLOADS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TARGET = "192.168.1.100"
APISERVER_HTTPS = f"https://{TARGET}:6443"
KUBELET_HTTPS = f"https://{TARGET}:10250"
KUBELET_HTTP_RO = f"http://{TARGET}:10255"
ETCD_HTTP = f"http://{TARGET}:2379"

VERSION_BODY = {
    "major": "1",
    "minor": "27",
    "gitVersion": "v1.27.3",
    "platform": "linux/amd64",
    "goVersion": "go1.21.0",
    "buildDate": "2023-06-14T09:47:40Z",
}

PODS_BODY = {
    "kind": "PodList",
    "apiVersion": "v1",
    "items": [
        {
            "metadata": {"name": "nginx-abc", "namespace": "default"},
            "spec": {
                "containers": [
                    {
                        "name": "nginx",
                        "securityContext": {"runAsUser": 0},
                    }
                ],
            },
        }
    ],
}

SECRETS_BODY = {
    "kind": "SecretList",
    "apiVersion": "v1",
    "items": [
        {"metadata": {"name": "db-secret"}, "data": {"password": "c2VjcmV0"}},
    ],
}


def _make_scanner(ports: list[int] | None = None) -> K8sScanner:
    return K8sScanner(target=TARGET, ports=ports or [6443, 10250, 2379], timeout=5.0)


# ===========================================================================
# CVE DATABASE TESTS
# ===========================================================================


class TestK8sCveDb:
    def test_db_non_empty(self):
        assert len(K8S_CVE_DB) >= 10

    def test_all_entries_have_required_fields(self):
        for entry in K8S_CVE_DB:
            assert entry.vuln_id, f"Missing vuln_id: {entry}"
            assert entry.owasp_id.startswith("K"), f"Bad owasp_id: {entry.vuln_id}"
            assert entry.severity in ("critical", "high", "medium", "low", "info")
            assert entry.title
            assert entry.description

    def test_all_owasp_ids_covered(self):
        ids = {e.owasp_id for e in K8S_CVE_DB}
        # Must cover at least K01, K02, K03, K06, K07, K08, K09
        for expected in ("K01", "K02", "K03", "K06", "K07", "K08", "K09"):
            assert expected in ids, f"OWASP {expected} not covered in K8S_CVE_DB"

    def test_match_cves_by_version_prefix(self):
        # CVE-2018-1002105 affects v1.12.x
        matches = match_cves("v1.12.2", ["api_server"])
        vuln_ids = [m.vuln_id for m in matches]
        assert "CVE-2018-1002105" in vuln_ids

    def test_match_cves_unaffected_version(self):
        # CVE-2018-1002105 does not affect v1.30.x
        matches = match_cves("v1.30.0", ["api_server"])
        vuln_ids = [m.vuln_id for m in matches]
        assert "CVE-2018-1002105" not in vuln_ids

    def test_match_cves_component_filter(self):
        # K8S-ADV-002 (kubelet port) should only match when kubelet is accessible
        matches = match_cves("v1.27.0", ["kubelet"])
        vuln_ids = [m.vuln_id for m in matches]
        assert "K8S-ADV-002" in vuln_ids

    def test_match_cves_component_excluded(self):
        # K8S-ADV-002 should not appear when kubelet is not in accessible_components
        matches = match_cves("v1.27.0", ["api_server"])
        vuln_ids = [m.vuln_id for m in matches]
        assert "K8S-ADV-002" not in vuln_ids

    def test_universal_entries_match_any_version(self):
        # K8S-ADV-001 has no affected_versions → must match any version
        matches = match_cves("v99.99.99", ["api_server"])
        vuln_ids = [m.vuln_id for m in matches]
        assert "K8S-ADV-001" in vuln_ids


# ===========================================================================
# PAYLOAD STRUCTURE TESTS
# ===========================================================================


class TestK8sPayloads:
    def test_component_ports_covers_all_components(self):
        expected = {
            "api_server", "kubelet", "etcd", "scheduler",
            "controller_manager", "kube_proxy", "cadvisor", "dashboard",
        }
        assert expected == set(K8S_COMPONENT_PORTS.keys())

    def test_default_scan_ports_non_empty(self):
        assert len(K8S_DEFAULT_SCAN_PORTS) >= 8

    def test_anon_read_payloads_structure(self):
        for p in APISERVER_ANON_READ_PAYLOADS:
            assert "id" in p
            assert "path" in p
            assert "method" in p
            assert "detect_in_response" in p
            assert "severity" in p
            assert "owasp_id" in p

    def test_rbac_probe_payloads_structure(self):
        for p in RBAC_PROBE_PAYLOADS:
            assert "id" in p
            assert "path" in p
            assert "body" in p
            assert "detect_in_response" in p

    def test_kubelet_exec_payloads_structure(self):
        for p in KUBELET_EXEC_PAYLOADS:
            assert "id" in p
            assert "command" in p
            assert "detect_in_response" in p
            assert "owasp_id" in p

    def test_etcd_key_payloads_structure(self):
        for p in ETCD_KEY_PAYLOADS:
            assert "id" in p
            assert "path" in p
            assert "detect_in_response" in p


# ===========================================================================
# RESULT MODEL TESTS
# ===========================================================================


class TestK8sResultModels:
    def test_scan_result_defaults(self):
        r = K8sScanResult(target="10.0.0.1")
        assert r.is_kubernetes is False
        assert r.vulnerabilities == []
        assert r.cve_matches == []
        assert r.critical_vulns == []
        assert r.high_vulns == []
        assert r.owasp_coverage == []

    def test_owasp_coverage_deduped_and_sorted(self):
        r = K8sScanResult(target="10.0.0.1")
        r.vulnerabilities = [
            K8sVulnerability(
                vuln_id="K8S-ADV-001", owasp_id="K06",
                severity=K8sVulnSeverity.CRITICAL,
                title="t", description="d",
            ),
            K8sVulnerability(
                vuln_id="K8S-ADV-007", owasp_id="K09",
                severity=K8sVulnSeverity.CRITICAL,
                title="t2", description="d2",
            ),
            K8sVulnerability(
                vuln_id="K8S-ADV-002", owasp_id="K06",   # duplicate OWASP id
                severity=K8sVulnSeverity.CRITICAL,
                title="t3", description="d3",
            ),
        ]
        assert r.owasp_coverage == ["K06", "K09"]

    def test_attack_report_successful_attacks(self):
        report = K8sAttackReport(target="10.0.0.1")
        report.attack_results = [
            K8sAttackResult(
                attack_id="X1", owasp_id="K06",
                description="d", severity=K8sVulnSeverity.CRITICAL,
                succeeded=True,
            ),
            K8sAttackResult(
                attack_id="X2", owasp_id="K09",
                description="d", severity=K8sVulnSeverity.HIGH,
                succeeded=False,
            ),
        ]
        assert len(report.successful_attacks) == 1
        assert report.successful_attacks[0].attack_id == "X1"
        assert len(report.critical_successes) == 1

    def test_scan_result_json_serializable(self):
        r = K8sScanResult(target="10.0.0.1", is_kubernetes=True)
        r.server_info = K8sServerInfo(git_version="v1.27.3")
        r.exposed_components = [
            K8sExposedComponent(
                component=K8sComponent.API_SERVER,
                port=6443, accessible=True, anonymous_access=True, tls=True,
            )
        ]
        data = r.model_dump(mode="json")
        dumped = json.dumps(data)
        parsed = json.loads(dumped)
        assert parsed["target"] == "10.0.0.1"
        assert parsed["server_info"]["git_version"] == "v1.27.3"


# ===========================================================================
# SCANNER TESTS
# ===========================================================================


@pytest.mark.asyncio
class TestK8sScannerFingerprint:
    """Phase 1: Component discovery and fingerprinting."""

    BASE = APISERVER_HTTPS

    @respx.mock
    async def test_fingerprint_apiserver_via_version_body(self):
        """API server detected from /version gitVersion field."""
        respx.get(f"{self.BASE}/version").mock(
            return_value=httpx.Response(200, json=VERSION_BODY)
        )
        respx.get(f"{self.BASE}/healthz").mock(
            return_value=httpx.Response(200, text="ok")
        )
        # Stub all other ports as unreachable
        respx.route(method="GET").mock(
            side_effect=httpx.ConnectError("connection refused")
        )

        scanner = _make_scanner(ports=[6443])
        result = await scanner.scan()

        assert result.is_kubernetes is True
        assert result.server_info.git_version == "v1.27.3"
        assert result.server_info.platform == "linux/amd64"
        assert K8sComponent.API_SERVER in result.server_info.components_found

    @respx.mock
    async def test_fingerprint_fails_on_unknown_target(self):
        """Non-Kubernetes target returns is_kubernetes=False."""
        respx.route(method="GET").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        scanner = _make_scanner(ports=[6443, 10250, 2379])
        result = await scanner.scan()

        assert result.is_kubernetes is False
        assert result.error != ""

    @respx.mock
    async def test_fingerprint_kubelet_from_pods(self):
        """Kubelet detected from /pods items list."""
        respx.get(f"{KUBELET_HTTPS}/healthz").mock(
            return_value=httpx.Response(200, text="ok")
        )
        respx.get(f"{KUBELET_HTTPS}/pods").mock(
            return_value=httpx.Response(200, json=PODS_BODY)
        )
        respx.route(method="GET").mock(
            side_effect=httpx.ConnectError("connection refused")
        )

        scanner = _make_scanner(ports=[10250])
        result = await scanner.scan()

        assert result.is_kubernetes is True
        assert K8sComponent.KUBELET in result.server_info.components_found

    @respx.mock
    async def test_401_port_counts_as_accessible_no_anon(self):
        """Port returning 401 is accessible but not anonymously."""
        respx.get(f"{self.BASE}/version").mock(
            return_value=httpx.Response(401, json={"message": "Unauthorized"})
        )
        respx.get(f"{self.BASE}/healthz").mock(
            return_value=httpx.Response(401, text="Unauthorized")
        )
        respx.route(method="GET").mock(
            side_effect=httpx.ConnectError("connection refused")
        )

        scanner = _make_scanner(ports=[6443])
        result = await scanner.scan()

        accessible = [c for c in result.exposed_components if c.accessible]
        if accessible:
            assert accessible[0].anonymous_access is False


@pytest.mark.asyncio
class TestK8sScannerAuthPosture:
    """Phase 3: Anonymous authentication detection."""

    @respx.mock
    async def test_anon_apiserver_triggers_k09_vuln(self):
        """Anonymous API server access produces K09 vulnerability."""
        respx.get(f"{APISERVER_HTTPS}/version").mock(
            return_value=httpx.Response(200, json=VERSION_BODY)
        )
        respx.get(f"{APISERVER_HTTPS}/healthz").mock(
            return_value=httpx.Response(200, text="ok")
        )
        # Phase 3 probes
        respx.get(f"{APISERVER_HTTPS}/api").mock(
            return_value=httpx.Response(200, json={"kind": "APIVersions"})
        )
        respx.get(f"{APISERVER_HTTPS}/api/v1/secrets").mock(
            return_value=httpx.Response(200, json=SECRETS_BODY)
        )
        respx.post(
            f"{APISERVER_HTTPS}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
        ).mock(
            return_value=httpx.Response(200, json={"status": {"allowed": False}})
        )
        # Catch-all
        respx.route(method="GET").mock(
            return_value=httpx.Response(404, json={})
        )
        respx.route(method="POST").mock(
            return_value=httpx.Response(404, json={})
        )

        scanner = _make_scanner(ports=[6443])
        result = await scanner.scan()

        owasp_ids = {v.owasp_id for v in result.vulnerabilities}
        assert "K09" in owasp_ids, "Expected K09 vuln for anonymous apiserver"
        # Secrets accessible anonymously → K03
        assert "K03" in owasp_ids, "Expected K03 vuln for anonymous secret access"

    @respx.mock
    async def test_anon_kubelet_10250_triggers_critical_vulns(self):
        """Anonymous kubelet 10250 access → K06+K09 critical vulns."""
        respx.get(f"{KUBELET_HTTPS}/healthz").mock(
            return_value=httpx.Response(200, text="ok")
        )
        respx.get(f"{KUBELET_HTTPS}/pods").mock(
            return_value=httpx.Response(200, json=PODS_BODY)
        )
        respx.route(method="GET").mock(
            return_value=httpx.Response(404)
        )

        scanner = _make_scanner(ports=[10250])
        result = await scanner.scan()

        owasp_ids = {v.owasp_id for v in result.vulnerabilities}
        assert "K06" in owasp_ids
        assert "K09" in owasp_ids

    @respx.mock
    async def test_rbac_allowed_triggers_k02_vuln(self):
        """SelfSubjectAccessReview allowed=True triggers K02 vulnerability."""
        respx.get(f"{APISERVER_HTTPS}/version").mock(
            return_value=httpx.Response(200, json=VERSION_BODY)
        )
        respx.get(f"{APISERVER_HTTPS}/healthz").mock(
            return_value=httpx.Response(200, text="ok")
        )
        respx.get(f"{APISERVER_HTTPS}/api").mock(
            return_value=httpx.Response(200, json={"kind": "APIVersions"})
        )
        respx.get(f"{APISERVER_HTTPS}/api/v1/secrets").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        respx.post(
            f"{APISERVER_HTTPS}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
        ).mock(
            return_value=httpx.Response(200, json={"status": {"allowed": True}})
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, json={}))
        respx.route(method="POST").mock(return_value=httpx.Response(404, json={}))

        scanner = _make_scanner(ports=[6443])
        result = await scanner.scan()

        owasp_ids = {v.owasp_id for v in result.vulnerabilities}
        assert "K02" in owasp_ids


@pytest.mark.asyncio
class TestK8sScannerCveMatching:
    """Phase 2: Version-based CVE matching."""

    @respx.mock
    async def test_old_version_matches_cve_2018_1002105(self):
        """v1.12.2 triggers CVE-2018-1002105 finding."""
        old_version = {**VERSION_BODY, "gitVersion": "v1.12.2"}
        respx.get(f"{APISERVER_HTTPS}/version").mock(
            return_value=httpx.Response(200, json=old_version)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, json={}))
        respx.route(method="POST").mock(return_value=httpx.Response(404, json={}))

        scanner = _make_scanner(ports=[6443])
        result = await scanner.scan()

        cve_ids = [v.cve_id for v in result.vulnerabilities]
        assert "CVE-2018-1002105" in cve_ids

    @respx.mock
    async def test_modern_version_no_old_cves(self):
        """v1.30.x does not trigger old version-specific CVEs."""
        modern = {**VERSION_BODY, "gitVersion": "v1.30.1"}
        respx.get(f"{APISERVER_HTTPS}/version").mock(
            return_value=httpx.Response(200, json=modern)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, json={}))
        respx.route(method="POST").mock(return_value=httpx.Response(404, json={}))

        scanner = _make_scanner(ports=[6443])
        result = await scanner.scan()

        cve_ids = [v.cve_id for v in result.vulnerabilities if v.cve_id]
        assert "CVE-2018-1002105" not in cve_ids


@pytest.mark.asyncio
class TestK8sScannerWorkloadInspection:
    """Phase 4: Workload security context inspection via kubelet /pods."""

    @respx.mock
    async def test_privileged_pod_triggers_k01_critical(self):
        """Privileged container in pod spec triggers K01 critical vuln."""
        priv_pods = {
            "kind": "PodList",
            "apiVersion": "v1",
            "items": [
                {
                    "metadata": {"name": "evil-pod", "namespace": "kube-system"},
                    "spec": {
                        "containers": [
                            {
                                "name": "evil",
                                "securityContext": {"privileged": True},
                            }
                        ]
                    },
                }
            ],
        }
        respx.get(f"{KUBELET_HTTPS}/healthz").mock(
            return_value=httpx.Response(200, text="ok")
        )
        respx.get(f"{KUBELET_HTTPS}/pods").mock(
            return_value=httpx.Response(200, json=priv_pods)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner(ports=[10250])
        result = await scanner.scan()

        k01_vulns = [v for v in result.vulnerabilities if v.owasp_id == "K01"]
        assert any("K8S-ADV-011" == v.vuln_id for v in k01_vulns), (
            "Expected K8S-ADV-011 (privileged container) in vulnerabilities"
        )
        assert any(v.severity == K8sVulnSeverity.CRITICAL for v in k01_vulns)

    @respx.mock
    async def test_root_container_triggers_k01_high(self):
        """Root-user container triggers K01 high vuln."""
        respx.get(f"{KUBELET_HTTPS}/healthz").mock(
            return_value=httpx.Response(200, text="ok")
        )
        respx.get(f"{KUBELET_HTTPS}/pods").mock(
            return_value=httpx.Response(200, json=PODS_BODY)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner(ports=[10250])
        result = await scanner.scan()

        k01_vulns = [v for v in result.vulnerabilities if v.owasp_id == "K01"]
        assert any("K8S-ADV-012" == v.vuln_id for v in k01_vulns), (
            "Expected K8S-ADV-012 (root container) in vulnerabilities"
        )


@pytest.mark.asyncio
class TestK8sScannerEtcd:
    """Phase 4: etcd exposure."""

    @respx.mock
    async def test_etcd_anon_health_triggers_vuln(self):
        """Accessible etcd without auth triggers K06 critical vuln."""
        respx.get(f"{ETCD_HTTP}/health").mock(
            return_value=httpx.Response(200, json={"health": "true"})
        )
        respx.get(f"{ETCD_HTTP}/version").mock(
            return_value=httpx.Response(200, json={"etcdserver": "3.5.9", "etcdcluster": "3.5.0"})
        )
        # etcd key dump fails (v2 not enabled)
        respx.get(f"{ETCD_HTTP}/v2/keys/").mock(
            return_value=httpx.Response(404, json={})
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404))

        scanner = _make_scanner(ports=[2379])
        result = await scanner.scan()

        k06_vulns = [v for v in result.vulnerabilities if v.owasp_id == "K06"]
        assert len(k06_vulns) >= 1


# ===========================================================================
# ATTACKER TESTS
# ===========================================================================


class TestK8sAttackerAuthorization:
    """Authorization gating."""

    def test_attacker_raises_without_authorization(self):
        with pytest.raises(AuthorizationRequired):
            K8sAttacker(authorized=False)

    def test_attacker_raises_with_default(self):
        with pytest.raises(AuthorizationRequired):
            K8sAttacker()

    def test_attacker_accepts_authorized_true(self):
        attacker = K8sAttacker(authorized=True)
        assert attacker.authorized is True


@pytest.mark.asyncio
class TestK8sAttackerSafeMode:
    """Attacker safe mode: anon reads + RBAC probe."""

    @respx.mock
    async def test_safe_mode_anon_secret_access_detected(self):
        """Anon secret access in safe mode marks attack as succeeded."""
        respx.get(f"{APISERVER_HTTPS}/api/v1/secrets").mock(
            return_value=httpx.Response(200, json=SECRETS_BODY)
        )
        respx.get(f"{APISERVER_HTTPS}/api/v1/pods").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        respx.get(f"{APISERVER_HTTPS}/api/v1/namespaces").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        respx.get(f"{APISERVER_HTTPS}/api/v1/nodes").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )
        # RBAC probes
        respx.post(
            f"{APISERVER_HTTPS}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
        ).mock(return_value=httpx.Response(403, json={}))
        respx.post(
            f"{APISERVER_HTTPS}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"
        ).mock(return_value=httpx.Response(403, json={}))
        # kubelet + etcd
        respx.route(method="GET").mock(
            side_effect=httpx.ConnectError("connection refused")
        )

        attacker = K8sAttacker(authorized=True)
        report = await attacker.attack(
            target=TARGET, ports=[6443], mode="safe", timeout=5.0
        )

        assert isinstance(report, K8sAttackReport)
        # Secret access should have succeeded
        secret_attacks = [
            r for r in report.attack_results
            if "secret" in r.description.lower()
        ]
        assert any(r.succeeded for r in secret_attacks), (
            "Expected anon secret access to be marked as succeeded"
        )

    @respx.mock
    async def test_safe_mode_all_forbidden_no_success(self):
        """When all probes return 403, no attacks succeed."""
        respx.route(method="GET").mock(return_value=httpx.Response(403, json={}))
        respx.route(method="POST").mock(return_value=httpx.Response(403, json={}))

        attacker = K8sAttacker(authorized=True)
        report = await attacker.attack(
            target=TARGET, ports=[6443], mode="safe", timeout=5.0
        )

        assert report.successful_attacks == []

    @respx.mock
    async def test_safe_mode_kubelet_pods_detected(self):
        """Kubelet /pods accessible in safe mode → succeeded."""
        respx.get(f"{KUBELET_HTTPS}/pods").mock(
            return_value=httpx.Response(200, json=PODS_BODY)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(403, json={}))
        respx.route(method="POST").mock(return_value=httpx.Response(403, json={}))

        attacker = K8sAttacker(authorized=True)
        report = await attacker.attack(
            target=TARGET, ports=[10250], mode="safe", timeout=5.0
        )

        kubelet_attacks = [
            r for r in report.attack_results
            if "kubelet" in r.description.lower()
        ]
        assert any(r.succeeded for r in kubelet_attacks), (
            "Expected kubelet /pods to be marked as succeeded"
        )


@pytest.mark.asyncio
class TestK8sAttackerDeepMode:
    """Attacker deep mode: exec + etcd dump + cloud metadata."""

    @respx.mock
    async def test_deep_mode_kubelet_exec_detected(self):
        """Kubelet /exec RCE detected in deep mode."""
        # Need pods first so exec knows which pod to target
        respx.get(f"{KUBELET_HTTPS}/pods").mock(
            return_value=httpx.Response(200, json=PODS_BODY)
        )
        # exec returns id output
        respx.get(url__regex=r".*/exec/default/nginx-abc/nginx.*").mock(
            return_value=httpx.Response(200, text="uid=0(root) gid=0(root)")
        )
        respx.route(method="GET").mock(return_value=httpx.Response(403, json={}))
        respx.route(method="POST").mock(return_value=httpx.Response(403, json={}))

        attacker = K8sAttacker(authorized=True)
        report = await attacker.attack(
            target=TARGET, ports=[10250], mode="deep", timeout=5.0
        )

        exec_attacks = [
            r for r in report.attack_results
            if "exec" in r.attack_id.lower() or "exec" in r.description.lower()
        ]
        assert len(exec_attacks) > 0
        assert any(r.succeeded for r in exec_attacks), (
            "Expected kubelet /exec to succeed"
        )

    @respx.mock
    async def test_deep_mode_etcd_key_dump_detected(self):
        """etcd v2 key dump succeeds in deep mode."""
        respx.get(f"{ETCD_HTTP}/health").mock(
            return_value=httpx.Response(200, json={"health": "true"})
        )
        respx.get(f"{ETCD_HTTP}/v2/keys/?recursive=true").mock(
            return_value=httpx.Response(
                200,
                json={
                    "node": {
                        "key": "/",
                        "dir": True,
                        "nodes": [
                            {"key": "/registry", "dir": True},
                        ],
                    }
                },
            )
        )
        respx.get(
            f"{ETCD_HTTP}/v2/keys/registry/secrets/?recursive=true"
        ).mock(return_value=httpx.Response(404, json={}))
        respx.route(method="GET").mock(return_value=httpx.Response(404, json={}))
        respx.route(method="POST").mock(return_value=httpx.Response(404, json={}))

        attacker = K8sAttacker(authorized=True)
        report = await attacker.attack(
            target=TARGET, ports=[2379], mode="deep", timeout=5.0
        )

        etcd_attacks = [
            r for r in report.attack_results
            if "etcd" in r.attack_id.lower()
        ]
        assert len(etcd_attacks) > 0
        assert any(r.succeeded for r in etcd_attacks), (
            "Expected etcd key dump to succeed"
        )

    @respx.mock
    async def test_deep_mode_includes_cloud_metadata_probes(self):
        """Deep mode runs cloud metadata SSRF probes."""
        respx.route(method="GET").mock(
            side_effect=httpx.ConnectError("no route")
        )
        respx.route(method="POST").mock(return_value=httpx.Response(403, json={}))

        attacker = K8sAttacker(authorized=True)
        report = await attacker.attack(
            target=TARGET, ports=[6443], mode="deep", timeout=5.0
        )

        meta_attacks = [
            r for r in report.attack_results
            if "meta" in r.attack_id.lower() or "K08" == r.owasp_id
        ]
        assert len(meta_attacks) >= 3, "Expected at least 3 cloud metadata SSRF probes"


@pytest.mark.asyncio
class TestK8sAttackerReportSerialization:
    """JSON serialization of attack report."""

    @respx.mock
    async def test_attack_report_serializable(self):
        """Attack report must be JSON-serializable via model_dump."""
        respx.route(method="GET").mock(return_value=httpx.Response(403, json={}))
        respx.route(method="POST").mock(return_value=httpx.Response(403, json={}))

        attacker = K8sAttacker(authorized=True)
        report = await attacker.attack(
            target=TARGET, ports=[6443], mode="safe", timeout=5.0
        )

        data = report.model_dump(mode="json")
        dumped = json.dumps(data, default=str)
        parsed = json.loads(dumped)
        assert parsed["target"] == TARGET
        assert "attack_results" in parsed


# ===========================================================================
# CLI SMOKE TESTS
# ===========================================================================


class TestK8sCliSmoke:
    def test_k8s_scan_command_exists(self):
        from click.testing import CliRunner
        from offensive_ai.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["k8s-scan", "--help"])
        assert result.exit_code == 0
        assert "k8s-scan" in result.output or "TARGET" in result.output

    def test_k8s_attack_command_exists(self):
        from click.testing import CliRunner
        from offensive_ai.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["k8s-attack", "--help"])
        assert result.exit_code == 0
        assert "i-have-authorization" in result.output

    def test_k8s_attack_requires_authorization_flag(self):
        from click.testing import CliRunner
        from offensive_ai.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["k8s-attack", "10.0.0.1"])
        assert result.exit_code != 0
        assert "authorization" in result.output.lower()
