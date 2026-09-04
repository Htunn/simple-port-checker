"""
Kubernetes security CVE and advisory database.

Sources:
- OWASP Kubernetes Top Ten 2025 (K01–K10)
- Published Kubernetes CVEs (NVD / GitHub Security Advisories)
- Common Kubernetes misconfiguration patterns from CIS Benchmarks
  and NSA/CISA Kubernetes Hardening Guidance

This database is used by K8sScanner to map findings to the OWASP K8s Top 10
and match discovered component versions against known CVEs.
All entries are for defensive/detection purposes only.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class K8sCVEEntry:
    vuln_id: str                                     # K8S-ADV-### or CVE ID
    cve_id: str | None
    owasp_id: str                                    # K01–K10
    severity: str                                    # critical / high / medium / low
    title: str
    description: str
    affected_versions: list[str] = field(default_factory=list)   # version prefixes, [] = all
    check_component: str = ""                        # component name hint
    remediation: str = ""
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Known CVEs, advisories, and misconfigurations
# ---------------------------------------------------------------------------
K8S_CVE_DB: list[K8sCVEEntry] = [
    # ---- K06: Overly Exposed Components -----
    K8sCVEEntry(
        vuln_id="K8S-ADV-001",
        cve_id=None,
        owasp_id="K06",
        severity="critical",
        title="Kubernetes API Server Exposed Without Authentication",
        description=(
            "The kube-apiserver is accessible without credentials. Anonymous "
            "authentication is enabled and the API returns cluster resources "
            "to unauthenticated clients. Full cluster compromise is possible."
        ),
        check_component="api_server",
        remediation=(
            "Disable anonymous authentication: set --anonymous-auth=false on the "
            "API server. Enable RBAC. Bind the API server listener to an internal "
            "IP or restrict access via firewall/security group."
        ),
        references=[
            "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests",
            "https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K06-Overly-Exposed-Kubernetes-Components.html",
        ],
    ),
    K8sCVEEntry(
        vuln_id="K8S-ADV-002",
        cve_id=None,
        owasp_id="K06",
        severity="critical",
        title="Kubelet Read-Write Port (10250) Exposed Without Authentication",
        description=(
            "The kubelet read-write API on port 10250 is accessible without "
            "authentication. This allows unauthenticated code execution via "
            "/exec, /run, and /logs, and full visibility into all workloads."
        ),
        check_component="kubelet",
        remediation=(
            "Set --anonymous-auth=false and --authorization-mode=Webhook on "
            "kubelet. Restrict port 10250 to the control plane via network "
            "policy or firewall. Enable client certificate authentication."
        ),
        references=[
            "https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/",
            "https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K06-Overly-Exposed-Kubernetes-Components.html",
        ],
    ),
    K8sCVEEntry(
        vuln_id="K8S-ADV-003",
        cve_id=None,
        owasp_id="K06",
        severity="high",
        title="Kubelet Read-Only Port (10255) Accessible Without Authentication",
        description=(
            "The deprecated kubelet read-only port 10255 is accessible without "
            "authentication. It exposes pod specs, container names, environment "
            "variables, and resource usage — sensitive information useful for "
            "reconnaissance and lateral movement planning."
        ),
        check_component="kubelet",
        remediation=(
            "Disable the read-only port entirely: set --read-only-port=0 on "
            "kubelet. This port is deprecated and provides no authentication."
        ),
        references=[
            "https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/",
        ],
    ),
    K8sCVEEntry(
        vuln_id="K8S-ADV-004",
        cve_id=None,
        owasp_id="K06",
        severity="critical",
        title="etcd Accessible Without Authentication",
        description=(
            "The etcd datastore is accessible without client certificate "
            "authentication. All Kubernetes cluster state — including Secrets, "
            "ServiceAccount tokens, and pod specs — is readable and writable."
        ),
        check_component="etcd",
        remediation=(
            "Enable etcd peer and client TLS authentication. Set "
            "--client-cert-auth=true and supply --trusted-ca-file, --cert-file, "
            "--key-file. Restrict port 2379 to the control plane only."
        ),
        references=[
            "https://etcd.io/docs/v3.5/op-guide/security/",
            "https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K06-Overly-Exposed-Kubernetes-Components.html",
        ],
    ),
    K8sCVEEntry(
        vuln_id="K8S-ADV-005",
        cve_id=None,
        owasp_id="K06",
        severity="medium",
        title="Kubernetes Dashboard Exposed Without Authentication",
        description=(
            "The Kubernetes Dashboard is accessible from the network without "
            "authentication. The dashboard may allow browsing cluster resources "
            "and executing commands in pods depending on its RBAC bindings."
        ),
        check_component="dashboard",
        remediation=(
            "Do not expose the dashboard externally. Use kubectl port-forward "
            "for local access. Enable dashboard authentication and bind to a "
            "RBAC role with minimal permissions."
        ),
        references=[
            "https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/",
        ],
    ),
    # ---- K07: Misconfigured / Vulnerable Components -----
    K8sCVEEntry(
        vuln_id="K8S-ADV-006",
        cve_id=None,
        owasp_id="K07",
        severity="high",
        title="Kube-Scheduler or Controller-Manager Metrics Port Exposed",
        description=(
            "The scheduler (10259) or controller-manager (10257) metrics endpoints "
            "are accessible from the network. These expose internal cluster state, "
            "scheduling decisions, and reconciliation data."
        ),
        check_component="scheduler",
        remediation=(
            "Bind scheduler and controller-manager to localhost. Restrict access "
            "to monitoring infrastructure only via network policy."
        ),
        references=[
            "https://kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/",
        ],
    ),
    K8sCVEEntry(
        vuln_id="CVE-2018-1002105",
        cve_id="CVE-2018-1002105",
        owasp_id="K07",
        severity="critical",
        title="Kubernetes API Server Privilege Escalation via API Aggregation",
        description=(
            "A privilege escalation vulnerability in the Kubernetes API server "
            "allows any user with access to the API aggregation layer to escalate "
            "to cluster-admin. Affected versions: < 1.10.11, < 1.11.5, < 1.12.3."
        ),
        affected_versions=["v1.0.", "v1.1.", "v1.2.", "v1.3.", "v1.4.", "v1.5.",
                           "v1.6.", "v1.7.", "v1.8.", "v1.9.", "v1.10.", "v1.11.",
                           "v1.12.0", "v1.12.1", "v1.12.2"],
        check_component="api_server",
        remediation=(
            "Upgrade to Kubernetes >= 1.10.11, >= 1.11.5, or >= 1.12.3 "
            "immediately. Disable the API aggregation layer if not in use."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2018-1002105",
            "https://github.com/kubernetes/kubernetes/issues/71411",
        ],
    ),
    K8sCVEEntry(
        vuln_id="CVE-2019-11253",
        cve_id="CVE-2019-11253",
        owasp_id="K07",
        severity="high",
        title="Kubernetes API Server DoS via Malformed YAML/JSON",
        description=(
            "The Kubernetes API server is vulnerable to a denial-of-service attack "
            "via malformed YAML or JSON in API requests. Affected versions: "
            "< 1.13.12, < 1.14.8, < 1.15.5, < 1.16.2."
        ),
        affected_versions=["v1.0.", "v1.1.", "v1.2.", "v1.3.", "v1.4.", "v1.5.",
                           "v1.6.", "v1.7.", "v1.8.", "v1.9.", "v1.10.", "v1.11.",
                           "v1.12.", "v1.13.0", "v1.13.1", "v1.13.2", "v1.13.3",
                           "v1.13.4", "v1.13.5", "v1.13.6", "v1.13.7", "v1.13.8",
                           "v1.13.9", "v1.13.10", "v1.13.11",
                           "v1.14.0", "v1.14.1", "v1.14.2", "v1.14.3", "v1.14.4",
                           "v1.14.5", "v1.14.6", "v1.14.7",
                           "v1.15.0", "v1.15.1", "v1.15.2", "v1.15.3", "v1.15.4",
                           "v1.16.0", "v1.16.1"],
        check_component="api_server",
        remediation="Upgrade to Kubernetes >= 1.13.12, >= 1.14.8, >= 1.15.5, or >= 1.16.2.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-11253"],
    ),
    K8sCVEEntry(
        vuln_id="CVE-2020-8558",
        cve_id="CVE-2020-8558",
        owasp_id="K07",
        severity="high",
        title="Kubernetes kube-proxy Nodeport Loopback Binding",
        description=(
            "kube-proxy incorrectly routes NodePort traffic to localhost services, "
            "allowing a pod to reach services bound to 127.0.0.1 on a node. "
            "Affected versions: < 1.18.4, < 1.17.7, < 1.16.11."
        ),
        affected_versions=["v1.0.", "v1.1.", "v1.2.", "v1.3.", "v1.4.", "v1.5.",
                           "v1.6.", "v1.7.", "v1.8.", "v1.9.", "v1.10.", "v1.11.",
                           "v1.12.", "v1.13.", "v1.14.", "v1.15.", "v1.16.0",
                           "v1.16.1", "v1.16.2", "v1.16.3", "v1.16.4", "v1.16.5",
                           "v1.16.6", "v1.16.7", "v1.16.8", "v1.16.9", "v1.16.10",
                           "v1.17.0", "v1.17.1", "v1.17.2", "v1.17.3", "v1.17.4",
                           "v1.17.5", "v1.17.6",
                           "v1.18.0", "v1.18.1", "v1.18.2", "v1.18.3"],
        check_component="kube_proxy",
        remediation="Upgrade to Kubernetes >= 1.18.4, >= 1.17.7, or >= 1.16.11.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-8558"],
    ),
    K8sCVEEntry(
        vuln_id="CVE-2021-25741",
        cve_id="CVE-2021-25741",
        owasp_id="K07",
        severity="high",
        title="Kubernetes Symlink Traversal in EmptyDir Volume",
        description=(
            "A symlink traversal vulnerability in how kubelet handles emptyDir "
            "volumes on Windows nodes allows privilege escalation. Affected versions "
            "< 1.22.2, < 1.21.5, < 1.20.11, < 1.19.15."
        ),
        affected_versions=["v1.19.", "v1.20.", "v1.21.", "v1.22.0", "v1.22.1"],
        check_component="kubelet",
        remediation="Upgrade to Kubernetes >= 1.22.2, >= 1.21.5, >= 1.20.11, or >= 1.19.15.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-25741"],
    ),
    K8sCVEEntry(
        vuln_id="CVE-2022-3294",
        cve_id="CVE-2022-3294",
        owasp_id="K07",
        severity="high",
        title="Kubernetes Node Address Bypass in API Server",
        description=(
            "When using a custom IP allowlist for node IPs in the API server, "
            "users can bypass the restriction using the apiserver-to-kubelet "
            "interface. Affected < 1.25.3, < 1.24.7, < 1.23.13, < 1.22.15."
        ),
        affected_versions=["v1.22.0", "v1.22.1", "v1.22.2", "v1.22.3", "v1.22.4",
                           "v1.22.5", "v1.22.6", "v1.22.7", "v1.22.8", "v1.22.9",
                           "v1.22.10", "v1.22.11", "v1.22.12", "v1.22.13", "v1.22.14",
                           "v1.23.", "v1.24.", "v1.25.0", "v1.25.1", "v1.25.2"],
        check_component="api_server",
        remediation="Upgrade to Kubernetes >= 1.25.3, >= 1.24.7, >= 1.23.13, or >= 1.22.15.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-3294"],
    ),
    # ---- K09: Broken Authentication -----
    K8sCVEEntry(
        vuln_id="K8S-ADV-007",
        cve_id=None,
        owasp_id="K09",
        severity="critical",
        title="Kubernetes API Server Anonymous Authentication Enabled",
        description=(
            "The API server accepts unauthenticated (anonymous) requests. "
            "By default, anonymous requests are bound to the 'system:anonymous' "
            "user and 'system:unauthenticated' group. If RBAC bindings are overly "
            "permissive for these groups, full cluster access may be possible."
        ),
        check_component="api_server",
        remediation=(
            "Set --anonymous-auth=false on the API server unless anonymous "
            "health checks are required. Audit ClusterRoleBindings for "
            "system:anonymous and system:unauthenticated."
        ),
        references=[
            "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests",
            "https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K09-Broken-Authentication-Mechanisms.html",
        ],
    ),
    K8sCVEEntry(
        vuln_id="K8S-ADV-008",
        cve_id=None,
        owasp_id="K09",
        severity="critical",
        title="Kubelet Anonymous Authentication Enabled",
        description=(
            "The kubelet is configured to accept unauthenticated requests "
            "(--anonymous-auth=true). Combined with --authorization-mode=AlwaysAllow, "
            "this allows any network-accessible client to execute commands in any "
            "pod on the node."
        ),
        check_component="kubelet",
        remediation=(
            "Set --anonymous-auth=false and --authorization-mode=Webhook on "
            "kubelet. Use kubeconfig to authenticate kubelet to the API server."
        ),
        references=[
            "https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/",
            "https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K09-Broken-Authentication-Mechanisms.html",
        ],
    ),
    # ---- K03: Secrets Management -----
    K8sCVEEntry(
        vuln_id="K8S-ADV-009",
        cve_id=None,
        owasp_id="K03",
        severity="critical",
        title="Kubernetes Secrets Accessible Anonymously via API Server",
        description=(
            "The /api/v1/secrets endpoint is accessible without authentication, "
            "exposing all Secrets in the cluster including database credentials, "
            "TLS certificates, ServiceAccount tokens, and API keys."
        ),
        check_component="api_server",
        remediation=(
            "Disable anonymous authentication (--anonymous-auth=false). Enable "
            "Secrets encryption at rest (--encryption-provider-config). Audit "
            "RBAC to restrict Secret access to least-privilege."
        ),
        references=[
            "https://kubernetes.io/docs/concepts/configuration/secret/",
            "https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K03-Secrets-Management-Failures.html",
        ],
    ),
    K8sCVEEntry(
        vuln_id="K8S-ADV-010",
        cve_id=None,
        owasp_id="K03",
        severity="high",
        title="etcd Stores Secrets in Plaintext Without Encryption",
        description=(
            "Kubernetes Secrets are stored in etcd as base64-encoded strings "
            "without at-rest encryption by default. An attacker with etcd "
            "access can trivially decode all Secrets."
        ),
        check_component="etcd",
        remediation=(
            "Enable Secret encryption at rest using EncryptionConfiguration "
            "with AES-GCM or KMS provider. Restrict etcd access to the "
            "control plane only."
        ),
        references=[
            "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/",
        ],
    ),
    # ---- K01: Insecure Workload Configurations -----
    K8sCVEEntry(
        vuln_id="K8S-ADV-011",
        cve_id=None,
        owasp_id="K01",
        severity="critical",
        title="Privileged Containers Running in Cluster",
        description=(
            "One or more running pods contain containers with "
            "securityContext.privileged=true. Privileged containers have full "
            "access to the host kernel and can trivially escape the container "
            "to compromise the node."
        ),
        check_component="kubelet",
        remediation=(
            "Remove privileged: true from container securityContexts. Use "
            "specific Linux capabilities (e.g. NET_ADMIN) instead of broad "
            "privilege. Enforce via PodSecurity admission or OPA/Gatekeeper."
        ),
        references=[
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
            "https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K01-Insecure-Workload-Configurations.html",
        ],
    ),
    K8sCVEEntry(
        vuln_id="K8S-ADV-012",
        cve_id=None,
        owasp_id="K01",
        severity="high",
        title="Containers Running as Root",
        description=(
            "Running pods contain containers that do not set a non-root UID "
            "(runAsNonRoot is absent or false, runAsUser is 0). Root containers "
            "increase the blast radius of a container breakout."
        ),
        check_component="kubelet",
        remediation=(
            "Set securityContext.runAsNonRoot: true and runAsUser: <non-zero> "
            "for all containers. Enforce via PodSecurity baseline or restricted "
            "policy."
        ),
        references=[
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        ],
    ),
    K8sCVEEntry(
        vuln_id="K8S-ADV-013",
        cve_id=None,
        owasp_id="K01",
        severity="high",
        title="hostNetwork or hostPID Enabled in Pods",
        description=(
            "One or more running pods have hostNetwork: true or hostPID: true. "
            "These settings allow the container to share the node's network "
            "namespace or PID namespace, enabling network sniffing and cross-"
            "container attacks."
        ),
        check_component="kubelet",
        remediation=(
            "Remove hostNetwork and hostPID from pod specs. Enforce via "
            "PodSecurity or OPA/Gatekeeper policy."
        ),
        references=[
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        ],
    ),
    # ---- K02: Overly Permissive RBAC -----
    K8sCVEEntry(
        vuln_id="K8S-ADV-014",
        cve_id=None,
        owasp_id="K02",
        severity="high",
        title="Anonymous SelfSubjectAccessReview Reveals Over-Permissive RBAC",
        description=(
            "Unauthenticated queries to SelfSubjectAccessReview reveal that the "
            "anonymous user (system:unauthenticated) has non-trivial cluster "
            "permissions. This indicates over-permissive RBAC ClusterRoleBindings."
        ),
        check_component="api_server",
        remediation=(
            "Audit ClusterRoleBindings for system:anonymous and "
            "system:unauthenticated. These groups should have no permissions "
            "beyond the discovery endpoints (/api, /apis, /healthz)."
        ),
        references=[
            "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
            "https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html",
        ],
    ),
    # ---- K08: Cluster-to-Cloud Lateral Movement -----
    K8sCVEEntry(
        vuln_id="K8S-ADV-015",
        cve_id=None,
        owasp_id="K08",
        severity="high",
        title="Cloud Instance Metadata Service (IMDS) Reachable from Cluster",
        description=(
            "The cloud instance metadata service (169.254.169.254) is reachable "
            "from within cluster workloads. Attackers who compromise a pod can "
            "retrieve cloud credentials, IAM roles, and instance metadata, "
            "enabling lateral movement to the underlying cloud account."
        ),
        check_component="api_server",
        remediation=(
            "Block access to 169.254.169.254 via NetworkPolicy or IMDSv2 "
            "requirement (AWS). Use Workload Identity / Pod Identity instead "
            "of instance profiles for pod-level cloud access."
        ),
        references=[
            "https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K08-Cluster-To-Cloud-Lateral-Movement.html",
        ],
    ),
    # ---- K06: cAdvisor -----
    K8sCVEEntry(
        vuln_id="K8S-ADV-016",
        cve_id=None,
        owasp_id="K06",
        severity="medium",
        title="cAdvisor Metrics Port Exposed Without Authentication",
        description=(
            "The cAdvisor metrics endpoint (port 4194) is accessible without "
            "authentication, exposing container resource usage, image names, "
            "environment variables, and container labels."
        ),
        check_component="cadvisor",
        remediation=(
            "Disable the standalone cAdvisor port (--cadvisor-port=0 on older "
            "kubelet versions). Use the kubelet /metrics/cadvisor endpoint with "
            "authentication instead. Restrict port 4194 via firewall."
        ),
        references=[
            "https://github.com/google/cadvisor",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------

def _version_prefix_matches(version: str, prefix: str) -> bool:
    """
    Check that *version* starts with *prefix* at a Semver component boundary.

    Examples::

        _version_prefix_matches("v1.3.5", "v1.3.")  -> True
        _version_prefix_matches("v1.30.0", "v1.3.") -> False   # not a boundary match
        _version_prefix_matches("v1.10.1", "v1.10.") -> True
    """
    if prefix.endswith("."):
        return version.startswith(prefix)
    # Require a dot or end-of-string immediately after the prefix
    return version == prefix or version.startswith(prefix + ".")


def match_cves(
    version: str,
    accessible_components: list[str],
) -> list[K8sCVEEntry]:
    """
    Return CVE/advisory entries relevant to this cluster.

    Args:
        version:               Kubernetes git_version string, e.g. "v1.27.3".
        accessible_components: List of accessible component names
                               (e.g. ["api_server", "kubelet", "etcd"]).
    """
    matched: list[K8sCVEEntry] = []
    for entry in K8S_CVE_DB:
        # Component match — empty check_component means universal
        if entry.check_component and entry.check_component not in accessible_components:
            continue
        # Version match — empty affected_versions means all versions
        if not entry.affected_versions:
            matched.append(entry)
            continue
        for prefix in entry.affected_versions:
            if _version_prefix_matches(version, prefix):
                matched.append(entry)
                break
    return matched
