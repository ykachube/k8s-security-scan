#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        Kubernetes Security Audit Scanner  –  Versatech Edition             ║
║  Based on: ReynardSec  K8s Security Guide, CIS Benchmark, NSA/CISA Guide     ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    pip install kubernetes
    python k8s_security_audit.py                          # current context
    python k8s_security_audit.py --context my-ctx         # specific context
    python k8s_security_audit.py --namespaces default ns2 # limit namespaces
    python k8s_security_audit.py --output report.json     # save JSON report
    python k8s_security_audit.py --json-only              # JSON to stdout
"""

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
except ImportError:
    print("ERROR: 'kubernetes' library not found.\n  pip install kubernetes")
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1,
    Severity.MEDIUM: 2,   Severity.LOW: 3, Severity.INFO: 4,
}

_C = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH:     "\033[31m",
    Severity.MEDIUM:   "\033[33m",
    Severity.LOW:      "\033[36m",
    Severity.INFO:     "\033[37m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"


@dataclass
class Finding:
    check_id:    str
    severity:    Severity
    category:    str
    title:       str
    resource:    str
    namespace:   Optional[str]
    detail:      str
    remediation: str
    reference:   str = ""

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class AuditReport:
    cluster_context: str
    findings: list = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def summary(self):
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self):
        return {
            "cluster_context": self.cluster_context,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in sorted(
                self.findings, key=lambda x: SEVERITY_ORDER[x.severity]
            )],
        }


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def safe_call(fn, *args, default=None, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ApiException as e:
        if e.status in (403, 404):
            return default
        raise


# Capabilities considered dangerous when explicitly added to a container
DANGEROUS_CAPS = {
    "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
    "NET_ADMIN",  "NET_RAW",    "SYS_CHROOT", "DAC_OVERRIDE",
    "DAC_READ_SEARCH", "SETUID", "SETGID", "FOWNER", "KILL",
}

SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}


# ──────────────────────────────────────────────────────────────────────────────
# Auditor
# ──────────────────────────────────────────────────────────────────────────────

class SecurityAuditor:

    def __init__(self, target_namespaces: Optional[list] = None):
        self.report = AuditReport(cluster_context="")
        self.target_namespaces = target_namespaces
        self.core  = client.CoreV1Api()
        self.apps  = client.AppsV1Api()
        self.rbac  = client.RbacAuthorizationV1Api()
        self.net   = client.NetworkingV1Api()
        self.batch = client.BatchV1Api()

    # ── Namespace helpers ─────────────────────────────────────────────────────

    def get_namespaces(self):
        ns_list = safe_call(self.core.list_namespace, default=None)
        if ns_list is None:
            return self.target_namespaces or ["default"]
        all_ns = [ns.metadata.name for ns in ns_list.items]
        if self.target_namespaces:
            return [n for n in all_ns if n in self.target_namespaces]
        return all_ns

    def _add(self, **kwargs):
        self.report.add(Finding(**kwargs))

    # ══════════════════════════════════════════════════════════════════════════
    # 1.  RBAC
    # ══════════════════════════════════════════════════════════════════════════

    def check_rbac_cluster_admin_bindings(self):
        """CRB-001 – Non-system principals bound to cluster-admin."""
        crbs = safe_call(self.rbac.list_cluster_role_binding, default=None)
        if not crbs:
            return
        for crb in crbs.items:
            if crb.role_ref.name != "cluster-admin":
                continue
            for subj in (crb.subjects or []):
                if subj.kind == "User" and subj.name.startswith("system:"):
                    continue
                if subj.kind == "Group" and subj.name.startswith("system:"):
                    continue
                self._add(
                    check_id="CRB-001", severity=Severity.HIGH,
                    category="RBAC",
                    title="Non-system subject bound to cluster-admin",
                    resource=f"ClusterRoleBinding/{crb.metadata.name}",
                    namespace=None,
                    detail=(f"Subject '{subj.name}' ({subj.kind}) has cluster-admin privileges. "
                            "Full control of the cluster."),
                    remediation="Use least-privilege roles. Reserve cluster-admin for break-glass accounts only.",
                    reference="Versatech § Users, Authentication and Authorization",
                )

    def check_rbac_wildcard_rules(self):
        """CRB-002 – Wildcard verbs or resources in ClusterRoles."""
        roles = safe_call(self.rbac.list_cluster_role, default=None)
        if not roles:
            return
        for role in roles.items:
            if role.metadata.name.startswith("system:"):
                continue
            for rule in (role.rules or []):
                if "*" in (rule.verbs or []) or "*" in (rule.resources or []):
                    self._add(
                        check_id="CRB-002", severity=Severity.MEDIUM,
                        category="RBAC",
                        title="ClusterRole with wildcard permissions",
                        resource=f"ClusterRole/{role.metadata.name}",
                        namespace=None,
                        detail=f"Wildcard rule — verbs={rule.verbs}, resources={rule.resources}",
                        remediation="Replace wildcards with explicit, minimal permissions.",
                        reference="Versatech § Authorization",
                    )

    def check_rbac_anonymous_access(self):
        """CRB-003 – Anonymous/unauthenticated users bound to any role."""
        crbs = safe_call(self.rbac.list_cluster_role_binding, default=None)
        if not crbs:
            return
        for crb in crbs.items:
            for subj in (crb.subjects or []):
                if subj.name in ("system:anonymous", "system:unauthenticated"):
                    self._add(
                        check_id="CRB-003", severity=Severity.CRITICAL,
                        category="RBAC",
                        title="Anonymous/unauthenticated access granted",
                        resource=f"ClusterRoleBinding/{crb.metadata.name}",
                        namespace=None,
                        detail=(f"'{subj.name}' bound to role '{crb.role_ref.name}'. "
                                "Anyone on the network can perform those operations without credentials."),
                        remediation="Delete this ClusterRoleBinding immediately.",
                        reference="Versatech § Anonymous Access",
                    )

    def check_rbac_default_sa_permissions(self, namespaces):
        """CRB-004 – 'default' service account granted explicit permissions."""
        for ns in namespaces:
            rbs = safe_call(self.rbac.list_namespaced_role_binding, ns, default=None)
            for rb in (rbs.items if rbs else []):
                for subj in (rb.subjects or []):
                    if subj.kind == "ServiceAccount" and subj.name == "default":
                        self._add(
                            check_id="CRB-004", severity=Severity.MEDIUM,
                            category="RBAC",
                            title="'default' service account has explicit role binding",
                            resource=f"RoleBinding/{rb.metadata.name}",
                            namespace=ns,
                            detail=(f"Default SA bound to '{rb.role_ref.name}'. "
                                    "All pods without an explicit SA inherit these permissions."),
                            remediation="Create dedicated per-workload ServiceAccounts.",
                            reference="Versatech § Secrets / automountServiceAccountToken",
                        )

    # ══════════════════════════════════════════════════════════════════════════
    # 2.  API Server flags (inspected via kube-system static pod)
    # ══════════════════════════════════════════════════════════════════════════

    def _get_static_pod_args(self, name_prefix):
        """Return (args_list, pod_name) for a static pod matching name_prefix."""
        pods = safe_call(self.core.list_namespaced_pod, "kube-system", default=None)
        if not pods:
            return [], None
        for pod in pods.items:
            if not pod.metadata.name.startswith(name_prefix):
                continue
            for c in (pod.spec.containers or []):
                return (list(c.args or []) + list(c.command or [])), pod.metadata.name
        return [], None

    def check_api_server_flags(self):
        """API-001…010 – Critical kube-apiserver security flags."""
        args, pod_name = self._get_static_pod_args("kube-apiserver")
        if not pod_name:
            return

        resource = f"StaticPod/{pod_name}"

        def flag_value(flag):
            for a in args:
                if a.startswith(flag + "="):
                    return a.split("=", 1)[1]
            return None

        def has_flag(flag):
            return any(flag in a for a in args)

        # Anonymous auth (default is true — must be explicitly false)
        if flag_value("--anonymous-auth") != "false":
            self._add(
                check_id="API-001", severity=Severity.CRITICAL,
                category="API Server",
                title="Anonymous authentication enabled (default)",
                resource=resource, namespace="kube-system",
                detail="--anonymous-auth defaults to true. Unauthenticated requests reach the API server.",
                remediation="Set --anonymous-auth=false in /etc/kubernetes/manifests/kube-apiserver.yaml.",
                reference="Versatech § Anonymous Access",
            )

        # Insecure HTTP port
        insecure = flag_value("--insecure-port")
        if insecure and insecure != "0":
            self._add(
                check_id="API-002", severity=Severity.CRITICAL,
                category="API Server",
                title="Insecure HTTP port open",
                resource=resource, namespace="kube-system",
                detail=f"--insecure-port={insecure} serves requests with no TLS or authentication.",
                remediation="Set --insecure-port=0.",
                reference="Versatech § Cluster Components Security",
            )

        # AlwaysAllow authorization
        authz = flag_value("--authorization-mode") or ""
        if "AlwaysAllow" in authz:
            self._add(
                check_id="API-003", severity=Severity.CRITICAL,
                category="API Server",
                title="AlwaysAllow authorization mode active",
                resource=resource, namespace="kube-system",
                detail="Every API request is granted — RBAC is completely bypassed.",
                remediation="Set --authorization-mode=Node,RBAC.",
                reference="Versatech § Authorization",
            )

        # ABAC still active
        if "ABAC" in authz:
            self._add(
                check_id="API-004", severity=Severity.MEDIUM,
                category="API Server",
                title="ABAC authorization is active",
                resource=resource, namespace="kube-system",
                detail="ABAC is harder to audit and maintain than RBAC.",
                remediation="Migrate all policies to RBAC and remove ABAC from --authorization-mode.",
                reference="Versatech § Other Authentication and Authorization Methods",
            )

        # Static token file
        if has_flag("--token-auth-file"):
            self._add(
                check_id="API-005", severity=Severity.HIGH,
                category="API Server",
                title="Static token file authentication enabled",
                resource=resource, namespace="kube-system",
                detail="--token-auth-file stores tokens in plaintext; tokens cannot be revoked without restart.",
                remediation="Remove --token-auth-file and use certificate-based or OIDC authentication.",
                reference="Versatech § Other Authentication and Authorization Methods",
            )

        # NodeRestriction admission plugin
        admission = flag_value("--enable-admission-plugins") or ""
        if "NodeRestriction" not in admission:
            self._add(
                check_id="API-006", severity=Severity.MEDIUM,
                category="API Server",
                title="NodeRestriction admission plugin not enabled",
                resource=resource, namespace="kube-system",
                detail="NodeRestriction prevents nodes from modifying resources outside their scope.",
                remediation="Add NodeRestriction to --enable-admission-plugins.",
                reference="CIS Kubernetes Benchmark 1.2.13",
            )

        # Audit logging
        if not has_flag("--audit-policy-file"):
            self._add(
                check_id="API-007", severity=Severity.HIGH,
                category="API Server",
                title="Audit logging not configured (disabled by default)",
                resource=resource, namespace="kube-system",
                detail=("Audit logging is off. Without it, malicious actions leave no trace "
                        "and incident response is severely hampered."),
                remediation=("Create an audit policy YAML and set --audit-policy-file, "
                             "--audit-log-path, --audit-log-maxage, --audit-log-maxbackup, --audit-log-maxsize."),
                reference="Versatech § Auditing (STRIDE R.01, R.02)",
            )

        # Encryption at rest
        if not has_flag("--encryption-provider-config"):
            self._add(
                check_id="API-008", severity=Severity.HIGH,
                category="API Server",
                title="Secrets not encrypted at rest in etcd",
                resource=resource, namespace="kube-system",
                detail=("Without --encryption-provider-config, Secrets are stored base64-encoded "
                        "(effectively plaintext) in etcd. Direct etcd access reveals all secrets."),
                remediation=("Create an EncryptionConfiguration with AES-GCM or KMS provider "
                             "and set --encryption-provider-config."),
                reference="Versatech § etcd Security (STRIDE I.06)",
            )

        # Profiling endpoint
        if flag_value("--profiling") != "false":
            self._add(
                check_id="API-009", severity=Severity.LOW,
                category="API Server",
                title="API server profiling endpoint enabled",
                resource=resource, namespace="kube-system",
                detail="Profiling exposes memory/CPU data useful to an attacker for reconnaissance.",
                remediation="Set --profiling=false.",
                reference="CIS Kubernetes Benchmark 1.2.21",
            )

        # Dedicated SA key
        if not has_flag("--service-account-key-file"):
            self._add(
                check_id="API-010", severity=Severity.MEDIUM,
                category="API Server",
                title="No dedicated service-account signing key",
                resource=resource, namespace="kube-system",
                detail="Without --service-account-key-file, the TLS private key signs SA tokens.",
                remediation="Generate a dedicated RSA key pair and set --service-account-key-file.",
                reference="CIS Kubernetes Benchmark 1.2.27",
            )

    # ══════════════════════════════════════════════════════════════════════════
    # 3.  kube-scheduler flags
    # ══════════════════════════════════════════════════════════════════════════

    def check_scheduler_flags(self):
        """SCH-001/002 – kube-scheduler hardening."""
        args, pod_name = self._get_static_pod_args("kube-scheduler")
        if not pod_name:
            return
        resource = f"StaticPod/{pod_name}"

        if not any("--profiling=false" in a for a in args):
            self._add(
                check_id="SCH-001", severity=Severity.LOW,
                category="Scheduler",
                title="kube-scheduler profiling enabled",
                resource=resource, namespace="kube-system",
                detail="Profiling data can be used to map cluster internals.",
                remediation="Add --profiling=false to kube-scheduler manifest.",
                reference="Versatech § Automated Tools / kube-bench 1.4.1",
            )

        if not any("--bind-address=127.0.0.1" in a for a in args):
            self._add(
                check_id="SCH-002", severity=Severity.MEDIUM,
                category="Scheduler",
                title="kube-scheduler bind address not restricted to localhost",
                resource=resource, namespace="kube-system",
                detail="Scheduler healthz/metrics may be reachable from other hosts on the node network.",
                remediation="Set --bind-address=127.0.0.1.",
                reference="CIS Kubernetes Benchmark 1.4.2",
            )

    # ══════════════════════════════════════════════════════════════════════════
    # 4.  kube-controller-manager flags
    # ══════════════════════════════════════════════════════════════════════════

    def check_controller_manager_flags(self):
        """CTL-001…003 – controller-manager hardening."""
        args, pod_name = self._get_static_pod_args("kube-controller-manager")
        if not pod_name:
            return
        resource = f"StaticPod/{pod_name}"

        if not any("--profiling=false" in a for a in args):
            self._add(
                check_id="CTL-001", severity=Severity.LOW,
                category="Controller Manager",
                title="kube-controller-manager profiling enabled",
                resource=resource, namespace="kube-system",
                detail="Profiling endpoint exposes internal state.",
                remediation="Set --profiling=false in the controller-manager manifest.",
                reference="CIS Kubernetes Benchmark 1.3.2",
            )

        if not any("--use-service-account-credentials=true" in a for a in args):
            self._add(
                check_id="CTL-002", severity=Severity.MEDIUM,
                category="Controller Manager",
                title="Controller manager not using per-controller SA credentials",
                resource=resource, namespace="kube-system",
                detail="Without --use-service-account-credentials=true, all controllers share one identity.",
                remediation="Set --use-service-account-credentials=true.",
                reference="CIS Kubernetes Benchmark 1.3.3",
            )

        if not any("--terminated-pod-gc-threshold" in a for a in args):
            self._add(
                check_id="CTL-003", severity=Severity.INFO,
                category="Controller Manager",
                title="No terminated pod GC threshold configured",
                resource=resource, namespace="kube-system",
                detail="Terminated pods accumulate and consume etcd storage indefinitely.",
                remediation="Set --terminated-pod-gc-threshold (e.g., 100).",
                reference="CIS Kubernetes Benchmark 1.3.1",
            )

    # ══════════════════════════════════════════════════════════════════════════
    # 5.  etcd flags
    # ══════════════════════════════════════════════════════════════════════════

    def check_etcd_flags(self):
        """ETCD-001…003 – etcd TLS and peer authentication."""
        args, pod_name = self._get_static_pod_args("etcd")
        if not pod_name:
            return
        resource = f"StaticPod/{pod_name}"

        def has(flag):
            return any(flag in a for a in args)

        if not has("--client-cert-auth=true"):
            self._add(
                check_id="ETCD-001", severity=Severity.CRITICAL,
                category="etcd",
                title="etcd client certificate authentication not enforced",
                resource=resource, namespace="kube-system",
                detail="Without --client-cert-auth=true, any client can connect to etcd and read all cluster data.",
                remediation="Set --client-cert-auth=true in the etcd static pod manifest.",
                reference="Versatech § etcd Security / CIS 2.1",
            )

        if not has("--peer-client-cert-auth=true"):
            self._add(
                check_id="ETCD-002", severity=Severity.HIGH,
                category="etcd",
                title="etcd peer certificate authentication not enforced",
                resource=resource, namespace="kube-system",
                detail="Peer communication between etcd cluster members is unauthenticated.",
                remediation="Set --peer-client-cert-auth=true.",
                reference="CIS Kubernetes Benchmark 2.5",
            )

        if has("--auto-tls=true"):
            self._add(
                check_id="ETCD-003", severity=Severity.HIGH,
                category="etcd",
                title="etcd using auto-generated self-signed TLS",
                resource=resource, namespace="kube-system",
                detail="--auto-tls=true uses self-signed certs with no CA validation.",
                remediation="Use CA-signed certificates and remove --auto-tls=true.",
                reference="CIS Kubernetes Benchmark 2.3",
            )

    # ══════════════════════════════════════════════════════════════════════════
    # 6.  Pod / Workload Security Context
    # ══════════════════════════════════════════════════════════════════════════

    def _check_pod_spec(self, namespace, kind, name, spec):
        containers = list(spec.containers or [])
        if spec.init_containers:
            containers += list(spec.init_containers)

        pod_sc = spec.security_context or client.V1PodSecurityContext()

        # PSC-001  Privileged mode ─────────────────────────────────────────────
        for c in containers:
            sc = c.security_context
            if sc and sc.privileged:
                self._add(
                    check_id="PSC-001", severity=Severity.CRITICAL,
                    category="Pod Security",
                    title="Privileged container",
                    resource=f"{kind}/{name}/{c.name}", namespace=namespace,
                    detail=("privileged=true gives root-level host access. "
                            "Full visibility of host devices including block storage (sda, etc.)."),
                    remediation="Remove privileged: true. Grant only specific Linux capabilities needed.",
                    reference="Versatech § Privileged and Unprivileged Modes",
                )

        # PSC-002  Running as root ─────────────────────────────────────────────
        for c in containers:
            sc          = c.security_context
            non_root_c  = getattr(sc,     "run_as_non_root", None) if sc else None
            uid_c       = getattr(sc,     "run_as_user",     None) if sc else None
            non_root_p  = getattr(pod_sc, "run_as_non_root", None)
            uid_p       = getattr(pod_sc, "run_as_user",     None)

            enforced = (
                non_root_c is True or
                (uid_c is not None and uid_c != 0) or
                (non_root_c is None and non_root_p is True) or
                (non_root_c is None and uid_p is not None and uid_p != 0)
            )
            if not enforced:
                self._add(
                    check_id="PSC-002", severity=Severity.HIGH,
                    category="Pod Security",
                    title="Container may run as root (UID 0)",
                    resource=f"{kind}/{name}/{c.name}", namespace=namespace,
                    detail="runAsNonRoot is not enforced and no non-zero UID is specified.",
                    remediation="Set securityContext.runAsNonRoot: true and runAsUser: <non-zero>.",
                    reference="Versatech § runAsUser, runAsGroup",
                )

        # PSC-003  Host namespace sharing ─────────────────────────────────────
        for attr, label in [
            ("host_pid",     "hostPID"),
            ("host_network", "hostNetwork"),
            ("host_ipc",     "hostIPC"),
        ]:
            if getattr(spec, attr, False):
                self._add(
                    check_id="PSC-003", severity=Severity.HIGH,
                    category="Pod Security",
                    title=f"{label} sharing enabled",
                    resource=f"{kind}/{name}", namespace=namespace,
                    detail=f"{label}=true allows the pod to interact with host-level namespaces.",
                    remediation=f"Set {label}: false unless absolutely required.",
                    reference="Versatech § Privileged and Unprivileged Modes",
                )

        # PSC-004  allowPrivilegeEscalation ───────────────────────────────────
        for c in containers:
            sc = c.security_context
            if not sc or sc.allow_privilege_escalation is not False:
                self._add(
                    check_id="PSC-004", severity=Severity.MEDIUM,
                    category="Pod Security",
                    title="allowPrivilegeEscalation not disabled",
                    resource=f"{kind}/{name}/{c.name}", namespace=namespace,
                    detail="Defaults to true — process can gain more privileges than its parent.",
                    remediation="Set securityContext.allowPrivilegeEscalation: false.",
                    reference="Versatech § allowPrivilegeEscalation",
                )

        # PSC-005  readOnlyRootFilesystem ─────────────────────────────────────
        for c in containers:
            sc = c.security_context
            if not sc or not sc.read_only_root_filesystem:
                self._add(
                    check_id="PSC-005", severity=Severity.LOW,
                    category="Pod Security",
                    title="Writable root filesystem",
                    resource=f"{kind}/{name}/{c.name}", namespace=namespace,
                    detail="Writable root FS allows attackers to drop web shells or tamper with binaries.",
                    remediation="Set securityContext.readOnlyRootFilesystem: true; use emptyDir for writes.",
                    reference="Versatech § readOnlyRootFilesystem",
                )

        # PSC-006  Resource limits ─────────────────────────────────────────────
        for c in containers:
            res     = c.resources
            missing = []
            if not res or not res.limits:
                missing = ["cpu", "memory"]
            else:
                if not res.limits.get("cpu"):
                    missing.append("cpu")
                if not res.limits.get("memory"):
                    missing.append("memory")
            if missing:
                self._add(
                    check_id="PSC-006", severity=Severity.MEDIUM,
                    category="Pod Security",
                    title="Missing resource limits",
                    resource=f"{kind}/{name}/{c.name}", namespace=namespace,
                    detail=f"No limits for: {', '.join(missing)}. Risk of resource exhaustion (DoS).",
                    remediation="Set resources.limits.cpu and resources.limits.memory.",
                    reference="Versatech § Resource Quotas (STRIDE D.01)",
                )

        # PSC-007  Image tag ───────────────────────────────────────────────────
        for c in containers:
            image = c.image or ""
            if "@sha256:" in image:
                continue  # pinned by digest — safe
            tag = image.split(":")[-1] if ":" in image else "latest"
            if tag in ("latest", ""):
                self._add(
                    check_id="PSC-007", severity=Severity.LOW,
                    category="Pod Security",
                    title="Image uses ':latest' or has no tag",
                    resource=f"{kind}/{name}/{c.name}", namespace=namespace,
                    detail=f"Image '{image}' — unpinned images lead to unpredictable deployments.",
                    remediation="Pin to a specific version tag or SHA digest.",
                    reference="Versatech § Specifying a Specific Image Version",
                )

        # PSC-008  automountServiceAccountToken ───────────────────────────────
        if spec.automount_service_account_token is not False:
            self._add(
                check_id="PSC-008", severity=Severity.LOW,
                category="Pod Security",
                title="Service account token auto-mounted",
                resource=f"{kind}/{name}", namespace=namespace,
                detail="automountServiceAccountToken defaults to true — unnecessary for most workloads.",
                remediation="Set automountServiceAccountToken: false if API access is not needed.",
                reference="Versatech § Secrets / automountServiceAccountToken",
            )

        # PSC-009  Dangerous Linux capabilities ───────────────────────────────
        for c in containers:
            sc = c.security_context
            if sc and sc.capabilities and sc.capabilities.add:
                dangerous = [cap for cap in sc.capabilities.add if cap in DANGEROUS_CAPS]
                if dangerous:
                    self._add(
                        check_id="PSC-009", severity=Severity.HIGH,
                        category="Pod Security",
                        title="Dangerous Linux capability added",
                        resource=f"{kind}/{name}/{c.name}", namespace=namespace,
                        detail=f"Container adds: {', '.join(dangerous)}",
                        remediation="Drop ALL capabilities, then add only the minimal required set.",
                        reference="Versatech § Linux Capabilities",
                    )

        # PSC-010  seccompProfile ──────────────────────────────────────────────
        pod_seccomp = getattr(pod_sc, "seccomp_profile", None)
        seccomp_found = bool(pod_seccomp)
        if not seccomp_found:
            for c in containers:
                sc = c.security_context
                if sc and getattr(sc, "seccomp_profile", None):
                    seccomp_found = True
                    break
        if not seccomp_found:
            self._add(
                check_id="PSC-010", severity=Severity.LOW,
                category="Pod Security",
                title="No seccomp profile defined",
                resource=f"{kind}/{name}", namespace=namespace,
                detail="Without seccomp, all syscalls are allowed, widening the kernel attack surface.",
                remediation="Set securityContext.seccompProfile.type: RuntimeDefault (or Localhost).",
                reference="Versatech § Other Capabilities",
            )

    def check_workload_security(self, namespaces):
        for ns in namespaces:
            for kind, lister in [
                ("Deployment",  lambda n: safe_call(self.apps.list_namespaced_deployment, n, default=None)),
                ("DaemonSet",   lambda n: safe_call(self.apps.list_namespaced_daemon_set, n, default=None)),
                ("StatefulSet", lambda n: safe_call(self.apps.list_namespaced_stateful_set, n, default=None)),
                ("Job",         lambda n: safe_call(self.batch.list_namespaced_job, n, default=None)),
            ]:
                result = lister(ns)
                for obj in (result.items if result else []):
                    self._check_pod_spec(ns, kind, obj.metadata.name,
                                         obj.spec.template.spec)

            # Standalone pods (no owner)
            pods = safe_call(self.core.list_namespaced_pod, ns, default=None)
            for p in (pods.items if pods else []):
                if not (p.metadata.owner_references or []):
                    self._check_pod_spec(ns, "Pod", p.metadata.name, p.spec)

    # ══════════════════════════════════════════════════════════════════════════
    # 7.  Network Policies
    # ══════════════════════════════════════════════════════════════════════════

    def check_network_policies(self, namespaces):
        """NET-001/002 – Missing policies and allow-all rules."""
        for ns in namespaces:
            if ns in SYSTEM_NAMESPACES:
                continue
            nps = safe_call(self.net.list_namespaced_network_policy, ns, default=None)
            if nps is None or len(nps.items) == 0:
                self._add(
                    check_id="NET-001", severity=Severity.HIGH,
                    category="Network",
                    title="No NetworkPolicy in namespace",
                    resource=f"Namespace/{ns}", namespace=ns,
                    detail=("All pod-to-pod and cross-namespace traffic is unrestricted. "
                            "A compromised pod can reach any service in the cluster."),
                    remediation=("Add a default-deny NetworkPolicy, then explicitly allow "
                                 "only required ingress/egress traffic."),
                    reference="Versatech § Network Policies (STRIDE E.02)",
                )
            else:
                for np in nps.items:
                    for ingress_rule in (np.spec.ingress or []):
                        if not ingress_rule.from_:
                            self._add(
                                check_id="NET-002", severity=Severity.MEDIUM,
                                category="Network",
                                title="NetworkPolicy allows ingress from ALL sources",
                                resource=f"NetworkPolicy/{np.metadata.name}",
                                namespace=ns,
                                detail="An ingress rule with no 'from' selector allows traffic from everywhere.",
                                remediation="Restrict ingress to specific podSelector/namespaceSelector/IPBlock.",
                                reference="Versatech § Network Policies",
                            )

    # ══════════════════════════════════════════════════════════════════════════
    # 8.  Secrets & service accounts
    # ══════════════════════════════════════════════════════════════════════════

    def check_secrets_in_env_vars(self, namespaces):
        """SEC-001 – Secrets exposed as plain environment variables."""
        for ns in namespaces:
            for kind, lister in [
                ("Deployment",  lambda n: safe_call(self.apps.list_namespaced_deployment, n, default=None)),
                ("StatefulSet", lambda n: safe_call(self.apps.list_namespaced_stateful_set, n, default=None)),
            ]:
                result = lister(ns)
                for obj in (result.items if result else []):
                    for c in (obj.spec.template.spec.containers or []):
                        for env in (c.env or []):
                            if env.value_from and env.value_from.secret_key_ref:
                                self._add(
                                    check_id="SEC-001", severity=Severity.MEDIUM,
                                    category="Secrets",
                                    title="Secret injected as environment variable",
                                    resource=f"{kind}/{obj.metadata.name}/{c.name}",
                                    namespace=ns,
                                    detail=(f"Env var '{env.name}' references secret "
                                            f"'{env.value_from.secret_key_ref.name}'. "
                                            "Env vars are visible in /proc and crash dumps."),
                                    remediation="Mount secrets as files via volumes instead of env vars.",
                                    reference="Versatech § Secrets",
                                )

    def check_default_service_accounts(self, namespaces):
        """SEC-002 – Workloads using the default service account."""
        for ns in namespaces:
            deps = safe_call(self.apps.list_namespaced_deployment, ns, default=None)
            for d in (deps.items if deps else []):
                sa = d.spec.template.spec.service_account_name
                if sa in (None, "", "default"):
                    self._add(
                        check_id="SEC-002", severity=Severity.LOW,
                        category="Secrets",
                        title="Workload uses the default service account",
                        resource=f"Deployment/{d.metadata.name}", namespace=ns,
                        detail="Sharing 'default' SA makes least-privilege RBAC impossible.",
                        remediation="Create a dedicated ServiceAccount per workload.",
                        reference="Versatech § Secrets",
                    )

    # ══════════════════════════════════════════════════════════════════════════
    # 9.  Namespace hygiene
    # ══════════════════════════════════════════════════════════════════════════

    def check_workloads_in_default_namespace(self):
        """NS-001 – Workloads deployed in the 'default' namespace."""
        for kind, lister in [
            ("Deployment",  lambda: safe_call(self.apps.list_namespaced_deployment,  "default", default=None)),
            ("StatefulSet", lambda: safe_call(self.apps.list_namespaced_stateful_set, "default", default=None)),
            ("DaemonSet",   lambda: safe_call(self.apps.list_namespaced_daemon_set,   "default", default=None)),
        ]:
            result = lister()
            for obj in (result.items if result else []):
                self._add(
                    check_id="NS-001", severity=Severity.LOW,
                    category="Namespace",
                    title=f"{kind} deployed in 'default' namespace",
                    resource=f"{kind}/{obj.metadata.name}", namespace="default",
                    detail="'default' namespace complicates RBAC scoping and NetworkPolicy management.",
                    remediation="Move workloads to dedicated, purpose-named namespaces.",
                    reference="Versatech § Namespaces",
                )

    def check_pod_security_standards(self, namespaces):
        """NS-002 – Namespaces missing Pod Security Standards labels."""
        ns_list = safe_call(self.core.list_namespace, default=None)
        if not ns_list:
            return
        for ns in ns_list.items:
            name = ns.metadata.name
            if name in SYSTEM_NAMESPACES:
                continue
            if self.target_namespaces and name not in self.target_namespaces:
                continue
            labels  = ns.metadata.labels or {}
            pss_set = any("pod-security.kubernetes.io" in k for k in labels)
            if not pss_set:
                self._add(
                    check_id="NS-002", severity=Severity.MEDIUM,
                    category="Namespace",
                    title="No Pod Security Standards label on namespace",
                    resource=f"Namespace/{name}", namespace=name,
                    detail=("Without PSS labels, no baseline or restricted security policy is enforced. "
                            "Privileged pods can be launched freely."),
                    remediation=("Add label pod-security.kubernetes.io/enforce: restricted "
                                 "(or at least baseline)."),
                    reference="Versatech § Pod Security Standards",
                )

    def check_resource_quotas(self, namespaces):
        """NS-003 – Namespaces without a ResourceQuota."""
        for ns in namespaces:
            if ns in SYSTEM_NAMESPACES:
                continue
            quotas = safe_call(self.core.list_namespaced_resource_quota, ns, default=None)
            if not quotas or len(quotas.items) == 0:
                self._add(
                    check_id="NS-003", severity=Severity.LOW,
                    category="Namespace",
                    title="No ResourceQuota in namespace",
                    resource=f"Namespace/{ns}", namespace=ns,
                    detail="A single misbehaving workload can exhaust cluster CPU/memory/storage (DoS).",
                    remediation="Create a ResourceQuota with CPU, memory, and pod count limits.",
                    reference="Versatech § Resource Quotas (STRIDE D.01)",
                )

    # ══════════════════════════════════════════════════════════════════════════
    # 10. Node health
    # ══════════════════════════════════════════════════════════════════════════

    def check_node_health(self):
        """NODE-001 – Nodes not in Ready state (may skip security controls)."""
        nodes = safe_call(self.core.list_node, default=None)
        if not nodes:
            return
        for node in nodes.items:
            conditions = {c.type: c.status for c in (node.status.conditions or [])}
            if conditions.get("Ready") != "True":
                self._add(
                    check_id="NODE-001", severity=Severity.INFO,
                    category="Node",
                    title="Node not in Ready state",
                    resource=f"Node/{node.metadata.name}", namespace=None,
                    detail=f"Conditions: {conditions}. An unhealthy node may skip security controls.",
                    remediation="Investigate node health before applying hardening.",
                    reference="kubectl get nodes -o wide",
                )

    # ══════════════════════════════════════════════════════════════════════════
    # 11. Certificates / CSR hygiene
    # ══════════════════════════════════════════════════════════════════════════

    def check_issued_certificates(self):
        """CERT-001 – Approved CSRs issued to non-system users."""
        try:
            certs_api = client.CertificatesV1Api()
            csrs = safe_call(certs_api.list_certificate_signing_request, default=None)
        except Exception:
            return
        if not csrs:
            return
        for csr in csrs.items:
            conditions = {c.type for c in (csr.status.conditions or [])}
            if "Approved" not in conditions:
                continue
            username = csr.spec.username or ""
            if username.startswith("system:"):
                continue
            self._add(
                check_id="CERT-001", severity=Severity.INFO,
                category="Certificates",
                title="Non-system approved CSR found",
                resource=f"CertificateSigningRequest/{csr.metadata.name}", namespace=None,
                detail=f"Issued to: '{username}'. Verify this certificate is still required.",
                remediation="Revoke certificates no longer needed. Audit with: kubectl get csr",
                reference="Versatech § Verification of Granted Access",
            )

    # ══════════════════════════════════════════════════════════════════════════
    # Run all checks
    # ══════════════════════════════════════════════════════════════════════════

    def run(self, context_name: str) -> AuditReport:
        self.report.cluster_context = context_name
        namespaces = self.get_namespaces()

        print(f"\n{BOLD}╔══════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}║   K8s Security Audit  –  Versatech Edition  ║{RESET}")
        print(f"{BOLD}╚══════════════════════════════════════════════╝{RESET}")
        print(f"  Context    : {BOLD}{context_name}{RESET}")
        print(f"  Namespaces : {', '.join(namespaces)}\n")

        checks = [
            # (category label, check label, function)
            ("RBAC",           "Cluster-admin bindings",           self.check_rbac_cluster_admin_bindings),
            ("RBAC",           "Wildcard permissions",              self.check_rbac_wildcard_rules),
            ("RBAC",           "Anonymous access grants",           self.check_rbac_anonymous_access),
            ("RBAC",           "Default SA role bindings",          lambda: self.check_rbac_default_sa_permissions(namespaces)),
            ("API Server",     "Security flags",                    self.check_api_server_flags),
            ("Scheduler",      "Security flags",                    self.check_scheduler_flags),
            ("Ctrl Manager",   "Security flags",                    self.check_controller_manager_flags),
            ("etcd",           "TLS & auth flags",                  self.check_etcd_flags),
            ("Pod Security",   "Workload security contexts",        lambda: self.check_workload_security(namespaces)),
            ("Network",        "NetworkPolicy coverage",            lambda: self.check_network_policies(namespaces)),
            ("Secrets",        "Secrets in env vars",               lambda: self.check_secrets_in_env_vars(namespaces)),
            ("Secrets",        "Default service accounts",          lambda: self.check_default_service_accounts(namespaces)),
            ("Namespace",      "Workloads in default namespace",    self.check_workloads_in_default_namespace),
            ("Namespace",      "Pod Security Standards labels",     lambda: self.check_pod_security_standards(namespaces)),
            ("Namespace",      "ResourceQuota coverage",            lambda: self.check_resource_quotas(namespaces)),
            ("Node",           "Node health",                       self.check_node_health),
            ("Certificates",   "Issued CSR hygiene",                self.check_issued_certificates),
        ]

        cat_w = max(len(c[0]) for c in checks) + 3
        for category, label, fn in checks:
            cat_str = f"{DIM}[{category}]{RESET}"
            print(f"  {cat_str:<{cat_w + 10}} {label} ...", end=" ", flush=True)
            before = len(self.report.findings)
            try:
                fn()
            except Exception as exc:
                print(f"{DIM}skipped ({exc}){RESET}")
                continue
            delta = len(self.report.findings) - before
            if delta:
                worst = sorted(
                    [f.severity for f in self.report.findings[before:]],
                    key=lambda s: SEVERITY_ORDER[s]
                )[0]
                print(f"{_C[worst]}{delta} findings{RESET}")
            else:
                print(f"\033[32m✓ ok{RESET}")

        return self.report


# ──────────────────────────────────────────────────────────────────────────────
# Pretty-print report
# ──────────────────────────────────────────────────────────────────────────────

def print_report(report: AuditReport):
    summary = report.summary()
    total   = sum(summary.values())
    n_checks = len({f.check_id for f in report.findings})

    print(f"\n{'═'*72}")
    print(f"{BOLD}  SUMMARY  ·  {report.cluster_context}{RESET}")
    print(f"{'═'*72}")
    for sev in Severity:
        count = summary[sev.value]
        color = _C[sev]
        bar   = "█" * min(count, 46)
        print(f"  {color}{sev.value:<10}{RESET}  {count:>4}  {color}{bar}{RESET}")
    print(f"\n  {BOLD}{total} findings{RESET} across {n_checks} check IDs\n")

    for sev in Severity:
        findings = [f for f in report.findings if f.severity == sev]
        if not findings:
            continue
        color = _C[sev]
        print(f"\n{color}{BOLD}{'─'*72}{RESET}")
        print(f"{color}{BOLD}  {sev.value}  ({len(findings)}){RESET}")
        print(f"{color}{BOLD}{'─'*72}{RESET}")
        for f in findings:
            ns_part  = f"  ns={f.namespace}" if f.namespace else ""
            ref_part = f"  {DIM}[{f.reference}]{RESET}" if f.reference else ""
            print(f"\n  {BOLD}[{f.check_id}]{RESET}  {BOLD}{f.title}{RESET}{ns_part}")
            print(f"  {DIM}Resource   :{RESET} {f.resource}")
            print(f"  {DIM}Detail     :{RESET} {f.detail}")
            print(f"  {DIM}Fix        :{RESET} {color}{f.remediation}{RESET}{ref_part}")


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Kubernetes Security Audit Scanner — Versatech Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--context",    help="kubeconfig context to use")
    parser.add_argument("--namespaces", nargs="*", metavar="NS",
                        help="Limit scan to specific namespaces")
    parser.add_argument("--output",     metavar="FILE",
                        help="Save full JSON report to this file")
    parser.add_argument("--json-only",  action="store_true",
                        help="Print JSON to stdout instead of coloured output")
    args = parser.parse_args()

    try:
        if args.context:
            config.load_kube_config(context=args.context)
            context_name = args.context
        else:
            config.load_kube_config()
            _, active = config.list_kube_config_contexts()
            context_name = active["name"] if active else "unknown"
    except config.ConfigException:
        try:
            config.load_incluster_config()
            context_name = "in-cluster"
        except config.ConfigException:
            print("ERROR: No kubeconfig found and not running in-cluster.")
            sys.exit(1)

    auditor = SecurityAuditor(target_namespaces=args.namespaces)
    report  = auditor.run(context_name)

    if args.json_only:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_report(report)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report.to_dict(), fh, indent=2)
        print(f"\n  📄  JSON report saved → {args.output}\n")

    # CI/CD-friendly exit codes
    summary = report.summary()
    if summary[Severity.CRITICAL.value]:
        sys.exit(3)
    if summary[Severity.HIGH.value]:
        sys.exit(2)
    if summary[Severity.MEDIUM.value]:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()