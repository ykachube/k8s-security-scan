# 🔐 Kubernetes Security Audit Scanner
### Versatech Edition

A single-file, dependency-light Python scanner that audits a Kubernetes cluster against the [ReynardSec Kubernetes Security Guide](https://reynardsec.com/en/kubernetes-security-guide/), the CIS Kubernetes Benchmark, and NSA/CISA hardening guidance.

No Helm chart, no operator, no side-car — just **one script and one `pip install`**.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Check Reference](#check-reference)
- [Exit Codes](#exit-codes)
- [Output Examples](#output-examples)
- [CI/CD Integration](#cicd-integration)
- [Limitations](#limitations)
- [References](#references)

---

## Features

- ✅ **17 check categories**, 30+ individual check IDs
- 🔴 Five severity levels: `CRITICAL` → `HIGH` → `MEDIUM` → `LOW` → `INFO`
- 🎨 Colour-coded terminal output with per-finding remediation guidance
- 📄 Optional JSON report export for SIEM/ticketing ingestion
- 🔒 Read-only — uses the Kubernetes API only, never mutates anything
- 🐳 Works with any cluster (kubeadm, k3s, managed AKS/EKS/GKE) and in-cluster
- 🚦 CI/CD-friendly exit codes based on worst severity found

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.9+ | Uses dataclasses and `list` type hints |
| `kubernetes` pip package | Official Python client |
| `kubectl` access | Needs a valid `~/.kube/config` or in-cluster SA |
| RBAC permissions | See [Required Permissions](#required-permissions) below |

---

## Installation

```bash
# 1. Install the only dependency
pip install kubernetes

# 2. Download the scanner
curl -O https://raw.githubusercontent.com/ykachube/k8s-security-scan/k8s_security_audit.py
# or clone this repo
git clone https://github.com/ykachube/k8s-security-scan

# 3. Make it executable (optional)
chmod +x k8s_security_audit.py
```

---

## Usage

```bash
# Scan the currently active kubeconfig context
python k8s_security_audit.py

# Scan a specific context
python k8s_security_audit.py --context staging-cluster

# Limit scan to specific namespaces
python k8s_security_audit.py --namespaces default app-ns monitoring

# Exclude namespaces entirely (no findings generated for them at all)
python k8s_security_audit.py --skip-namespaces monitoring logging

# Save a full JSON report alongside the terminal output
python k8s_security_audit.py --output report.json

# Print JSON only (no colours) — useful for piping
python k8s_security_audit.py --json-only | jq '.findings[] | select(.severity == "CRITICAL")'

# Hide the infrastructure components section from terminal output
python k8s_security_audit.py --hide-infra

# Combine options
python k8s_security_audit.py --context prod --namespaces backend --output prod-audit.json
```

### CLI Flags Reference

| Flag | Description |
|---|---|
| `--context` | kubeconfig context to use |
| `--namespaces NS [NS ...]` | Scan only these namespaces |
| `--skip-namespaces NS [NS ...]` | Exclude these namespaces entirely — no findings generated |
| `--output FILE` | Save full JSON report (includes infra findings) |
| `--json-only` | Print JSON to stdout, no coloured terminal output |
| `--hide-infra` | Suppress the grey infrastructure section from terminal output |

---

### Infrastructure Workload Handling

Many system-level workloads **legitimately require** elevated privileges that the scanner would otherwise flag as CRITICAL or HIGH — Calico needs `privileged: true` to manage eBPF/iptables, kube-proxy needs `hostNetwork`, CSI drivers need `SYS_ADMIN`, etc.

Rather than suppressing these or producing false CRITICAL alerts that bury real findings, the scanner handles them like this:

- Findings for known infrastructure workloads are **tagged `is_infra: true`**
- They are shown in a **separate grey section** at the bottom of the terminal output, clearly labelled *"System / Infrastructure Components"*
- Their **original severity is preserved** in the JSON report under `infra_findings`
- **Exit codes and the main summary count only real (non-infra) findings**

Namespaces always treated as infrastructure: `kube-system`, `kube-public`, `kube-node-lease`, `cert-manager`

Known infrastructure workload names (partial match):

```
calico-node, calico-typha, calico-kube-controllers
cilium, cilium-operator, kube-flannel-ds, weave-net
kube-proxy, coredns
csi-cinder-nodeplugin, csi-cinder-controllerplugin, ebs-csi-*, gce-pd-csi-driver
openstack-cloud-controller-manager, aws-cloud-controller-manager, azure-cloud-controller-manager
metrics-server, cert-manager, cert-manager-cainjector, cert-manager-webhook
ingress-nginx-controller, local-path-provisioner, nfs-subdir-external-provisioner
```

To add your own, edit the `INFRA_WORKLOAD_NAMES` set near the top of the script.

---

### Required Permissions

The scanner only reads cluster state. A minimal ClusterRole looks like this:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-auditor
rules:
  - apiGroups: [""]
    resources: ["pods", "namespaces", "nodes", "secrets",
                "serviceaccounts", "resourcequotas"]
    verbs: ["get", "list"]
  - apiGroups: ["apps"]
    resources: ["deployments", "daemonsets", "statefulsets"]
    verbs: ["get", "list"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["get", "list"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles", "clusterrolebindings",
                "roles", "rolebindings"]
    verbs: ["get", "list"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list"]
  - apiGroups: ["certificates.k8s.io"]
    resources: ["certificatesigningrequests"]
    verbs: ["get", "list"]
```

---

## Check Reference

### 🔑 RBAC

| ID | Severity | Title | STRIDE / Source |
|---|---|---|---|
| `CRB-001` | HIGH | Non-system subject bound to `cluster-admin` | T.01 |
| `CRB-002` | MEDIUM | ClusterRole with wildcard verbs or resources | T.01 |
| `CRB-003` | **CRITICAL** | Anonymous / unauthenticated access granted | I.04 |
| `CRB-004` | MEDIUM | `default` service account has explicit role binding | I.04 |

### 🌐 API Server

| ID | Severity | Title | STRIDE / Source |
|---|---|---|---|
| `API-001` | **CRITICAL** | Anonymous authentication enabled (default) | I.04 |
| `API-002` | **CRITICAL** | Insecure HTTP port open | S.01 |
| `API-003` | **CRITICAL** | `AlwaysAllow` authorization mode | T.01 |
| `API-004` | MEDIUM | ABAC authorization mode active | T.01 |
| `API-005` | HIGH | Static token file authentication enabled | I.04 |
| `API-006` | MEDIUM | `NodeRestriction` admission plugin missing | E.03 |
| `API-007` | HIGH | Audit logging not configured | R.01, R.02 |
| `API-008` | HIGH | Secrets not encrypted at rest in etcd | I.06 |
| `API-009` | LOW | API server profiling endpoint enabled | I.07 |
| `API-010` | MEDIUM | No dedicated service-account signing key | I.04 |

### ⚙️ Scheduler & Controller Manager

| ID | Severity | Title | Source |
|---|---|---|---|
| `SCH-001` | LOW | kube-scheduler profiling enabled | CIS 1.4.1 |
| `SCH-002` | MEDIUM | kube-scheduler bind address not restricted | CIS 1.4.2 |
| `CTL-001` | LOW | controller-manager profiling enabled | CIS 1.3.2 |
| `CTL-002` | MEDIUM | Not using per-controller SA credentials | CIS 1.3.3 |
| `CTL-003` | INFO | No terminated pod GC threshold | CIS 1.3.1 |

### 🗄️ etcd

| ID | Severity | Title | Source |
|---|---|---|---|
| `ETCD-001` | **CRITICAL** | Client certificate authentication not enforced | CIS 2.1 |
| `ETCD-002` | HIGH | Peer certificate authentication not enforced | CIS 2.5 |
| `ETCD-003` | HIGH | Auto-generated self-signed TLS in use | CIS 2.3 |

### 🐳 Pod / Workload Security

Scans `Deployments`, `DaemonSets`, `StatefulSets`, `Jobs`, and standalone `Pods`.

| ID | Severity | Title | Source |
|---|---|---|---|
| `PSC-001` | **CRITICAL** | Privileged container (`privileged: true`) | E.01 |
| `PSC-002` | HIGH | Container may run as root (UID 0) | E.01 |
| `PSC-003` | HIGH | `hostPID` / `hostNetwork` / `hostIPC` sharing | E.01 |
| `PSC-004` | MEDIUM | `allowPrivilegeEscalation` not disabled | E.01 |
| `PSC-005` | LOW | Writable root filesystem | E.01 |
| `PSC-006` | MEDIUM | Missing CPU / memory limits | D.01 |
| `PSC-007` | LOW | Image uses `:latest` or no tag | T.02 |
| `PSC-008` | LOW | Service account token auto-mounted | I.04 |
| `PSC-009` | HIGH | Dangerous Linux capability added (`SYS_ADMIN`, `NET_RAW`, …) | E.01 |
| `PSC-010` | LOW | No seccomp profile defined | E.01 |

Dangerous capabilities flagged by `PSC-009`:
`SYS_ADMIN` `SYS_PTRACE` `SYS_MODULE` `SYS_RAWIO` `NET_ADMIN` `NET_RAW`
`SYS_CHROOT` `DAC_OVERRIDE` `DAC_READ_SEARCH` `SETUID` `SETGID` `FOWNER` `KILL`

### 🔒 Network

| ID | Severity | Title | Source |
|---|---|---|---|
| `NET-001` | HIGH | No NetworkPolicy in namespace | E.02 |
| `NET-002` | MEDIUM | NetworkPolicy with allow-all ingress rule | E.02 |

### 🔑 Secrets

| ID | Severity | Title | Source |
|---|---|---|---|
| `SEC-001` | MEDIUM | Secret injected as environment variable | I.04 |
| `SEC-002` | LOW | Workload uses the `default` service account | I.04 |

### 📦 Namespace Hygiene

| ID | Severity | Title | Source |
|---|---|---|---|
| `NS-001` | LOW | Workload deployed in `default` namespace | ReynardSec § Namespaces |
| `NS-002` | MEDIUM | No Pod Security Standards label on namespace | ReynardSec § PSS |
| `NS-003` | LOW | No ResourceQuota in namespace | D.01 |

### 🖥️ Node & Certificates

| ID | Severity | Title | Source |
|---|---|---|---|
| `NODE-001` | INFO | Node not in Ready state | ReynardSec § Node Security |
| `CERT-001` | INFO | Non-system approved CSR found | ReynardSec § Verification |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings, or only INFO-level findings |
| `1` | At least one MEDIUM finding |
| `2` | At least one HIGH finding |
| `3` | At least one CRITICAL finding |

These are designed for **fail-fast CI/CD gates**:

```bash
python k8s_security_audit.py && echo "Cluster passed security audit"
```

---

## Output Examples

### Terminal (default)

```
╔══════════════════════════════════════════════╗
║   K8s Security Audit  –  Versatech Edition  ║
╚══════════════════════════════════════════════╝
  Context    : staging
  Namespaces : default, app-ns, monitoring

  [RBAC]          Cluster-admin bindings ... 1 findings
  [RBAC]          Wildcard permissions ... ✓ ok
  [RBAC]          Anonymous access grants ... 1 findings
  [API Server]    Security flags ... 3 findings
  [etcd]          TLS & auth flags ... ✓ ok
  ...

════════════════════════════════════════════════════════════════════════
  SUMMARY  ·  staging
════════════════════════════════════════════════════════════════════════
  CRITICAL      2  ██
  HIGH          5  █████
  MEDIUM        8  ████████
  LOW          12  ████████████
  INFO          1  █

  28 findings across 14 check IDs
```

### JSON output (`--output report.json`)

```json
{
  "cluster_context": "staging",
  "summary": {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 8,
    "LOW": 12,
    "INFO": 1
  },
  "findings": [
    {
      "check_id": "API-001",
      "severity": "CRITICAL",
      "category": "API Server",
      "title": "Anonymous authentication enabled (default)",
      "resource": "StaticPod/kube-apiserver-control-plane",
      "namespace": "kube-system",
      "detail": "--anonymous-auth defaults to true. Unauthenticated requests reach the API server.",
      "remediation": "Set --anonymous-auth=false in /etc/kubernetes/manifests/kube-apiserver.yaml.",
      "reference": "ReynardSec § Anonymous Access"
    }
  ]
}
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: K8s Security Audit

on:
  schedule:
    - cron: '0 6 * * 1'   # every Monday at 06:00
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install kubernetes

      - name: Configure kubectl
        uses: azure/k8s-set-context@v3
        with:
          kubeconfig: ${{ secrets.KUBECONFIG }}

      - name: Run security audit
        run: |
          python k8s_security_audit.py \
            --output audit-report.json \
            --namespaces production staging
        # exits 2 or 3 on HIGH/CRITICAL — fails the workflow

      - name: Upload report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: k8s-audit-report
          path: audit-report.json
```

### GitLab CI

```yaml
k8s-audit:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install kubernetes
    - mkdir -p ~/.kube && echo "$KUBECONFIG_B64" | base64 -d > ~/.kube/config
  script:
    - python k8s_security_audit.py --output gl-audit.json
  artifacts:
    when: always
    paths:
      - gl-audit.json
    expire_in: 30 days
  allow_failure: false
```

---

## Limitations

| Area | Limitation |
|---|---|
| **Kubelet config** | Kubelet security settings (`--anonymous-auth`, `--authorization-mode`, etc.) require SSH or direct node access — not available via the Kubernetes API. Use [kube-bench](https://github.com/aquasecurity/kube-bench) for full kubelet auditing. |
| **AppArmor profiles** | AppArmor profile *content* cannot be validated remotely. The scanner checks for seccompProfile but not AppArmor (which requires node access). |
| **Image vulnerability scanning** | This scanner does not scan container images for CVEs. Use [Trivy](https://github.com/aquasecurity/trivy) or [Grype](https://github.com/anchore/grype) for that. |
| **Managed clusters** | On managed clusters (AKS, EKS, GKE), the control-plane static pods are hidden. API-00x, SCH-00x, CTL-00x, and ETCD-00x checks will be silently skipped. |
| **Runtime detection** | This is a *static configuration* audit. It does not detect runtime threats like reverse shells or privilege escalations in progress — use [Falco](https://falco.org) for that. |
| **Custom PSPs / OPA** | Existing OPA Gatekeeper or Kyverno policies are not evaluated as compensating controls. |

---

## Complementary Tools

The ReynardSec guide recommends these tools alongside this scanner:

| Tool | Purpose |
|---|---|
| [kube-bench](https://github.com/aquasecurity/kube-bench) | Full CIS Benchmark compliance (runs on nodes) |
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | Active penetration testing |
| [rbac-tool](https://github.com/alcideio/rbac-tool) | Visual RBAC graph & who-can queries |
| [Trivy](https://github.com/aquasecurity/trivy) | Container image vulnerability scanning |
| [Falco](https://falco.org) | Runtime threat detection |
| [KubiScan](https://github.com/cyberark/KubiScan) | Risky RBAC permissions scanner |
| [kubeaudit](https://github.com/Shopify/kubeaudit) | Additional workload security checks |

---

## References

- [ReynardSec – Kubernetes Security Guide](https://reynardsec.com/en/kubernetes-security-guide/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA/CISA Kubernetes Hardening Guidance](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)
- [Kubernetes Official Security Docs](https://kubernetes.io/docs/concepts/security/)
- [Kubernetes Network Policy Recipes](https://github.com/ahmetb/kubernetes-network-policy-recipes)

---

## License

MIT — do whatever you want, but don't blame us if your cluster catches fire. 🔥

---

> ⚠️ **Always test hardening changes in a non-production environment first.**
> Not every recommendation applies to every cluster. Use this tool as a
> starting point for discussion, not as a compliance checkbox.
