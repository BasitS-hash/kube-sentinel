# kube-sentinel

> Kubernetes security posture scanner. Audit manifests and live clusters for misconfigurations against the **CIS Kubernetes Benchmark**, **Pod Security Standards**, and the **NSA/CISA Kubernetes Hardening Guide** — with a posture score, a letter grade, and SARIF output for GitHub code scanning.

[![CI](https://github.com/BasitS-hash/kube-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/BasitS-hash/kube-sentinel/actions/workflows/ci.yml)
[![Security](https://github.com/BasitS-hash/kube-sentinel/actions/workflows/security.yml/badge.svg)](https://github.com/BasitS-hash/kube-sentinel/actions/workflows/security.yml)
[![CodeQL](https://github.com/BasitS-hash/kube-sentinel/actions/workflows/codeql.yml/badge.svg)](https://github.com/BasitS-hash/kube-sentinel/actions/workflows/codeql.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

---

## Why this matters

Most Kubernetes breaches do not start with a zero-day — they start with a misconfiguration. A container running as root with `privileged: true`, a service account bound to `cluster-admin`, a `hostPath` mount of `/`, a namespace with no NetworkPolicy: each is a stepping stone an attacker uses for container escape, lateral movement, and credential theft.

The three authoritative baselines everyone is measured against are:

- **[Pod Security Standards (PSS)](https://kubernetes.io/docs/concepts/security/pod-security-standards/)** — the three built-in profiles `privileged`, `baseline`, and `restricted`, enforced by Pod Security Admission.
- **[CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)** — Section 5 (Policies) covers RBAC, Pod Security Standards, and Network Policies.
- **[NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)** — least-privilege pods, network separation, strong authentication/authorization, and scanning for misconfigurations.

**kube-sentinel** turns those baselines into a fast, pluggable rule pack you can run on a developer laptop, in CI, or against a live cluster — and it speaks SARIF, so findings land directly in the GitHub Security tab.

## Features

- **Static manifest scanning** — recursively parses multi-document YAML (Deployments, Pods, DaemonSets, StatefulSets, Jobs, CronJobs, RBAC, Services, NetworkPolicies).
- **22 data-driven rules** across workload security, RBAC, and networking — each mapped to CIS, PSS, NSA/CISA, and MITRE ATT&CK for Containers.
- **Cross-resource analysis** — flags namespaces that run workloads but ship no NetworkPolicy.
- **Optional live-cluster scanning** (`cluster` extra) — scans running workloads via your current kubeconfig context; exits cleanly with a clear message if no cluster is reachable.
- **`harden` command** — rewrites a manifest to satisfy the restricted Pod Security Standard.
- **Multiple outputs** — rich terminal table (default), `--json`, and valid **SARIF 2.1.0** for GitHub code scanning.
- **Posture score and grade** — a 0–100 score and an A+→F letter grade summarising overall posture.
- **Configurable failure gate** — `--fail-on {CRITICAL,HIGH,MEDIUM,LOW,INFO}` controls the CI exit code.

## Install

```bash
# Core install (manifest scanning, no cluster dependency)
pip install kube-sentinel

# With live-cluster support
pip install "kube-sentinel[cluster]"
```

From source:

```bash
git clone https://github.com/BasitS-hash/kube-sentinel.git
cd kube-sentinel
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# Scan a directory of manifests
kube-sentinel scan ./manifests

# JSON or SARIF output
kube-sentinel scan ./manifests --json
kube-sentinel scan ./manifests --sarif -o results.sarif

# Fail the build only on CRITICAL findings
kube-sentinel scan ./manifests --fail-on CRITICAL

# Scan a live cluster (requires the [cluster] extra)
kube-sentinel cluster --context my-prod-context

# Emit a hardened version of a manifest
kube-sentinel harden deployment.yaml -o deployment.hardened.yaml

# List the rule catalog
kube-sentinel rules
```

Exit codes: `0` clean, `1` findings at/above the `--fail-on` threshold, `2` usage/runtime error (including an unreachable cluster).

### Insecure vs. hardened — the difference

The repo ships an `examples/insecure` set and a matching `examples/hardened` set.

```text
$ kube-sentinel scan examples/insecure
...
╭───────────────── Summary ─────────────────╮
│ Resources: 10   Findings: 42              │
│ CRITICAL: 3  HIGH: 15  MEDIUM: 20  LOW: 4 │
│                                           │
│ Posture score: 0/100   Grade: F           │
╰───────────────────────────────────────────╯
```

```text
$ kube-sentinel scan examples/hardened
╭─────────────────────── kube-sentinel ───────────────────────╮
│ No findings. Scanned 6 resource(s) with 22 rules.            │
╰──────────────────────────────────────────────────────────────╯
╭───────────── Summary ──────────────╮
│ Resources: 6   Findings: 0         │
│ clean                              │
│                                    │
│ Posture score: 100/100   Grade: A+ │
╰────────────────────────────────────╯
```

Each finding includes the file, resource kind/name, rule ID, severity, a remediation, and the CIS/PSS/NSA mapping. For example, the privileged container in the insecure Deployment produces:

```text
CRITICAL  KS-WL-001  Deployment/web (ns: demo)
          container 'web' runs in privileged mode
          → Remove 'privileged: true' from the container securityContext.
          CIS 5.2.5 · PSS baseline:Privileged Containers · MITRE T1611 Escape to Host
```

## Rule catalog

| ID | Description | Severity | CIS | PSS | MITRE ATT&CK |
|----|-------------|----------|-----|-----|--------------|
| `KS-WL-001` | Privileged container | CRITICAL | 5.2.5 | baseline (Privileged Containers) | T1611 Escape to Host |
| `KS-WL-002` | `allowPrivilegeEscalation` not disabled | HIGH | 5.2.6 | restricted (Privilege Escalation) | T1548 Abuse Elevation Control |
| `KS-WL-003` | Container may run as root | HIGH | 5.2.6 | restricted (Running as Non-root) | T1610 Deploy Container |
| `KS-WL-004` | Root filesystem is writable | MEDIUM | 5.2.12 | restricted | T1222 File/Dir Permissions Mod |
| `KS-WL-005` | Capabilities not dropped (`drop: [ALL]`) | MEDIUM | 5.2.9 | restricted (Capabilities) | T1548 Abuse Elevation Control |
| `KS-WL-006` | Dangerous capability added | HIGH | 5.2.9 | baseline (Capabilities) | T1611 Escape to Host |
| `KS-WL-007` | Missing container `securityContext` | MEDIUM | 5.2.1 | restricted | T1610 Deploy Container |
| `KS-WL-008` | Host namespace sharing (`hostNetwork`/`hostPID`/`hostIPC`) | HIGH | 5.2.2–5.2.4 | baseline (Host Namespaces) | T1611 Escape to Host |
| `KS-WL-009` | `hostPath` volume mount | HIGH | 5.2.10 | baseline (HostPath) / restricted (Volume Types) | T1006 Direct Volume Access |
| `KS-WL-010` | Missing resource requests/limits | LOW | 5.7.3 | — | T1499 Endpoint DoS |
| `KS-WL-011` | Mutable or untagged image (`:latest`) | MEDIUM | — | — | T1525 Implant Internal Image |
| `KS-WL-012` | Missing liveness/readiness probe | LOW | — | — | — |
| `KS-WL-013` | Service account token auto-mounted | MEDIUM | 5.1.6 | — | T1528 Steal App Access Token |
| `KS-WL-014` | Missing or `Unconfined` seccomp profile | MEDIUM | 5.2.1 | baseline / restricted (Seccomp) | T1611 Escape to Host |
| `KS-RBAC-001` | Wildcard in RBAC rule | HIGH | 5.1.3 | — | T1078 Valid Accounts |
| `KS-RBAC-002` | Broad secrets access | HIGH | 5.1.2 | — | T1552 Unsecured Credentials |
| `KS-RBAC-003` | Pod `exec`/`attach` permission | MEDIUM | 5.1.4 | — | T1609 Container Admin Command |
| `KS-RBAC-004` | `cluster-admin` binding | CRITICAL | 5.1.1 | — | T1098 Account Manipulation |
| `KS-RBAC-005` | Binding to unauthenticated principal | CRITICAL | 5.1.1 | — | T1078 Valid Accounts |
| `KS-NET-001` | Broadly exposed Service (NodePort / open LoadBalancer) | MEDIUM | 5.3.2 | — | T1190 Exploit Public-Facing App |
| `KS-NET-002` | Service uses `externalIPs` | HIGH | 5.3.2 | — | T1190 Exploit Public-Facing App |
| `KS-NET-003` | Namespace without a NetworkPolicy | MEDIUM | 5.3.2 | — | T1046 Network Service Discovery |

Run `kube-sentinel rules` for the full mapping including the NSA/CISA themes.

### MITRE ATT&CK for Containers

kube-sentinel maps findings to the [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/) matrix so you can reason about real adversary behaviour rather than abstract checks. The headline techniques covered:

- **T1611 Escape to Host** — privileged containers, host namespaces, dangerous capabilities, unconfined seccomp.
- **T1610 Deploy Container** / **T1525 Implant Internal Image** — untrusted/mutable images and overly permissive pod specs.
- **T1078 Valid Accounts** / **T1098 Account Manipulation** — RBAC wildcards, `cluster-admin` bindings, anonymous bindings.
- **T1552 Unsecured Credentials** / **T1528 Steal Application Access Token** — broad secrets access, auto-mounted SA tokens.
- **T1190 Exploit Public-Facing Application** — over-exposed Services and `externalIPs`.

## CI / SARIF integration

Add kube-sentinel to your pipeline and publish findings to the GitHub Security tab:

```yaml
name: kube-sentinel
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install kube-sentinel
      - run: kube-sentinel scan ./manifests --sarif -o kube-sentinel.sarif --fail-on HIGH
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: kube-sentinel.sarif
```

This repository **dogfoods itself**: the [`kube-sentinel-scan` workflow](.github/workflows/kube-sentinel-scan.yml) scans `examples/insecure`, uploads the SARIF, and gates on `examples/hardened` staying clean.

## How it works

```
parser ─► resources ─► engine ─► rule pack ─► findings ─► renderer (table / json / sarif)
                          │
                          └─ cross-resource checks (e.g. namespaces lacking NetworkPolicy)
```

- **Rules are data.** Each rule declares its ID, severity, remediation, and compliance mapping, plus a pure `check` function. New rule packs register themselves into a central registry — no engine changes required.
- **Inputs are decoupled from rules.** The same rule pack runs over parsed YAML and over live-cluster objects (which the kubernetes client serialises to the same camelCase shape).
- **Outputs are pure functions** of the report, so every renderer is unit-tested without touching a terminal.

## Project layout

```
src/kube_sentinel/
├── cli.py          # typer CLI (scan / cluster / harden / rules)
├── parser.py       # multi-doc YAML parsing, recursive directory walk
├── k8s.py          # pod-spec / container navigation helpers
├── models.py       # frozen dataclasses: Severity, Finding, Resource, mappings
├── engine.py       # rule execution, cross-resource checks, scoring/grading
├── harden.py       # restricted-PSS manifest rewriting
├── report.py       # rich table, JSON, SARIF 2.1.0 renderers
├── cluster.py      # optional kubernetes-client live scanning (graceful)
└── rules/
    ├── base.py     # Rule abstraction + registry
    ├── workload.py # KS-WL-* (PSS baseline + restricted)
    ├── rbac.py     # KS-RBAC-*
    └── networking.py # KS-NET-*
```

## Development

```bash
pip install -e ".[dev]"
ruff check src tests          # lint
ruff format src tests         # format
mypy                          # type-check
pytest --cov=kube_sentinel    # tests + coverage
bandit -r src                 # SAST
pip-audit                     # dependency CVEs
```

The test suite asserts that the insecure examples trip the full range of rules, that the hardened examples produce **zero** findings, that malformed-but-valid manifests (e.g. a null `containers:` field) are handled without crashing, and that emitted SARIF validates against the official [SARIF 2.1.0 JSON schema](https://github.com/oasis-tcs/sarif-spec) (vendored under `tests/fixtures/` so the check runs offline).

## Roadmap

- [ ] Configurable rule severity overrides and per-rule suppressions (inline annotations + config file).
- [ ] Helm chart and Kustomize overlay rendering before scanning.
- [ ] Additional rule packs: secrets-in-env, image registry allow-lists, PodDisruptionBudget coverage.
- [ ] Policy bundles for `baseline`-only vs. `restricted` enforcement.
- [ ] JUnit and Markdown report renderers.
- [ ] OCI image distribution and a pre-commit hook.

## References

- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA/CISA Kubernetes Hardening Guide (v1.2)](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

## License

[MIT](LICENSE) © kube-sentinel contributors
