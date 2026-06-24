# Security Policy

## Supported Versions

kube-sentinel is pre-1.0. Security fixes are applied to the latest released
version and to `main`.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a Vulnerability

Please **do not** open a public issue for security vulnerabilities.

Instead, report privately via [GitHub Security Advisories](https://github.com/BasitS-hash/kube-sentinel/security/advisories/new).
Include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal manifest or command is ideal).
- Affected version(s).

You can expect an acknowledgement within **3 business days** and a remediation
plan within **10 business days** for confirmed issues. We will coordinate a
disclosure timeline with you.

## Scope and threat model

kube-sentinel is a **static analysis and read-only audit tool**:

- The `scan` and `harden` commands operate purely on local files. They parse
  YAML with `yaml.safe_load_all` (never `yaml.load`), enforce a maximum file
  size, and never execute manifest content.
- The `cluster` command performs **read-only** API calls using your existing
  kubeconfig credentials. It does not create, modify, or delete any cluster
  resources, and it degrades gracefully when no cluster is reachable.
- kube-sentinel does not transmit your manifests or cluster data anywhere. All
  analysis happens locally.

Findings are advisory. Always review remediations and hardened output before
applying them to production.

## Hardening of this project

- CI runs `bandit` (SAST), `pip-audit` (dependency CVEs), `gitleaks`
  (secret scanning), and CodeQL on every push and pull request.
- Dependencies are kept current via Dependabot.
- No secrets are committed; inputs are validated at the parser boundary.
