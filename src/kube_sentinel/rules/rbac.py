"""RBAC security rules.

Covers CIS Section 5.1 (RBAC and Service Accounts) and the NSA/CISA
authentication/authorization mitigations: least privilege, no wildcards, and
controlled use of cluster-admin.
"""

from __future__ import annotations

from collections.abc import Iterator

from ..models import Resource, Severity
from .base import build_rule, register

ROLE_KINDS = frozenset({"Role", "ClusterRole"})
BINDING_KINDS = frozenset({"RoleBinding", "ClusterRoleBinding"})

# Verbs that grant broad write/secret access and warrant scrutiny.
SENSITIVE_VERBS = frozenset({"*", "create", "update", "patch", "delete", "deletecollection"})


def _iter_rules(resource: Resource) -> Iterator[dict]:
    for rule in resource.raw.get("rules", []) or []:
        if isinstance(rule, dict):
            yield rule


def _check_wildcard_rules(resource: Resource) -> Iterator[str]:
    for rule in _iter_rules(resource):
        verbs = [str(v) for v in rule.get("verbs", [])]
        resources = [str(r) for r in rule.get("resources", [])]
        api_groups = [str(g) for g in rule.get("apiGroups", [])]
        wildcard_parts = []
        if "*" in verbs:
            wildcard_parts.append("verbs")
        if "*" in resources:
            wildcard_parts.append("resources")
        if "*" in api_groups:
            wildcard_parts.append("apiGroups")
        if wildcard_parts:
            yield (f"{resource.kind} grants wildcard '*' on {', '.join(wildcard_parts)}")


def _check_secrets_access(resource: Resource) -> Iterator[str]:
    for rule in _iter_rules(resource):
        resources = {str(r) for r in rule.get("resources", [])}
        verbs = {str(v) for v in rule.get("verbs", [])}
        if ("secrets" in resources or "*" in resources) and verbs & {"get", "list", "watch", "*"}:
            yield (
                f"{resource.kind} can read secrets "
                f"(verbs: {', '.join(sorted(verbs & {'get', 'list', 'watch', '*'}))})"
            )


def _check_pods_exec(resource: Resource) -> Iterator[str]:
    for rule in _iter_rules(resource):
        resources = {str(r) for r in rule.get("resources", [])}
        verbs = {str(v) for v in rule.get("verbs", [])}
        if {"pods/exec", "pods/attach"} & resources and verbs & {"create", "*"}:
            yield f"{resource.kind} allows exec/attach into pods (interactive shell access)"


def _check_cluster_admin_binding(resource: Resource) -> Iterator[str]:
    role_ref = resource.raw.get("roleRef", {})
    role_ref = role_ref if isinstance(role_ref, dict) else {}
    if role_ref.get("name") == "cluster-admin":
        subjects = resource.raw.get("subjects", []) or []
        names = ", ".join(
            f"{s.get('kind', '?')}/{s.get('name', '?')}" for s in subjects if isinstance(s, dict)
        )
        yield (f"{resource.kind} binds the cluster-admin role to: {names or '<no subjects>'}")


def _check_anonymous_or_system_unauth(resource: Resource) -> Iterator[str]:
    subjects = resource.raw.get("subjects", []) or []
    for s in subjects:
        if not isinstance(s, dict):
            continue
        name = s.get("name", "")
        if name in {"system:anonymous", "system:unauthenticated"}:
            yield f"{resource.kind} grants access to unauthenticated principal '{name}'"


register(
    build_rule(
        id="KS-RBAC-001",
        title="Wildcard in RBAC rule",
        severity=Severity.HIGH,
        remediation="Replace '*' verbs/resources/apiGroups with the explicit minimum "
        "set the workload needs. Wildcards defeat least privilege.",
        check=_check_wildcard_rules,
        cis=("5.1.3",),
        pss=(),
        nsa_cisa=("Authorization: use least-privilege RBAC, avoid wildcards",),
        mitre_attack=("T1078 Valid Accounts",),
        applies_to=ROLE_KINDS,
    )
)

register(
    build_rule(
        id="KS-RBAC-002",
        title="Broad secrets access",
        severity=Severity.HIGH,
        remediation="Scope secret access to named secrets where possible and grant "
        "only to workloads that genuinely need them. Secrets read access enables "
        "credential theft.",
        check=_check_secrets_access,
        cis=("5.1.2",),
        pss=(),
        nsa_cisa=("Authorization: protect secrets via least privilege",),
        mitre_attack=("T1552 Unsecured Credentials",),
        applies_to=ROLE_KINDS,
    )
)

register(
    build_rule(
        id="KS-RBAC-003",
        title="Pod exec/attach permission",
        severity=Severity.MEDIUM,
        remediation="Avoid granting pods/exec or pods/attach. Interactive access to "
        "pods can be used for lateral movement and to bypass admission controls.",
        check=_check_pods_exec,
        cis=("5.1.4",),
        pss=(),
        nsa_cisa=("Authorization: restrict interactive pod access",),
        mitre_attack=("T1609 Container Administration Command",),
        applies_to=ROLE_KINDS,
    )
)

register(
    build_rule(
        id="KS-RBAC-004",
        title="cluster-admin binding",
        severity=Severity.CRITICAL,
        remediation="Do not bind cluster-admin to users, groups, or service accounts. "
        "Create a narrowly scoped role granting only the required permissions.",
        check=_check_cluster_admin_binding,
        cis=("5.1.1",),
        pss=(),
        nsa_cisa=("Authorization: limit administrator access",),
        mitre_attack=("T1078 Valid Accounts", "T1098 Account Manipulation"),
        applies_to=BINDING_KINDS,
    )
)

register(
    build_rule(
        id="KS-RBAC-005",
        title="Binding to unauthenticated principal",
        severity=Severity.CRITICAL,
        remediation="Remove bindings to system:anonymous or system:unauthenticated. "
        "Disable anonymous authentication on the API server.",
        check=_check_anonymous_or_system_unauth,
        cis=("5.1.1",),
        pss=(),
        nsa_cisa=("Authentication: disable anonymous access",),
        mitre_attack=("T1078 Valid Accounts",),
        applies_to=BINDING_KINDS,
    )
)
