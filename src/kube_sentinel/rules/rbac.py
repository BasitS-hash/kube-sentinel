"""RBAC security rules.

Covers CIS Section 5.1 (RBAC and Service Accounts) and the NSA/CISA
authentication/authorization mitigations: least privilege, no wildcards, and
controlled use of cluster-admin.

KS-RBAC-001..005 judge a Role or a binding on its own. KS-RBAC-006 is the
correlation: it asks whether any of that privilege is actually reachable from a
running workload.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .. import k8s
from ..models import Resource, Severity
from .base import CrossHit, ScanContext, build_rule, register

ROLE_KINDS = frozenset({"Role", "ClusterRole"})
BINDING_KINDS = frozenset({"RoleBinding", "ClusterRoleBinding"})

# Verbs that grant broad write/secret access and warrant scrutiny.
SENSITIVE_VERBS = frozenset({"*", "create", "update", "patch", "delete", "deletecollection"})

# The built-in ClusterRole that grants everything. It is matched by name because
# it ships with the cluster and so is almost never among the scanned manifests.
CLUSTER_ADMIN = "cluster-admin"

# Identity of a ServiceAccount: (namespace, name). A RoleBinding is namespaced
# and a ClusterRoleBinding is not, but a ServiceAccount always is, so the
# namespace is part of what makes two same-named SAs different principals.
SaIdentity = tuple[str, str]


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


def _role_index(context: ScanContext) -> dict[tuple[str, str | None, str], Resource]:
    """Index Roles and ClusterRoles by (kind, namespace, name).

    ClusterRoles are cluster-scoped, so their namespace key is ``None``; Roles
    only exist inside one namespace and must be looked up there.
    """
    index: dict[tuple[str, str | None, str], Resource] = {}
    for resource in context.resources:
        if resource.kind == "ClusterRole":
            index[("ClusterRole", None, resource.name)] = resource
        elif resource.kind == "Role":
            index[("Role", resource.namespace or "default", resource.name)] = resource
    return index


def _is_admin_equivalent(rule: dict[str, Any]) -> bool:
    """Whether one policy rule grants effectively unlimited power.

    Wildcard verbs over a wildcard scope is cluster-admin by another name.
    Narrower wildcards — ``verbs: [get]`` on ``resources: ["*"]`` — are real
    findings, but KS-RBAC-001 already reports them at HIGH; escalating only on
    the admin-equivalent combination keeps this rule's CRITICAL meaningful.
    """
    verbs = {str(v) for v in rule.get("verbs", []) or []}
    resources = {str(r) for r in rule.get("resources", []) or []}
    api_groups = {str(g) for g in rule.get("apiGroups", []) or []}
    return "*" in verbs and ("*" in resources or "*" in api_groups)


def _admin_grant_reason(
    binding: Resource,
    roles: dict[tuple[str, str | None, str], Resource],
) -> str | None:
    """Describe why a binding confers admin-equivalent power, else ``None``."""
    role_ref = binding.raw.get("roleRef")
    role_ref = role_ref if isinstance(role_ref, dict) else {}
    ref_kind = str(role_ref.get("kind", ""))
    ref_name = str(role_ref.get("name", ""))
    if not ref_name:
        return None
    if ref_name == CLUSTER_ADMIN:
        return f"the built-in {CLUSTER_ADMIN} ClusterRole"

    scope = None if ref_kind == "ClusterRole" else (binding.namespace or "default")
    role = roles.get((ref_kind, scope, ref_name))
    if role is None:
        # The role is not in the scanned set — a Helm chart's, or one that only
        # exists in the live cluster. Guessing at what it grants would produce a
        # CRITICAL nobody can verify, so stay silent.
        return None
    for policy_rule in _iter_rules(role):
        if _is_admin_equivalent(policy_rule):
            return f"{ref_kind}/{ref_name}, which grants wildcard verbs cluster-wide"
    return None


def _bound_service_accounts(binding: Resource) -> Iterator[SaIdentity]:
    """Yield the identity of every ServiceAccount subject of a binding.

    Users and Groups are skipped: they are human or external principals, which
    KS-RBAC-004/005 already report, and they never mount a pod token. A
    ClusterRoleBinding's SA subject must name its namespace; a RoleBinding's may
    omit it, in which case it means the binding's own namespace.
    """
    subjects = binding.raw.get("subjects") or []
    if not isinstance(subjects, list):
        return
    for subject in subjects:
        if not isinstance(subject, dict) or subject.get("kind") != "ServiceAccount":
            continue
        name = subject.get("name")
        if not name:
            continue
        namespace = subject.get("namespace") or binding.namespace or "default"
        yield (str(namespace), str(name))


def _mounts_token(pod_spec: dict[str, Any], service_account: Resource | None) -> bool:
    """Whether the SA token is actually projected into the pod's containers.

    The pod-level setting wins; failing that the ServiceAccount's own setting
    applies; failing both, Kubernetes mounts the token.
    """
    pod_setting = pod_spec.get("automountServiceAccountToken")
    if isinstance(pod_setting, bool):
        return pod_setting
    if service_account is not None:
        sa_setting = service_account.raw.get("automountServiceAccountToken")
        if isinstance(sa_setting, bool):
            return sa_setting
    return True


def _check_workload_admin_identity(context: ScanContext) -> Iterator[CrossHit]:
    """Correlate workloads with the bindings that make their SA dangerous.

    A cluster-admin binding on its own may be dead weight, and a mounted SA
    token on its own may be harmless. Together they are a direct path from one
    container compromise to control of the cluster, which is why this reports
    CRITICAL where each half reports MEDIUM or less in isolation.
    """
    roles = _role_index(context)

    # SA identity -> the bindings that grant it admin, each already phrased for
    # the finding message. Several bindings can grant the same SA, and deleting
    # one does not fix the others, so all of them get named.
    admin_bindings: dict[SaIdentity, list[str]] = {}
    for binding in context.of_kinds(BINDING_KINDS):
        reason = _admin_grant_reason(binding, roles)
        if reason is None:
            continue
        for identity in _bound_service_accounts(binding):
            admin_bindings.setdefault(identity, []).append(
                f"{binding.kind}/{binding.name} binds to {reason}"
            )

    if not admin_bindings:
        return

    service_accounts = {
        (r.namespace or "default", r.name): r
        for r in context.of_kinds(frozenset({"ServiceAccount"}))
    }

    for resource in context.of_kinds(k8s.POD_BEARING_KINDS):
        pod_spec = k8s.get_pod_spec(resource.raw)
        if pod_spec is None:
            continue
        identity = (resource.namespace or "default", k8s.service_account_name(pod_spec))
        grants = admin_bindings.get(identity)
        if not grants:
            continue
        if not _mounts_token(pod_spec, service_accounts.get(identity)):
            continue
        sa_namespace, sa_name = identity
        for grant in sorted(grants):
            yield CrossHit(
                message=(
                    f"{resource.kind}/{resource.name} mounts ServiceAccount "
                    f"'{sa_name}' (ns: {sa_namespace}), which {grant}"
                ),
                resource_kind=resource.kind,
                resource_name=resource.name,
                namespace=resource.namespace,
                file_path=resource.file_path,
            )


register(
    build_rule(
        id="KS-RBAC-006",
        title="Workload mounts an admin-equivalent service account",
        severity=Severity.CRITICAL,
        remediation="Bind the workload's ServiceAccount to a narrowly scoped Role "
        "instead of cluster-admin, or set automountServiceAccountToken: false if the "
        "workload never calls the Kubernetes API. Until one of those is true, any "
        "code execution in this pod is code execution as a cluster administrator.",
        cross_check=_check_workload_admin_identity,
        cis=("5.1.1", "5.1.6"),
        pss=(),
        nsa_cisa=("Authorization: apply least privilege to service accounts",),
        mitre_attack=(
            "T1098 Account Manipulation",
            "T1528 Steal Application Access Token",
        ),
    )
)
