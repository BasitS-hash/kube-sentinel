"""Unit tests for KS-RBAC-006: workloads that mount an admin-equivalent SA.

Every other rule judges one object. This one only has an answer when it can see
a workload, a ServiceAccount, and a binding at the same time, so the tests are
written against whole resource sets rather than single resources.
"""

from __future__ import annotations

from typing import Any

from kube_sentinel.engine import scan_resources
from kube_sentinel.models import Resource, Severity
from kube_sentinel.rules import get_rule, load_default_rules

load_default_rules()

RULE_ID = "KS-RBAC-006"


def res(kind: str, name: str, raw: dict[str, Any], namespace: str | None = "demo") -> Resource:
    return Resource(
        kind=kind,
        name=name,
        namespace=namespace,
        api_version="v1",
        file_path=f"mem://{name}",
        doc_index=0,
        raw={"kind": kind, "metadata": {"name": name, "namespace": namespace}, **raw},
    )


def deployment(name: str, pod_spec: dict[str, Any], namespace: str = "demo") -> Resource:
    return res(
        "Deployment",
        name,
        {"spec": {"template": {"spec": {"containers": [{"name": "c"}], **pod_spec}}}},
        namespace=namespace,
    )


def binding(
    name: str,
    role_name: str,
    subjects: list[dict[str, Any]],
    kind: str = "ClusterRoleBinding",
    role_kind: str = "ClusterRole",
    namespace: str | None = None,
) -> Resource:
    return res(
        kind,
        name,
        {
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": role_kind,
                "name": role_name,
            },
            "subjects": subjects,
        },
        namespace=namespace,
    )


def sa_subject(name: str, namespace: str | None = None) -> dict[str, Any]:
    subject: dict[str, Any] = {"kind": "ServiceAccount", "name": name}
    if namespace is not None:
        subject["namespace"] = namespace
    return subject


def hits(*resources: Resource) -> list[str]:
    report = scan_resources(tuple(resources))
    return [f.message for f in report.findings if f.rule_id == RULE_ID]


def test_workload_mounting_cluster_admin_sa_is_critical() -> None:
    findings = [
        f
        for f in scan_resources(
            (
                deployment("web", {"serviceAccountName": "ci"}),
                res("ServiceAccount", "ci", {}),
                binding("ci-admin", "cluster-admin", [sa_subject("ci", "demo")]),
            )
        ).findings
        if f.rule_id == RULE_ID
    ]
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    # Both sides of the correlation have to be named, or the finding is not
    # actionable: the operator needs to know which binding to go delete.
    assert "Deployment/web" in findings[0].message
    assert "ci" in findings[0].message
    assert "ClusterRoleBinding/ci-admin" in findings[0].message
    assert "cluster-admin" in findings[0].message


def test_implicit_default_service_account_is_resolved() -> None:
    # No serviceAccountName at all: Kubernetes injects the namespace's
    # 'default' SA, which is exactly the binding people forget about.
    messages = hits(
        deployment("web", {}),
        binding("default-admin", "cluster-admin", [sa_subject("default", "demo")]),
    )
    assert len(messages) == 1
    assert "default" in messages[0]


def test_deprecated_service_account_field_is_honoured() -> None:
    messages = hits(
        deployment("web", {"serviceAccount": "ci"}),
        binding("ci-admin", "cluster-admin", [sa_subject("ci", "demo")]),
    )
    assert len(messages) == 1


def test_pod_disabling_automount_is_not_flagged() -> None:
    # The binding is still a KS-RBAC-004 finding, but no token reaches the
    # container, so there is no live path from this workload.
    assert not hits(
        deployment("web", {"serviceAccountName": "ci", "automountServiceAccountToken": False}),
        binding("ci-admin", "cluster-admin", [sa_subject("ci", "demo")]),
    )


def test_service_account_disabling_automount_is_not_flagged() -> None:
    assert not hits(
        deployment("web", {"serviceAccountName": "ci"}),
        res("ServiceAccount", "ci", {"automountServiceAccountToken": False}),
        binding("ci-admin", "cluster-admin", [sa_subject("ci", "demo")]),
    )


def test_pod_setting_overrides_service_account_setting() -> None:
    # Pod-level automountServiceAccountToken wins over the SA's own default.
    messages = hits(
        deployment("web", {"serviceAccountName": "ci", "automountServiceAccountToken": True}),
        res("ServiceAccount", "ci", {"automountServiceAccountToken": False}),
        binding("ci-admin", "cluster-admin", [sa_subject("ci", "demo")]),
    )
    assert len(messages) == 1


def test_wildcard_cluster_role_counts_as_admin_equivalent() -> None:
    messages = hits(
        deployment("web", {"serviceAccountName": "ci"}),
        res(
            "ClusterRole",
            "too-powerful",
            {"rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]},
            namespace=None,
        ),
        binding("ci-power", "too-powerful", [sa_subject("ci", "demo")]),
    )
    assert len(messages) == 1
    assert "too-powerful" in messages[0]


def test_narrow_wildcard_is_left_to_ks_rbac_001() -> None:
    # 'get' on every resource is broad read access — a real finding, already
    # reported at HIGH by KS-RBAC-001 — but it is not cluster takeover, so it
    # must not inflate this rule's CRITICAL.
    report = scan_resources(
        (
            deployment("web", {"serviceAccountName": "ci"}),
            res(
                "ClusterRole",
                "reader",
                {"rules": [{"apiGroups": [""], "resources": ["*"], "verbs": ["get"]}]},
                namespace=None,
            ),
            binding("ci-read", "reader", [sa_subject("ci", "demo")]),
        )
    )
    triggered = {f.rule_id for f in report.findings}
    assert RULE_ID not in triggered
    assert "KS-RBAC-001" in triggered


def test_least_privilege_role_keeps_mounted_token_clean() -> None:
    # The headline distinction: a workload that mounts a token is fine when the
    # SA behind it cannot do anything interesting. KS-WL-013 still notes the
    # mount at MEDIUM; KS-RBAC-006 must stay quiet.
    report = scan_resources(
        (
            deployment("web", {"serviceAccountName": "ci"}),
            res(
                "Role",
                "config-reader",
                {
                    "rules": [
                        {
                            "apiGroups": [""],
                            "resources": ["configmaps"],
                            "resourceNames": ["web-config"],
                            "verbs": ["get"],
                        }
                    ]
                },
            ),
            binding(
                "ci-read",
                "config-reader",
                [sa_subject("ci")],
                kind="RoleBinding",
                role_kind="Role",
                namespace="demo",
            ),
        )
    )
    triggered = {f.rule_id for f in report.findings}
    assert RULE_ID not in triggered
    assert "KS-WL-013" in triggered


def test_rolebinding_subject_defaults_to_binding_namespace() -> None:
    # A RoleBinding subject may omit 'namespace'; it then means the binding's
    # own namespace.
    messages = hits(
        deployment("web", {"serviceAccountName": "ci"}),
        binding(
            "ci-admin",
            "cluster-admin",
            [sa_subject("ci")],
            kind="RoleBinding",
            namespace="demo",
        ),
    )
    assert len(messages) == 1


def test_service_account_namespace_is_scoped() -> None:
    # Same SA name, different namespace: a distinct identity, so the binding in
    # 'demo' says nothing about the workload in 'staging'.
    assert not hits(
        deployment("web", {"serviceAccountName": "ci"}, namespace="staging"),
        binding("ci-admin", "cluster-admin", [sa_subject("ci", "demo")]),
    )


def test_mixed_subject_list_only_follows_service_accounts() -> None:
    # Users and Groups are covered by KS-RBAC-004/005; they must neither crash
    # the walk nor produce a workload correlation.
    messages = hits(
        deployment("web", {"serviceAccountName": "ci"}),
        binding(
            "mixed-admin",
            "cluster-admin",
            [
                {"kind": "User", "name": "alice", "apiGroup": "rbac.authorization.k8s.io"},
                {"kind": "Group", "name": "ops", "apiGroup": "rbac.authorization.k8s.io"},
                sa_subject("ci", "demo"),
                {"kind": "ServiceAccount"},  # malformed: no name
            ],
        ),
    )
    assert len(messages) == 1


def test_unresolvable_role_reference_is_not_guessed() -> None:
    # The ClusterRole is not in the scanned set. We cannot know what it grants,
    # and inventing a CRITICAL would be worse than staying silent.
    assert not hits(
        deployment("web", {"serviceAccountName": "ci"}),
        binding("ci-unknown", "some-chart-role", [sa_subject("ci", "demo")]),
    )


def test_cronjob_pod_template_is_correlated() -> None:
    # CronJob nests its pod spec two levels deeper than everything else.
    messages = hits(
        res(
            "CronJob",
            "backup",
            {
                "spec": {
                    "schedule": "0 2 * * *",
                    "jobTemplate": {
                        "spec": {
                            "template": {
                                "spec": {
                                    "serviceAccountName": "ci",
                                    "containers": [{"name": "c"}],
                                }
                            }
                        }
                    },
                }
            },
        ),
        binding("ci-admin", "cluster-admin", [sa_subject("ci", "demo")]),
    )
    assert len(messages) == 1


def test_one_finding_per_dangerous_binding() -> None:
    # Two separate bindings grant the same SA admin: both need naming, because
    # deleting one does not fix the other.
    messages = hits(
        deployment("web", {"serviceAccountName": "ci"}),
        binding("ci-admin-a", "cluster-admin", [sa_subject("ci", "demo")]),
        binding("ci-admin-b", "cluster-admin", [sa_subject("ci", "demo")]),
    )
    assert len(messages) == 2
    assert any("ci-admin-a" in m for m in messages)
    assert any("ci-admin-b" in m for m in messages)


def test_mapping_cites_cis_and_mitre() -> None:
    rule = get_rule(RULE_ID)
    assert rule is not None
    assert "5.1.1" in rule.mapping.cis
    assert "5.1.6" in rule.mapping.cis
    assert any("T1098" in t for t in rule.mapping.mitre_attack)
    assert any("T1528" in t for t in rule.mapping.mitre_attack)
    assert rule.mapping.nsa_cisa  # least-privilege theme
    assert rule.severity is Severity.CRITICAL


def test_rule_is_registered_as_cross_resource() -> None:
    rule = get_rule(RULE_ID)
    assert rule is not None
    assert rule.is_cross_resource
    assert rule.check is None
