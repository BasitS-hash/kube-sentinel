"""Regression tests for malformed-but-valid manifests.

YAML lets a list-valued field be null (``containers:`` with no value parses to
``None``). Before the fix, iterating those None values raised ``TypeError`` and
aborted the entire scan/harden. These tests pin the graceful behaviour.
"""

from __future__ import annotations

from typing import Any

from kube_sentinel.engine import scan_resources
from kube_sentinel.harden import harden_to_yaml
from kube_sentinel.models import Resource
from kube_sentinel.rules import get_rule, load_default_rules

load_default_rules()


def _pod(spec: dict[str, Any], kind: str = "Pod") -> Resource:
    return Resource(
        kind=kind,
        name="t",
        namespace="demo",
        api_version="v1",
        file_path="mem://t",
        doc_index=0,
        raw={"kind": kind, "metadata": {"name": "t"}, "spec": spec},
    )


def test_null_containers_does_not_crash_scan() -> None:
    # Arrange: a Pod whose list fields are explicitly null.
    resource = _pod({"containers": None, "initContainers": None, "volumes": None})

    # Act: a full scan must complete without raising.
    report = scan_resources((resource,))

    # Assert: no container-level findings, but the scan produced a report.
    assert report.resource_count == 1
    assert not any(f.rule_id == "KS-WL-001" for f in report.findings)


def test_null_containers_does_not_crash_individual_rules() -> None:
    resource = _pod({"containers": None, "volumes": None})
    for rule_id in ("KS-WL-001", "KS-WL-005", "KS-WL-009", "KS-WL-014"):
        rule = get_rule(rule_id)
        assert rule is not None
        assert rule.evaluate(resource) == []


def test_null_containers_does_not_crash_harden() -> None:
    resource = _pod({"containers": None})
    # Act + Assert: hardening a degenerate spec returns YAML, not a traceback.
    out = harden_to_yaml([resource])
    assert "kind: Pod" in out


def test_empty_spec_scans_cleanly() -> None:
    report = scan_resources((_pod({}),))
    assert report.resource_count == 1


def test_non_list_volumes_ignored() -> None:
    # A scalar where a list is expected must be ignored, not crash.
    resource = _pod({"containers": [{"name": "c"}], "volumes": "oops"})
    rule = get_rule("KS-WL-009")
    assert rule is not None
    assert rule.evaluate(resource) == []


def test_binding_with_null_or_scalar_subjects_does_not_crash() -> None:
    # 'subjects:' with no value parses to None; a hand-mangled manifest can
    # also leave a scalar there. Neither may abort the correlation walk.
    def binding(subjects: Any) -> Resource:
        return Resource(
            kind="ClusterRoleBinding",
            name="b",
            namespace=None,
            api_version="rbac.authorization.k8s.io/v1",
            file_path="mem://b",
            doc_index=0,
            raw={
                "kind": "ClusterRoleBinding",
                "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                "subjects": subjects,
            },
        )

    for subjects in (None, "oops", [None, 7]):
        report = scan_resources((_pod({"containers": [{"name": "c"}]}), binding(subjects)))
        assert not any(f.rule_id == "KS-RBAC-006" for f in report.findings)


def test_binding_without_a_role_ref_name_is_ignored() -> None:
    # An empty or missing roleRef tells us nothing; it must not be treated as a
    # grant, and it must not raise.
    for role_ref in (None, {}, {"kind": "ClusterRole"}, "cluster-admin"):
        binding = Resource(
            kind="ClusterRoleBinding",
            name="b",
            namespace=None,
            api_version="rbac.authorization.k8s.io/v1",
            file_path="mem://b",
            doc_index=0,
            raw={
                "kind": "ClusterRoleBinding",
                "roleRef": role_ref,
                "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "demo"}],
            },
        )
        report = scan_resources((_pod({"containers": [{"name": "c"}]}), binding))
        assert not any(f.rule_id == "KS-RBAC-006" for f in report.findings)


def test_workload_with_no_pod_spec_is_skipped_by_the_correlation() -> None:
    # A Deployment whose spec.template is missing has nothing to correlate.
    broken = Resource(
        kind="Deployment",
        name="d",
        namespace="demo",
        api_version="apps/v1",
        file_path="mem://d",
        doc_index=0,
        raw={"kind": "Deployment", "spec": {"replicas": 1}},
    )
    binding = Resource(
        kind="ClusterRoleBinding",
        name="b",
        namespace=None,
        api_version="rbac.authorization.k8s.io/v1",
        file_path="mem://b",
        doc_index=0,
        raw={
            "kind": "ClusterRoleBinding",
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "demo"}],
        },
    )
    report = scan_resources((broken, binding))
    assert not any(f.rule_id == "KS-RBAC-006" for f in report.findings)
