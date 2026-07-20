"""Unit tests for RBAC, networking, and cross-resource rules."""

from __future__ import annotations

from typing import Any

from kube_sentinel.engine import scan_resources
from kube_sentinel.models import Resource, Severity
from kube_sentinel.rules import get_rule, load_default_rules

load_default_rules()


def make(kind: str, raw: dict[str, Any], namespace: str | None = "demo") -> Resource:
    raw = {"kind": kind, "metadata": {"name": "t"}, **raw}
    return Resource(
        kind=kind,
        name="t",
        namespace=namespace,
        api_version="rbac.authorization.k8s.io/v1",
        file_path="mem://t",
        doc_index=0,
        raw=raw,
    )


def fires(rule_id: str, resource: Resource) -> bool:
    rule = get_rule(rule_id)
    assert rule is not None
    return bool(rule.evaluate(resource))


def test_wildcard_rbac() -> None:
    bad = make(
        "ClusterRole",
        {"rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]},
    )
    good = make(
        "ClusterRole",
        {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]},
    )
    assert fires("KS-RBAC-001", bad)
    assert not fires("KS-RBAC-001", good)


def test_secrets_access() -> None:
    bad = make(
        "Role",
        {"rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]},
    )
    good = make(
        "Role",
        {"rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]},
    )
    assert fires("KS-RBAC-002", bad)
    assert not fires("KS-RBAC-002", good)


def test_pods_exec() -> None:
    bad = make(
        "Role",
        {"rules": [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}]},
    )
    good = make(
        "Role",
        {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]},
    )
    assert fires("KS-RBAC-003", bad)
    assert not fires("KS-RBAC-003", good)


def test_cluster_admin_binding() -> None:
    bad = make(
        "ClusterRoleBinding",
        {
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{"kind": "User", "name": "alice"}],
        },
    )
    good = make(
        "ClusterRoleBinding",
        {
            "roleRef": {"kind": "ClusterRole", "name": "view"},
            "subjects": [{"kind": "User", "name": "alice"}],
        },
    )
    assert fires("KS-RBAC-004", bad)
    assert not fires("KS-RBAC-004", good)


def test_anonymous_binding() -> None:
    bad = make(
        "ClusterRoleBinding",
        {
            "roleRef": {"kind": "ClusterRole", "name": "view"},
            "subjects": [{"kind": "User", "name": "system:anonymous"}],
        },
    )
    good = make(
        "ClusterRoleBinding",
        {
            "roleRef": {"kind": "ClusterRole", "name": "view"},
            "subjects": [{"kind": "User", "name": "alice"}],
        },
    )
    assert fires("KS-RBAC-005", bad)
    assert not fires("KS-RBAC-005", good)


def make_svc(spec: dict[str, Any]) -> Resource:
    return Resource(
        kind="Service",
        name="s",
        namespace="demo",
        api_version="v1",
        file_path="mem://s",
        doc_index=0,
        raw={"kind": "Service", "metadata": {"name": "s"}, "spec": spec},
    )


def test_nodeport_and_loadbalancer() -> None:
    nodeport = make_svc({"type": "NodePort"})
    lb_open = make_svc({"type": "LoadBalancer"})
    lb_scoped = make_svc({"type": "LoadBalancer", "loadBalancerSourceRanges": ["10.0.0.0/8"]})
    clusterip = make_svc({"type": "ClusterIP"})
    assert fires("KS-NET-001", nodeport)
    assert fires("KS-NET-001", lb_open)
    assert not fires("KS-NET-001", lb_scoped)
    assert not fires("KS-NET-001", clusterip)


def test_loadbalancer_open_cidr_is_flagged() -> None:
    # A LoadBalancer "scoped" to 0.0.0.0/0 or ::/0 is open to the whole
    # internet and must be flagged, not treated as safely restricted.
    open_v4 = make_svc({"type": "LoadBalancer", "loadBalancerSourceRanges": ["0.0.0.0/0"]})
    open_v6 = make_svc({"type": "LoadBalancer", "loadBalancerSourceRanges": ["::/0"]})
    mixed = make_svc(
        {"type": "LoadBalancer", "loadBalancerSourceRanges": ["10.0.0.0/8", "0.0.0.0/0"]}
    )
    scoped = make_svc({"type": "LoadBalancer", "loadBalancerSourceRanges": ["10.0.0.0/8"]})
    assert fires("KS-NET-001", open_v4)
    assert fires("KS-NET-001", open_v6)
    assert fires("KS-NET-001", mixed)
    assert not fires("KS-NET-001", scoped)


def test_external_ips() -> None:
    bad = make_svc({"type": "ClusterIP", "externalIPs": ["1.2.3.4"]})
    good = make_svc({"type": "ClusterIP"})
    assert fires("KS-NET-002", bad)
    assert not fires("KS-NET-002", good)


def test_missing_networkpolicy_cross_resource() -> None:
    # A namespace with a workload but no NetworkPolicy triggers KS-NET-003.
    pod = Resource(
        kind="Pod",
        name="p",
        namespace="app",
        api_version="v1",
        file_path="mem://p",
        doc_index=0,
        raw={"kind": "Pod", "spec": {"containers": [{"name": "c"}]}},
    )
    report = scan_resources((pod,))
    assert any(f.rule_id == "KS-NET-003" for f in report.findings)


def test_networkpolicy_present_suppresses_finding() -> None:
    pod = Resource(
        kind="Pod",
        name="p",
        namespace="app",
        api_version="v1",
        file_path="mem://p",
        doc_index=0,
        raw={"kind": "Pod", "spec": {"containers": [{"name": "c"}]}},
    )
    netpol = Resource(
        kind="NetworkPolicy",
        name="deny",
        namespace="app",
        api_version="networking.k8s.io/v1",
        file_path="mem://np",
        doc_index=0,
        raw={"kind": "NetworkPolicy", "spec": {"podSelector": {}}},
    )
    report = scan_resources((pod, netpol))
    assert not any(f.rule_id == "KS-NET-003" for f in report.findings)


def test_netpol_finding_metadata() -> None:
    pod = Resource(
        kind="Pod",
        name="p",
        namespace=None,  # falls back to 'default'
        api_version="v1",
        file_path="mem://p",
        doc_index=0,
        raw={"kind": "Pod", "spec": {"containers": [{"name": "c"}]}},
    )
    report = scan_resources((pod,))
    netpol_findings = [f for f in report.findings if f.rule_id == "KS-NET-003"]
    assert len(netpol_findings) == 1
    assert netpol_findings[0].namespace == "default"
    assert netpol_findings[0].severity is Severity.MEDIUM
