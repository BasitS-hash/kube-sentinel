"""Unit tests for individual workload rules.

Each rule is exercised with a minimal positive (should fire) and negative
(should not fire) case to keep coverage focused and meaningful.
"""

from __future__ import annotations

from typing import Any

from kube_sentinel.models import Resource
from kube_sentinel.rules import get_rule, load_default_rules

load_default_rules()


def make_pod(spec: dict[str, Any], kind: str = "Pod") -> Resource:
    raw = {"apiVersion": "v1", "kind": kind, "metadata": {"name": "t"}, "spec": spec}
    return Resource(
        kind=kind,
        name="t",
        namespace="demo",
        api_version="v1",
        file_path="mem://t",
        doc_index=0,
        raw=raw,
    )


def make_deployment(pod_spec: dict[str, Any]) -> Resource:
    raw = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "t"},
        "spec": {"template": {"spec": pod_spec}},
    }
    return Resource(
        kind="Deployment",
        name="t",
        namespace="demo",
        api_version="apps/v1",
        file_path="mem://t",
        doc_index=0,
        raw=raw,
    )


def fires(rule_id: str, resource: Resource) -> bool:
    rule = get_rule(rule_id)
    assert rule is not None
    return bool(rule.evaluate(resource))


def test_privileged_fires_and_clears() -> None:
    bad = make_pod({"containers": [{"name": "c", "securityContext": {"privileged": True}}]})
    good = make_pod({"containers": [{"name": "c", "securityContext": {"privileged": False}}]})
    assert fires("KS-WL-001", bad)
    assert not fires("KS-WL-001", good)


def test_privilege_escalation() -> None:
    bad = make_pod({"containers": [{"name": "c"}]})
    good = make_pod(
        {"containers": [{"name": "c", "securityContext": {"allowPrivilegeEscalation": False}}]}
    )
    assert fires("KS-WL-002", bad)
    assert not fires("KS-WL-002", good)


def test_run_as_root_explicit_uid_zero() -> None:
    bad = make_pod({"containers": [{"name": "c", "securityContext": {"runAsUser": 0}}]})
    assert fires("KS-WL-003", bad)


def test_run_as_non_root_pod_level_inheritance() -> None:
    good = make_pod(
        {
            "securityContext": {"runAsNonRoot": True},
            "containers": [{"name": "c"}],
        }
    )
    assert not fires("KS-WL-003", good)


def test_run_as_non_root_container_overrides_pod() -> None:
    bad = make_pod(
        {
            "securityContext": {"runAsNonRoot": True},
            "containers": [{"name": "c", "securityContext": {"runAsNonRoot": False}}],
        }
    )
    assert fires("KS-WL-003", bad)


def test_read_only_root_fs() -> None:
    bad = make_pod({"containers": [{"name": "c"}]})
    good = make_pod(
        {"containers": [{"name": "c", "securityContext": {"readOnlyRootFilesystem": True}}]}
    )
    assert fires("KS-WL-004", bad)
    assert not fires("KS-WL-004", good)


def test_drop_all_capabilities() -> None:
    bad = make_pod({"containers": [{"name": "c", "securityContext": {"capabilities": {}}}]})
    good = make_pod(
        {"containers": [{"name": "c", "securityContext": {"capabilities": {"drop": ["ALL"]}}}]}
    )
    assert fires("KS-WL-005", bad)
    assert not fires("KS-WL-005", good)


def test_dangerous_capabilities() -> None:
    bad = make_pod(
        {"containers": [{"name": "c", "securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}}]}
    )
    good = make_pod(
        {
            "containers": [
                {"name": "c", "securityContext": {"capabilities": {"add": ["NET_BIND_SERVICE"]}}}
            ]
        }
    )
    assert fires("KS-WL-006", bad)
    assert not fires("KS-WL-006", good)


def test_missing_security_context() -> None:
    bad = make_pod({"containers": [{"name": "c"}]})
    good = make_pod({"containers": [{"name": "c", "securityContext": {"runAsNonRoot": True}}]})
    assert fires("KS-WL-007", bad)
    assert not fires("KS-WL-007", good)


def test_host_namespaces() -> None:
    for field in ("hostNetwork", "hostPID", "hostIPC"):
        bad = make_pod({field: True, "containers": [{"name": "c"}]})
        assert fires("KS-WL-008", bad), field
    good = make_pod({"containers": [{"name": "c"}]})
    assert not fires("KS-WL-008", good)


def test_host_path_volume() -> None:
    bad = make_pod(
        {
            "containers": [{"name": "c"}],
            "volumes": [{"name": "v", "hostPath": {"path": "/etc"}}],
        }
    )
    good = make_pod({"containers": [{"name": "c"}], "volumes": [{"name": "v", "emptyDir": {}}]})
    assert fires("KS-WL-009", bad)
    assert not fires("KS-WL-009", good)


def test_missing_resources() -> None:
    bad = make_pod({"containers": [{"name": "c"}]})
    good = make_pod(
        {
            "containers": [
                {
                    "name": "c",
                    "resources": {
                        "requests": {"cpu": "100m", "memory": "128Mi"},
                        "limits": {"cpu": "500m", "memory": "256Mi"},
                    },
                }
            ]
        }
    )
    assert fires("KS-WL-010", bad)
    assert not fires("KS-WL-010", good)


def test_image_tags() -> None:
    latest = make_pod({"containers": [{"name": "c", "image": "nginx:latest"}]})
    untagged = make_pod({"containers": [{"name": "c", "image": "nginx"}]})
    pinned = make_pod({"containers": [{"name": "c", "image": "nginx:1.27.3"}]})
    digest = make_pod({"containers": [{"name": "c", "image": "nginx@sha256:abc"}]})
    no_image = make_pod({"containers": [{"name": "c"}]})
    assert fires("KS-WL-011", latest)
    assert fires("KS-WL-011", untagged)
    assert fires("KS-WL-011", no_image)
    assert not fires("KS-WL-011", pinned)
    assert not fires("KS-WL-011", digest)


def test_registry_port_not_confused_with_tag() -> None:
    # host:5000/img with no tag is untagged, not "tagged 5000/img".
    untagged = make_pod({"containers": [{"name": "c", "image": "registry:5000/img"}]})
    assert fires("KS-WL-011", untagged)
    tagged = make_pod({"containers": [{"name": "c", "image": "registry:5000/img:v1"}]})
    assert not fires("KS-WL-011", tagged)


def test_probes_only_for_long_running_controllers() -> None:
    bad = make_deployment({"containers": [{"name": "c"}]})
    good = make_deployment(
        {
            "containers": [
                {
                    "name": "c",
                    "livenessProbe": {"httpGet": {"path": "/", "port": 8080}},
                    "readinessProbe": {"httpGet": {"path": "/", "port": 8080}},
                }
            ]
        }
    )
    assert fires("KS-WL-012", bad)
    assert not fires("KS-WL-012", good)
    # A Pod should not trigger the probe rule (applies_to excludes it).
    assert not fires("KS-WL-012", make_pod({"containers": [{"name": "c"}]}))


def test_automount_token() -> None:
    bad = make_pod({"containers": [{"name": "c"}]})
    good = make_pod({"automountServiceAccountToken": False, "containers": [{"name": "c"}]})
    assert fires("KS-WL-013", bad)
    assert not fires("KS-WL-013", good)


def test_seccomp_profile() -> None:
    missing = make_pod({"containers": [{"name": "c"}]})
    unconfined = make_pod(
        {
            "containers": [
                {"name": "c", "securityContext": {"seccompProfile": {"type": "Unconfined"}}}
            ]
        }
    )
    good_pod_level = make_pod(
        {
            "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "c"}],
        }
    )
    assert fires("KS-WL-014", missing)
    assert fires("KS-WL-014", unconfined)
    assert not fires("KS-WL-014", good_pod_level)


def test_rule_applies_to_filtering() -> None:
    # A workload rule must not fire on a Service.
    svc = Resource(
        kind="Service",
        name="s",
        namespace="demo",
        api_version="v1",
        file_path="mem://s",
        doc_index=0,
        raw={"kind": "Service", "spec": {"type": "ClusterIP"}},
    )
    assert not fires("KS-WL-001", svc)


def test_all_rules_have_unique_ids_and_mappings() -> None:
    rules = load_default_rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    for r in rules:
        assert r.remediation
        assert r.title
