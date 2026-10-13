"""Parity between the two inputs: parsed YAML and live-cluster objects.

The README claims inputs are decoupled from rules — that the same rule pack runs
over a manifest and over the equivalent object fetched from a cluster. Nothing
asserted that until this module. The claim is load-bearing: the official Python
client's model objects expose snake_case attributes and ``to_dict()`` returns
snake_case keys (``security_context``, ``host_network``), while the rules and
``k8s.py`` navigate the camelCase API field names. A converter that handed the
engine snake_case would make every rule find nothing against a real cluster, and
``kube-sentinel cluster`` would print "No findings" and report a perfect score on
a cluster full of privileged containers.

``cluster.py`` uses ``ApiClient.sanitize_for_serialization``, which emits the
camelCase API field names (unlike ``to_dict()``) and drops unset fields. These
tests pin that: the fixtures are built as real client model objects and pushed
through ``cluster.py``'s own ``_to_dict``/``_to_resource``, so the expected shape
comes from the library rather than from an assumption about it. If someone
swaps in ``to_dict()`` for being the more obvious call, these tests fail.

The spread covers all three rule packs — a privileged Deployment (workload), a
cluster-admin ClusterRoleBinding (RBAC), and a NodePort Service (networking) —
and the three are scanned as one set so the cross-resource rules run too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kube_sentinel.engine import scan_resources
from kube_sentinel.models import Resource
from kube_sentinel.parser import parse_path

# The parity check is only meaningful against the real client: the whole point is
# to derive the fixture from the library instead of trusting a hand-written dict.
# Installed via the `cluster` extra, which CI installs alongside `dev`.
kubernetes = pytest.importorskip("kubernetes", reason="requires the 'cluster' extra")

from kube_sentinel.cluster import _to_dict, _to_resource  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
INSECURE = REPO_ROOT / "examples" / "insecure"


def _yaml_resource(file_name: str, kind: str, name: str) -> Resource:
    """Pull one document out of an examples/insecure manifest by kind and name."""
    result = parse_path(INSECURE / file_name)
    matches = [r for r in result.resources if r.kind == kind and r.name == name]
    assert len(matches) == 1, f"expected exactly one {kind}/{name} in {file_name}"
    return matches[0]


def _live_resource(kind: str, api_version: str, model: object) -> Resource:
    """Serialise a client model object exactly as a live scan does.

    Routed through ``cluster.py``'s own helpers rather than reimplemented, so the
    test breaks if the conversion changes rather than silently testing a copy.
    """
    return _to_resource(kind, api_version, _to_dict(model), None)


# --- Fixtures built as real client model objects ---------------------------
#
# Each mirrors the correspondingly named document in examples/insecure. Fields
# are set with the client's snake_case constructor arguments, which is how the
# client itself would deliver an object fetched from the API.


def _live_privileged_deployment() -> Resource:
    """The `web` Deployment from examples/insecure/workloads.yaml."""
    k = kubernetes.client
    deployment = k.V1Deployment(
        api_version="apps/v1",
        kind="Deployment",
        metadata=k.V1ObjectMeta(name="web", namespace="demo"),
        spec=k.V1DeploymentSpec(
            replicas=2,
            selector=k.V1LabelSelector(match_labels={"app": "web"}),
            template=k.V1PodTemplateSpec(
                metadata=k.V1ObjectMeta(labels={"app": "web"}),
                spec=k.V1PodSpec(
                    host_network=True,
                    host_pid=True,
                    containers=[
                        k.V1Container(
                            name="web",
                            image="nginx:latest",
                            security_context=k.V1SecurityContext(
                                privileged=True,
                                allow_privilege_escalation=True,
                                run_as_user=0,
                                capabilities=k.V1Capabilities(add=["SYS_ADMIN", "NET_ADMIN"]),
                            ),
                            ports=[k.V1ContainerPort(container_port=80)],
                            volume_mounts=[k.V1VolumeMount(name="host-root", mount_path="/host")],
                        )
                    ],
                    volumes=[
                        k.V1Volume(
                            name="host-root",
                            host_path=k.V1HostPathVolumeSource(path="/"),
                        )
                    ],
                ),
            ),
        ),
    )
    return _live_resource("Deployment", "apps/v1", deployment)


def _live_cluster_admin_binding() -> Resource:
    """The `dangerous-admin-binding` ClusterRoleBinding from examples/insecure/rbac.yaml."""
    k = kubernetes.client
    binding = k.V1ClusterRoleBinding(
        api_version="rbac.authorization.k8s.io/v1",
        kind="ClusterRoleBinding",
        metadata=k.V1ObjectMeta(name="dangerous-admin-binding"),
        role_ref=k.V1RoleRef(
            api_group="rbac.authorization.k8s.io",
            kind="ClusterRole",
            name="cluster-admin",
        ),
        subjects=[
            k.RbacV1Subject(kind="ServiceAccount", name="default", namespace="demo"),
        ],
    )
    return _live_resource("ClusterRoleBinding", "rbac.authorization.k8s.io/v1", binding)


def _live_nodeport_service() -> Resource:
    """The `web-nodeport` Service from examples/insecure/networking.yaml."""
    k = kubernetes.client
    service = k.V1Service(
        api_version="v1",
        kind="Service",
        metadata=k.V1ObjectMeta(name="web-nodeport", namespace="demo"),
        spec=k.V1ServiceSpec(
            type="NodePort",
            selector={"app": "web"},
            ports=[k.V1ServicePort(port=80, target_port=80, node_port=30080)],
        ),
    )
    return _live_resource("Service", "v1", service)


# --- The shape assertions --------------------------------------------------


def test_serialised_pod_spec_uses_camel_case_api_field_names() -> None:
    """The conversion must emit API field names, not the model's snake_case attrs.

    Asserted directly as well as via rule parity, because this is the exact
    thing a well-meaning refactor to ``to_dict()`` would break, and the failure
    mode is silence rather than an error.
    """
    pod_spec = _live_privileged_deployment().raw["spec"]["template"]["spec"]

    assert "hostNetwork" in pod_spec
    assert "hostPID" in pod_spec
    assert "host_network" not in pod_spec
    assert "host_pid" not in pod_spec

    security_context = pod_spec["containers"][0]["securityContext"]
    assert "allowPrivilegeEscalation" in security_context
    assert "allow_privilege_escalation" not in security_context


def test_unset_fields_are_dropped_rather_than_serialised_as_none() -> None:
    """``sanitize_for_serialization`` omits unset fields; ``to_dict()`` keeps them as None.

    This matters because several rules distinguish "absent" from "set to a falsy
    value" — ``effective_run_as_non_root`` returns None only when no context sets
    the key at all, so a dict full of explicit nulls would answer differently.
    """
    pod_spec = _live_nodeport_service().raw["spec"]

    assert "loadBalancerIP" not in pod_spec
    assert all(value is not None for value in pod_spec.values())


# --- The parity assertions ------------------------------------------------


@pytest.mark.parametrize(
    ("file_name", "kind", "name", "build_live"),
    [
        ("workloads.yaml", "Deployment", "web", _live_privileged_deployment),
        (
            "rbac.yaml",
            "ClusterRoleBinding",
            "dangerous-admin-binding",
            _live_cluster_admin_binding,
        ),
        ("networking.yaml", "Service", "web-nodeport", _live_nodeport_service),
    ],
)
def test_same_rules_fire_on_yaml_and_live_object(
    file_name: str,
    kind: str,
    name: str,
    build_live: object,
) -> None:
    """A rule that fires on a manifest must fire on the live object too."""
    from_yaml = scan_resources((_yaml_resource(file_name, kind, name),))
    from_cluster = scan_resources((build_live(),))  # type: ignore[operator]

    yaml_ids = {f.rule_id for f in from_yaml.findings}
    cluster_ids = {f.rule_id for f in from_cluster.findings}

    # Guard against a vacuous pass: both sides firing nothing would also be equal.
    assert yaml_ids, f"no rule fired on {kind}/{name} from YAML — fixture is wrong"
    assert cluster_ids == yaml_ids


def test_cross_resource_rules_reach_parity_over_the_whole_set() -> None:
    """Correlation rules see the same cluster as they see the same manifests.

    Scanned as one set rather than one resource at a time: the RBAC/workload
    correlation needs a workload and a binding in view together, and KS-NET-003
    is a property of a namespace rather than of any single object. Those are the
    rules most likely to break on a shape change, since they read fields off
    several objects to join them.
    """
    yaml_set = (
        _yaml_resource("workloads.yaml", "Deployment", "web"),
        _yaml_resource("rbac.yaml", "ClusterRoleBinding", "dangerous-admin-binding"),
        _yaml_resource("networking.yaml", "Service", "web-nodeport"),
    )
    live_set = (
        _live_privileged_deployment(),
        _live_cluster_admin_binding(),
        _live_nodeport_service(),
    )

    from_yaml = scan_resources(yaml_set)
    from_cluster = scan_resources(live_set)

    # Identity as well as rule id: a shape bug could plausibly fire the right
    # rule against the wrong object, which comparing ids alone would not catch.
    def fired(report: object) -> set[tuple[str, str, str, str | None]]:
        return {
            (f.rule_id, f.resource_kind, f.resource_name, f.namespace)
            for f in report.findings  # type: ignore[attr-defined]
        }

    assert fired(from_yaml), "no rule fired over the YAML set — fixture is wrong"
    assert fired(from_cluster) == fired(from_yaml)

    # The score is what a user acts on, so pin that it matches too.
    assert from_cluster.score == from_yaml.score
    assert from_cluster.grade == from_yaml.grade
