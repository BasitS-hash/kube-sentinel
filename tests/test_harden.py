"""Tests for the harden module."""

from __future__ import annotations

from pathlib import Path

import yaml

from kube_sentinel import k8s
from kube_sentinel.engine import scan_resources
from kube_sentinel.harden import harden_resource, harden_to_yaml
from kube_sentinel.models import Resource
from kube_sentinel.parser import parse_path


def _insecure_deployment() -> Resource:
    raw = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "web"},
        "spec": {
            "template": {
                "spec": {
                    "hostNetwork": True,
                    "containers": [
                        {
                            "name": "web",
                            "image": "nginx:1.27",
                            "securityContext": {
                                "privileged": True,
                                "allowPrivilegeEscalation": True,
                                "runAsUser": 0,
                                "capabilities": {"add": ["SYS_ADMIN"]},
                            },
                        }
                    ],
                    "volumes": [{"name": "v", "hostPath": {"path": "/"}}],
                }
            }
        },
    }
    return Resource(
        kind="Deployment",
        name="web",
        namespace="demo",
        api_version="apps/v1",
        file_path="mem://web",
        doc_index=0,
        raw=raw,
    )


def test_harden_does_not_mutate_original() -> None:
    resource = _insecure_deployment()
    original_priv = resource.raw["spec"]["template"]["spec"]["containers"][0]["securityContext"][
        "privileged"
    ]
    harden_resource(resource)
    # Original must be untouched (immutability).
    assert (
        resource.raw["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"]
        == original_priv
    )


def test_harden_applies_restricted_controls() -> None:
    hardened = harden_resource(_insecure_deployment())
    pod_spec = k8s.get_pod_spec(hardened)
    assert pod_spec is not None
    assert "hostNetwork" not in pod_spec
    assert pod_spec["automountServiceAccountToken"] is False
    assert pod_spec["securityContext"]["runAsNonRoot"] is True
    assert pod_spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"

    container = pod_spec["containers"][0]
    sc = container["securityContext"]
    assert sc["privileged"] is False
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["runAsNonRoot"] is True
    assert sc["capabilities"]["drop"] == ["ALL"]
    assert "add" not in sc["capabilities"]


def test_harden_replaces_hostpath_with_emptydir() -> None:
    hardened = harden_resource(_insecure_deployment())
    pod_spec = k8s.get_pod_spec(hardened)
    assert pod_spec is not None
    vol = pod_spec["volumes"][0]
    assert "hostPath" not in vol
    assert vol["emptyDir"] == {}


def test_harden_overrides_unconfined_seccomp() -> None:
    raw = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "p"},
        "spec": {
            "containers": [
                {
                    "name": "c",
                    "image": "nginx:1.27",
                    "securityContext": {"seccompProfile": {"type": "Unconfined"}},
                }
            ]
        },
    }
    resource = Resource(
        kind="Pod",
        name="p",
        namespace="demo",
        api_version="v1",
        file_path="mem://p",
        doc_index=0,
        raw=raw,
    )
    hardened = harden_resource(resource)
    sc = hardened["spec"]["containers"][0]["securityContext"]
    assert sc["seccompProfile"]["type"] == "RuntimeDefault"


def test_harden_to_yaml_is_valid_yaml() -> None:
    text = harden_to_yaml([_insecure_deployment()])
    parsed = list(yaml.safe_load_all(text))
    assert parsed[0]["kind"] == "Deployment"


def test_hardening_insecure_examples_removes_most_findings(insecure_dir: Path) -> None:
    result = parse_path(insecure_dir)
    workloads = [r for r in result.resources if r.kind in k8s.POD_BEARING_KINDS]
    assert workloads

    hardened_resources = []
    for original in workloads:
        hardened_raw = harden_resource(original)
        hardened_resources.append(
            Resource(
                kind=original.kind,
                name=original.name,
                namespace=original.namespace,
                api_version=original.api_version,
                file_path=original.file_path,
                doc_index=original.doc_index,
                raw=hardened_raw,
            )
        )

    before = scan_resources(tuple(workloads))
    after = scan_resources(tuple(hardened_resources))
    # Hardening should sharply reduce findings.
    assert len(after.findings) < len(before.findings)
    # No CRITICAL or HIGH should remain on the workloads after hardening.
    remaining_serious = [
        f
        for f in after.findings
        if f.severity.rank <= 1  # CRITICAL or HIGH
    ]
    assert not remaining_serious, [f.message for f in remaining_serious]
