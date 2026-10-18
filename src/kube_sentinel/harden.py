"""Generate hardened manifests / securityContext patches.

Given a parsed resource, produce a deep-copied, hardened version that satisfies
the restricted Pod Security Standard: non-root, no privilege escalation, dropped
capabilities, read-only root filesystem, and a seccomp profile.

Pod specs are all this rewrites. Resources without one — Roles, bindings,
Services — are passed through untouched, and nothing here can invent a
NetworkPolicy for a namespace it was never handed, so hardened output still
carries RBAC and networking findings. It also leaves what restricted PSS does
not govern: image tags, probes, and a half-specified resources block.
``tests/test_harden_boundary.py`` pins that boundary against the rule pack, and
the README documents it under "What ``harden`` does not touch".
"""

from __future__ import annotations

import copy
from typing import Any

import yaml

from . import k8s
from .models import Resource

# A safe, non-zero default UID for the hardened pod-level securityContext.
DEFAULT_NON_ROOT_UID = 10001

# The only seccomp profile types the restricted profile accepts.
CONFINED_SECCOMP_TYPES: frozenset[str] = frozenset({"RuntimeDefault", "Localhost"})

HARDENED_POD_SECURITY_CONTEXT: dict[str, Any] = {
    "runAsNonRoot": True,
    "runAsUser": DEFAULT_NON_ROOT_UID,
    "runAsGroup": DEFAULT_NON_ROOT_UID,
    "fsGroup": DEFAULT_NON_ROOT_UID,
    "seccompProfile": {"type": "RuntimeDefault"},
}

HARDENED_CONTAINER_SECURITY_CONTEXT: dict[str, Any] = {
    "allowPrivilegeEscalation": False,
    "privileged": False,
    "readOnlyRootFilesystem": True,
    "runAsNonRoot": True,
    "capabilities": {"drop": ["ALL"]},
    "seccompProfile": {"type": "RuntimeDefault"},
}


def _is_confined_seccomp(profile: Any) -> bool:
    """Whether a seccompProfile is one the restricted profile accepts."""
    return isinstance(profile, dict) and profile.get("type") in CONFINED_SECCOMP_TYPES


def _harden_pod_spec(pod_spec: dict[str, Any]) -> None:
    """Mutate a (copied) pod spec in place to satisfy the restricted profile."""
    # Pod-level securityContext. setdefault is right for the fields where the
    # manifest's own value is a legitimate choice — a deliberate non-zero UID,
    # a particular fsGroup — but it must not be allowed to preserve the three
    # values below. Each is a restricted-PSS violation in its own right, and
    # leaving one in place while _harden_container forces the container-level
    # opposite emits a pod that contradicts itself: runAsUser: 0 under
    # runAsNonRoot: true is rejected by the kubelet at startup, so the output
    # would be both non-compliant and unschedulable.
    pod_sc = pod_spec.get("securityContext")
    pod_sc = pod_sc if isinstance(pod_sc, dict) else {}
    for key, value in HARDENED_POD_SECURITY_CONTEXT.items():
        pod_sc.setdefault(key, copy.deepcopy(value))
    if pod_sc.get("runAsNonRoot") is not True:
        pod_sc["runAsNonRoot"] = True
    if pod_sc.get("runAsUser") == 0:
        pod_sc["runAsUser"] = DEFAULT_NON_ROOT_UID
    if not _is_confined_seccomp(pod_sc.get("seccompProfile")):
        pod_sc["seccompProfile"] = {"type": "RuntimeDefault"}
    pod_spec["securityContext"] = pod_sc

    # Remove host namespace sharing.
    for field_name in ("hostNetwork", "hostPID", "hostIPC"):
        pod_spec.pop(field_name, None)

    # Disable token automount unless the app clearly uses the API.
    pod_spec.setdefault("automountServiceAccountToken", False)

    # Drop hostPath volumes (replace with an emptyDir of the same name).
    volumes = pod_spec.get("volumes")
    if isinstance(volumes, list):
        for vol in volumes:
            if isinstance(vol, dict) and "hostPath" in vol:
                vol.pop("hostPath", None)
                vol["emptyDir"] = {}

    for key in ("containers", "initContainers", "ephemeralContainers"):
        containers = pod_spec.get(key)
        if not isinstance(containers, list):
            continue
        for container in containers:
            if isinstance(container, dict):
                _harden_container(container)


def _harden_container(container: dict[str, Any]) -> None:
    sc = container.get("securityContext")
    sc = sc if isinstance(sc, dict) else {}

    # Force the secure values (override unsafe existing ones).
    sc["allowPrivilegeEscalation"] = False
    sc["privileged"] = False
    sc["readOnlyRootFilesystem"] = True
    sc["runAsNonRoot"] = True

    # An explicit runAsUser: 0 is forbidden by the restricted profile, and the
    # runAsNonRoot: true just set above would make the kubelet refuse to start
    # the container. A non-zero UID the manifest chose is left alone.
    if sc.get("runAsUser") == 0:
        sc["runAsUser"] = DEFAULT_NON_ROOT_UID

    caps = sc.get("capabilities")
    caps = caps if isinstance(caps, dict) else {}
    caps["drop"] = ["ALL"]
    caps.pop("add", None)
    sc["capabilities"] = caps

    # Force a confined seccomp profile, overriding Unconfined if present.
    if not _is_confined_seccomp(sc.get("seccompProfile")):
        sc["seccompProfile"] = {"type": "RuntimeDefault"}
    container["securityContext"] = sc

    # Add modest resource requests/limits if entirely missing.
    if "resources" not in container or not container.get("resources"):
        container["resources"] = {
            "requests": {"cpu": "100m", "memory": "128Mi"},
            "limits": {"cpu": "500m", "memory": "256Mi"},
        }


def harden_resource(resource: Resource) -> dict[str, Any]:
    """Return a hardened deep copy of a resource's raw document."""
    hardened = copy.deepcopy(resource.raw)
    pod_spec = k8s.get_pod_spec(hardened)
    if pod_spec is not None:
        _harden_pod_spec(pod_spec)
    return hardened


def harden_to_yaml(resources: list[Resource]) -> str:
    """Harden one or more resources and serialize them back to multi-doc YAML."""
    hardened_docs = [harden_resource(r) for r in resources]
    return yaml.safe_dump_all(
        hardened_docs,
        default_flow_style=False,
        sort_keys=False,
    )
