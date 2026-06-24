"""Generate hardened manifests / securityContext patches.

Given a parsed resource, produce a deep-copied, hardened version that satisfies
the restricted Pod Security Standard: non-root, no privilege escalation, dropped
capabilities, read-only root filesystem, and a seccomp profile.
"""

from __future__ import annotations

import copy
from typing import Any

import yaml

from . import k8s
from .models import Resource

# A safe, non-zero default UID for the hardened pod-level securityContext.
DEFAULT_NON_ROOT_UID = 10001

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


def _harden_pod_spec(pod_spec: dict[str, Any]) -> None:
    """Mutate a (copied) pod spec in place to satisfy the restricted profile."""
    # Pod-level securityContext.
    pod_sc = pod_spec.get("securityContext")
    pod_sc = pod_sc if isinstance(pod_sc, dict) else {}
    for key, value in HARDENED_POD_SECURITY_CONTEXT.items():
        pod_sc.setdefault(key, copy.deepcopy(value))
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
        for container in pod_spec.get(key, []):
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

    caps = sc.get("capabilities")
    caps = caps if isinstance(caps, dict) else {}
    caps["drop"] = ["ALL"]
    caps.pop("add", None)
    sc["capabilities"] = caps

    # Force a confined seccomp profile, overriding Unconfined if present.
    profile = sc.get("seccompProfile")
    if not isinstance(profile, dict) or profile.get("type") in (None, "Unconfined"):
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
