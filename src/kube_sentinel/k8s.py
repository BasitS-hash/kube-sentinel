"""Helpers for navigating Kubernetes object structure.

Different workload kinds nest the pod template at different paths. These helpers
normalize access so rules can operate on a single shape regardless of kind.
"""

from __future__ import annotations

from typing import Any

# Kinds that embed a pod template under different paths.
WORKLOAD_KINDS: frozenset[str] = frozenset(
    {
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "ReplicationController",
        "Job",
        "Pod",
    }
)

# Kinds we apply pod-level rules to (workloads + CronJob, which nests deeper).
POD_BEARING_KINDS: frozenset[str] = WORKLOAD_KINDS | frozenset({"CronJob"})


def get_pod_spec(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Return the PodSpec for any pod-bearing object, or None if absent."""
    kind = obj.get("kind", "")
    spec = obj.get("spec")
    if not isinstance(spec, dict):
        return None

    if kind == "Pod":
        return spec

    if kind == "CronJob":
        job_template = spec.get("jobTemplate", {})
        job_spec = job_template.get("spec", {}) if isinstance(job_template, dict) else {}
        template = job_spec.get("template", {}) if isinstance(job_spec, dict) else {}
        pod_spec = template.get("spec") if isinstance(template, dict) else None
        return pod_spec if isinstance(pod_spec, dict) else None

    # Deployment, StatefulSet, DaemonSet, Job, ReplicaSet, ReplicationController.
    template = spec.get("template", {})
    pod_spec = template.get("spec") if isinstance(template, dict) else None
    return pod_spec if isinstance(pod_spec, dict) else None


def get_containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Return regular containers (excludes init/ephemeral)."""
    containers = pod_spec.get("containers", [])
    return [c for c in containers if isinstance(c, dict)]


def get_all_containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Return all containers including init and ephemeral containers."""
    out: list[dict[str, Any]] = []
    for key in ("containers", "initContainers", "ephemeralContainers"):
        for c in pod_spec.get(key, []):
            if isinstance(c, dict):
                out.append(c)
    return out


def container_security_context(container: dict[str, Any]) -> dict[str, Any]:
    """Return a container's securityContext as a dict (empty if missing)."""
    sc = container.get("securityContext")
    return sc if isinstance(sc, dict) else {}


def pod_security_context(pod_spec: dict[str, Any]) -> dict[str, Any]:
    """Return the pod-level securityContext as a dict (empty if missing)."""
    sc = pod_spec.get("securityContext")
    return sc if isinstance(sc, dict) else {}


def effective_run_as_non_root(pod_spec: dict[str, Any], container: dict[str, Any]) -> bool | None:
    """Resolve runAsNonRoot considering pod-level and container-level contexts.

    Container-level wins over pod-level. Returns None when neither sets it.
    """
    c_sc = container_security_context(container)
    if "runAsNonRoot" in c_sc:
        return bool(c_sc["runAsNonRoot"])
    p_sc = pod_security_context(pod_spec)
    if "runAsNonRoot" in p_sc:
        return bool(p_sc["runAsNonRoot"])
    return None


def effective_run_as_user(pod_spec: dict[str, Any], container: dict[str, Any]) -> int | None:
    """Resolve runAsUser considering pod-level and container-level contexts."""
    c_sc = container_security_context(container)
    if "runAsUser" in c_sc:
        value = c_sc["runAsUser"]
        return int(value) if isinstance(value, int) else None
    p_sc = pod_security_context(pod_spec)
    if "runAsUser" in p_sc:
        value = p_sc["runAsUser"]
        return int(value) if isinstance(value, int) else None
    return None


def image_tag(image: str) -> str | None:
    """Extract the tag from an image reference, or None if untagged.

    Handles registry ports (host:5000/image:tag) and digests (image@sha256:...).
    """
    if "@" in image:
        # Digest-pinned images are explicitly versioned.
        return "@digest"
    # Strip the registry/host segment so we don't confuse a port with a tag.
    last_segment = image.rsplit("/", 1)[-1]
    if ":" in last_segment:
        return last_segment.rsplit(":", 1)[-1]
    return None
