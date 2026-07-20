"""Workload security rules for pod-bearing resources.

Covers Pod Security Standards (baseline + restricted), CIS Section 5.2, and the
NSA/CISA "least privilege" and "immutable filesystem" mitigations. Each rule
operates on a single resource and yields human-readable messages.
"""

from __future__ import annotations

from collections.abc import Iterator

from .. import k8s
from ..models import Resource, Severity
from .base import build_rule, register

# Capabilities widely considered dangerous if added back to a container.
DANGEROUS_CAPS: frozenset[str] = frozenset(
    {
        "ALL",
        "SYS_ADMIN",
        "NET_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "SYS_RAWIO",
        "SYS_BOOT",
        "NET_RAW",
        "DAC_READ_SEARCH",
        "BPF",
        "PERFMON",
    }
)

_POD = k8s.POD_BEARING_KINDS


def _pod_and_containers(
    resource: Resource,
) -> tuple[dict, list[dict]]:
    spec = k8s.get_pod_spec(resource.raw)
    if spec is None:
        return {}, []
    return spec, k8s.get_all_containers(spec)


def _check_privileged(resource: Resource) -> Iterator[str]:
    _spec, containers = _pod_and_containers(resource)
    for c in containers:
        sc = k8s.container_security_context(c)
        if sc.get("privileged") is True:
            yield f"container '{c.get('name', '?')}' runs in privileged mode"


def _check_privilege_escalation(resource: Resource) -> Iterator[str]:
    _spec, containers = _pod_and_containers(resource)
    for c in containers:
        sc = k8s.container_security_context(c)
        if sc.get("allowPrivilegeEscalation") is not False:
            yield (f"container '{c.get('name', '?')}' does not set allowPrivilegeEscalation: false")


def _check_run_as_non_root(resource: Resource) -> Iterator[str]:
    spec, containers = _pod_and_containers(resource)
    for c in containers:
        non_root = k8s.effective_run_as_non_root(spec, c)
        run_as_user = k8s.effective_run_as_user(spec, c)
        if non_root is True:
            continue
        if run_as_user is not None and run_as_user != 0:
            continue
        if run_as_user == 0:
            yield f"container '{c.get('name', '?')}' explicitly runs as root (runAsUser: 0)"
        else:
            yield (
                f"container '{c.get('name', '?')}' may run as root: "
                "neither runAsNonRoot: true nor a non-zero runAsUser is set"
            )


def _check_read_only_root_fs(resource: Resource) -> Iterator[str]:
    _spec, containers = _pod_and_containers(resource)
    for c in containers:
        sc = k8s.container_security_context(c)
        if sc.get("readOnlyRootFilesystem") is not True:
            yield (f"container '{c.get('name', '?')}' does not set readOnlyRootFilesystem: true")


def _check_drop_capabilities(resource: Resource) -> Iterator[str]:
    _spec, containers = _pod_and_containers(resource)
    for c in containers:
        sc = k8s.container_security_context(c)
        caps = sc.get("capabilities", {})
        caps = caps if isinstance(caps, dict) else {}
        drop = {str(x).upper() for x in caps.get("drop", []) if isinstance(x, str)}
        if "ALL" not in drop:
            yield (
                f"container '{c.get('name', '?')}' does not drop ALL capabilities "
                f"(drop: {sorted(drop) or 'none'})"
            )


def _check_added_capabilities(resource: Resource) -> Iterator[str]:
    _spec, containers = _pod_and_containers(resource)
    for c in containers:
        sc = k8s.container_security_context(c)
        caps = sc.get("capabilities", {})
        caps = caps if isinstance(caps, dict) else {}
        added = {str(x).upper() for x in caps.get("add", []) if isinstance(x, str)}
        dangerous = sorted(added & DANGEROUS_CAPS)
        if dangerous:
            yield (
                f"container '{c.get('name', '?')}' adds dangerous "
                f"capabilities: {', '.join(dangerous)}"
            )


def _check_missing_security_context(resource: Resource) -> Iterator[str]:
    _spec, containers = _pod_and_containers(resource)
    for c in containers:
        if not k8s.container_security_context(c):
            yield f"container '{c.get('name', '?')}' has no securityContext defined"


def _check_host_namespaces(resource: Resource) -> Iterator[str]:
    spec, _ = _pod_and_containers(resource)
    for field_name in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(field_name) is True:
            yield f"pod sets {field_name}: true, sharing the host namespace"


def _check_host_path(resource: Resource) -> Iterator[str]:
    spec, _ = _pod_and_containers(resource)
    volumes = spec.get("volumes")
    if not isinstance(volumes, list):
        return
    for vol in volumes:
        if isinstance(vol, dict) and "hostPath" in vol:
            host_path = vol.get("hostPath", {})
            path = host_path.get("path", "?") if isinstance(host_path, dict) else "?"
            yield (
                f"volume '{vol.get('name', '?')}' mounts hostPath '{path}' from the node filesystem"
            )


def _check_resources(resource: Resource) -> Iterator[str]:
    _spec, containers = _pod_and_containers(resource)
    for c in containers:
        res = c.get("resources", {})
        res = res if isinstance(res, dict) else {}
        reqs = res.get("requests", {})
        limits = res.get("limits", {})
        missing = []
        if not (isinstance(reqs, dict) and reqs.get("cpu") and reqs.get("memory")):
            missing.append("requests")
        if not (isinstance(limits, dict) and limits.get("cpu") and limits.get("memory")):
            missing.append("limits")
        if missing:
            yield (
                f"container '{c.get('name', '?')}' is missing CPU/memory "
                f"resource {' and '.join(missing)}"
            )


def _check_image_tag(resource: Resource) -> Iterator[str]:
    _spec, containers = _pod_and_containers(resource)
    for c in containers:
        image = c.get("image")
        if not isinstance(image, str) or not image:
            yield f"container '{c.get('name', '?')}' has no image specified"
            continue
        tag = k8s.image_tag(image)
        if tag is None:
            yield f"container '{c.get('name', '?')}' uses an untagged image '{image}'"
        elif tag == "latest":
            yield f"container '{c.get('name', '?')}' uses the mutable ':latest' tag"


def _check_probes(resource: Resource) -> Iterator[str]:
    # CronJob/Job/Pod workloads are short-lived or one-off; probes matter most
    # for long-running, restartable controllers.
    if resource.kind not in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
        return
    spec = k8s.get_pod_spec(resource.raw)
    if spec is None:
        return
    for c in k8s.get_containers(spec):
        missing = [p for p in ("livenessProbe", "readinessProbe") if p not in c]
        if missing:
            yield (f"container '{c.get('name', '?')}' is missing {' and '.join(missing)}")


def _check_automount_token(resource: Resource) -> Iterator[str]:
    spec, _ = _pod_and_containers(resource)
    if not spec:
        return
    # Default is true; flag only when not explicitly disabled.
    if spec.get("automountServiceAccountToken") is not False:
        yield (
            "pod does not disable automountServiceAccountToken; the SA token "
            "is mounted into every container by default"
        )


def _check_seccomp(resource: Resource) -> Iterator[str]:
    spec, containers = _pod_and_containers(resource)
    if not spec:
        return
    pod_sc = k8s.pod_security_context(spec)
    pod_profile = pod_sc.get("seccompProfile", {})
    pod_type = pod_profile.get("type") if isinstance(pod_profile, dict) else None
    for c in containers:
        c_sc = k8s.container_security_context(c)
        c_profile = c_sc.get("seccompProfile", {})
        c_type = c_profile.get("type") if isinstance(c_profile, dict) else None
        effective = c_type or pod_type
        if effective is None:
            yield (
                f"container '{c.get('name', '?')}' has no seccompProfile "
                "(should be RuntimeDefault or Localhost)"
            )
        elif effective == "Unconfined":
            yield f"container '{c.get('name', '?')}' uses seccompProfile: Unconfined"


# --- Registration ----------------------------------------------------------

register(
    build_rule(
        id="KS-WL-001",
        title="Privileged container",
        severity=Severity.CRITICAL,
        remediation="Remove 'privileged: true' from the container securityContext. "
        "Privileged containers can access all host devices and effectively own the node.",
        check=_check_privileged,
        cis=("5.2.5",),
        pss=("baseline:Privileged Containers", "restricted"),
        nsa_cisa=("Pod Security: prevent privileged containers",),
        mitre_attack=("T1611 Escape to Host",),
        applies_to=_POD,
    )
)

register(
    build_rule(
        id="KS-WL-002",
        title="Privilege escalation not disabled",
        severity=Severity.HIGH,
        remediation="Set securityContext.allowPrivilegeEscalation: false on every "
        "container to prevent gaining more privileges than the parent process.",
        check=_check_privilege_escalation,
        cis=("5.2.6",),
        pss=("restricted:Privilege Escalation",),
        nsa_cisa=("Pod Security: run with least privilege",),
        mitre_attack=("T1548 Abuse Elevation Control Mechanism",),
        applies_to=_POD,
    )
)

register(
    build_rule(
        id="KS-WL-003",
        title="Container may run as root",
        severity=Severity.HIGH,
        remediation="Set runAsNonRoot: true and a non-zero runAsUser at the pod or "
        "container level. Build images that run as an unprivileged user.",
        check=_check_run_as_non_root,
        cis=("5.2.6",),
        pss=("restricted:Running as Non-root",),
        nsa_cisa=("Pod Security: run containers as non-root",),
        mitre_attack=("T1610 Deploy Container",),
        applies_to=_POD,
    )
)

register(
    build_rule(
        id="KS-WL-004",
        title="Root filesystem is writable",
        severity=Severity.MEDIUM,
        remediation="Set securityContext.readOnlyRootFilesystem: true and mount "
        "writable emptyDir volumes only where the app genuinely needs to write.",
        check=_check_read_only_root_fs,
        cis=("5.2.12",),
        pss=("restricted",),
        nsa_cisa=("Pod Security: use immutable container filesystems",),
        mitre_attack=("T1222 File and Directory Permissions Modification",),
        applies_to=_POD,
    )
)

register(
    build_rule(
        id="KS-WL-005",
        title="Capabilities not dropped",
        severity=Severity.MEDIUM,
        remediation="Drop ALL capabilities (capabilities.drop: [ALL]) and add back "
        "only the specific ones required (e.g. NET_BIND_SERVICE).",
        check=_check_drop_capabilities,
        cis=("5.2.9",),
        pss=("restricted:Capabilities",),
        nsa_cisa=("Pod Security: run with least privilege",),
        mitre_attack=("T1548 Abuse Elevation Control Mechanism",),
        applies_to=_POD,
    )
)

register(
    build_rule(
        id="KS-WL-006",
        title="Dangerous capability added",
        severity=Severity.HIGH,
        remediation="Remove dangerous added capabilities (SYS_ADMIN, NET_ADMIN, "
        "SYS_PTRACE, etc.). These enable host access and container escape.",
        check=_check_added_capabilities,
        cis=("5.2.9",),
        pss=("baseline:Capabilities",),
        nsa_cisa=("Pod Security: restrict breakout capabilities",),
        mitre_attack=("T1611 Escape to Host",),
        applies_to=_POD,
    )
)

register(
    build_rule(
        id="KS-WL-007",
        title="Missing container securityContext",
        severity=Severity.MEDIUM,
        remediation="Define a securityContext for every container with non-root, "
        "no privilege escalation, dropped capabilities, and a read-only root FS.",
        check=_check_missing_security_context,
        cis=("5.2.1",),
        pss=("restricted",),
        nsa_cisa=("Pod Security: run with least privilege",),
        mitre_attack=("T1610 Deploy Container",),
        applies_to=_POD,
    )
)

register(
    build_rule(
        id="KS-WL-008",
        title="Host namespace sharing",
        severity=Severity.HIGH,
        remediation="Remove hostNetwork/hostPID/hostIPC. Sharing host namespaces "
        "breaks pod isolation and exposes other processes on the node.",
        check=_check_host_namespaces,
        cis=("5.2.2", "5.2.3", "5.2.4"),
        pss=("baseline:Host Namespaces",),
        nsa_cisa=("Pod Security: isolate host namespaces",),
        mitre_attack=("T1610 Deploy Container", "T1611 Escape to Host"),
        applies_to=_POD,
    )
)

register(
    build_rule(
        id="KS-WL-009",
        title="hostPath volume mount",
        severity=Severity.HIGH,
        remediation="Replace hostPath volumes with emptyDir, PersistentVolumeClaims, "
        "or CSI volumes. hostPath can read/write the node filesystem.",
        check=_check_host_path,
        cis=("5.2.10",),
        pss=("baseline:HostPath Volumes", "restricted:Volume Types"),
        nsa_cisa=("Pod Security: prevent host filesystem mounts",),
        mitre_attack=("T1610 Deploy Container", "T1006 Direct Volume Access"),
        applies_to=_POD,
    )
)

register(
    build_rule(
        id="KS-WL-010",
        title="Missing resource requests/limits",
        severity=Severity.LOW,
        remediation="Set resources.requests and resources.limits for CPU and memory "
        "to prevent noisy-neighbour starvation and resource-exhaustion DoS.",
        check=_check_resources,
        cis=("5.7.3",),
        pss=(),
        nsa_cisa=("Resource limits to mitigate denial of service",),
        mitre_attack=("T1499 Endpoint Denial of Service",),
        applies_to=_POD,
    )
)

register(
    build_rule(
        id="KS-WL-011",
        title="Mutable or untagged image",
        severity=Severity.MEDIUM,
        remediation="Pin images to an immutable tag or digest (image@sha256:...). "
        "':latest' and untagged images make deployments non-reproducible.",
        check=_check_image_tag,
        cis=(),
        pss=(),
        nsa_cisa=("Scan images and use trusted, pinned image sources",),
        mitre_attack=("T1525 Implant Internal Image",),
        applies_to=_POD,
    )
)

register(
    build_rule(
        id="KS-WL-012",
        title="Missing liveness/readiness probe",
        severity=Severity.LOW,
        remediation="Add livenessProbe and readinessProbe so the platform can "
        "detect hung or not-ready containers and route traffic safely.",
        check=_check_probes,
        cis=(),
        pss=(),
        nsa_cisa=("Operational resilience",),
        mitre_attack=(),
        applies_to=frozenset({"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}),
    )
)

register(
    build_rule(
        id="KS-WL-013",
        title="Service account token auto-mounted",
        severity=Severity.MEDIUM,
        remediation="Set automountServiceAccountToken: false on the pod (or service "
        "account) unless the workload calls the Kubernetes API.",
        check=_check_automount_token,
        cis=("5.1.6",),
        pss=(),
        nsa_cisa=("Authentication: limit token exposure",),
        mitre_attack=("T1528 Steal Application Access Token",),
        applies_to=_POD,
    )
)

register(
    build_rule(
        id="KS-WL-014",
        title="Missing or unconfined seccomp profile",
        severity=Severity.MEDIUM,
        remediation="Set securityContext.seccompProfile.type to RuntimeDefault (or "
        "Localhost). Avoid Unconfined, which disables syscall filtering.",
        check=_check_seccomp,
        cis=("5.2.1",),
        pss=("baseline:Seccomp", "restricted:Seccomp"),
        nsa_cisa=("Pod Security: restrict syscalls with seccomp",),
        mitre_attack=("T1611 Escape to Host",),
        applies_to=_POD,
    )
)
