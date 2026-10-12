"""Networking and namespace isolation rules.

Covers the NSA/CISA "network separation" mitigations and CIS Section 5.3
(Network Policies and CNI). Includes Service exposure checks and a cluster-level
check for namespaces that lack any NetworkPolicy.
"""

from __future__ import annotations

from collections.abc import Iterator

from .. import k8s
from ..models import Resource, Severity
from .base import CrossHit, ScanContext, build_rule, register

# CIDRs that match every address, i.e. the whole internet. A LoadBalancer
# "scoped" to one of these is not scoped at all.
_OPEN_CIDRS: frozenset[str] = frozenset({"0.0.0.0/0", "::/0"})


def _check_service_exposure(resource: Resource) -> Iterator[str]:
    spec = resource.raw.get("spec", {})
    spec = spec if isinstance(spec, dict) else {}
    svc_type = spec.get("type", "ClusterIP")
    if svc_type == "NodePort":
        yield (
            "Service of type NodePort exposes a port on every node; prefer "
            "ClusterIP behind an Ingress or a scoped LoadBalancer"
        )
    elif svc_type == "LoadBalancer":
        ranges = spec.get("loadBalancerSourceRanges")
        ranges = ranges if isinstance(ranges, list) else []
        if not ranges:
            yield (
                "Service of type LoadBalancer has no loadBalancerSourceRanges; "
                "it may be reachable from the entire internet"
            )
        elif any(str(r).strip() in _OPEN_CIDRS for r in ranges):
            yield (
                "Service of type LoadBalancer allows an open CIDR "
                "(0.0.0.0/0 or ::/0) in loadBalancerSourceRanges; it is "
                "reachable from the entire internet"
            )


def _check_external_ips(resource: Resource) -> Iterator[str]:
    spec = resource.raw.get("spec", {})
    spec = spec if isinstance(spec, dict) else {}
    external_ips = spec.get("externalIPs")
    if external_ips:
        yield (
            f"Service defines externalIPs {external_ips}; this bypasses normal "
            "ingress controls and can hijack traffic"
        )


register(
    build_rule(
        id="KS-NET-001",
        title="Broadly exposed Service",
        severity=Severity.MEDIUM,
        remediation="Use ClusterIP services behind an Ingress with TLS, or restrict "
        "LoadBalancer services with loadBalancerSourceRanges.",
        check=_check_service_exposure,
        cis=("5.3.2",),
        pss=(),
        nsa_cisa=("Network Separation: limit external exposure",),
        mitre_attack=("T1190 Exploit Public-Facing Application",),
        applies_to=frozenset({"Service"}),
    )
)

register(
    build_rule(
        id="KS-NET-002",
        title="Service uses externalIPs",
        severity=Severity.HIGH,
        remediation="Avoid Service.spec.externalIPs. Route external traffic through "
        "a controlled Ingress or LoadBalancer instead.",
        check=_check_external_ips,
        cis=("5.3.2",),
        pss=(),
        nsa_cisa=("Network Separation: control ingress paths",),
        mitre_attack=("T1190 Exploit Public-Facing Application",),
        applies_to=frozenset({"Service"}),
    )
)


def _check_missing_networkpolicy(context: ScanContext) -> Iterator[CrossHit]:
    """Flag namespaces that host workloads but ship no NetworkPolicy.

    Cross-resource because no single object can answer it: a Deployment is not
    at fault for the policy that is missing beside it.
    """
    with_workloads = context.namespaces_of(k8s.POD_BEARING_KINDS)
    with_netpol = context.namespaces_of(frozenset({"NetworkPolicy"}))
    for ns in sorted(with_workloads - with_netpol):
        # Attribute the finding to the first file that touches the namespace,
        # for a stable, useful location in reports.
        file_path = next(
            (r.file_path for r in context.resources if (r.namespace or "default") == ns),
            "<cluster>",
        )
        yield CrossHit(
            message=(
                f"namespace '{ns}' runs workloads but has no NetworkPolicy; "
                "pod-to-pod traffic is unrestricted by default"
            ),
            resource_kind="Namespace",
            resource_name=ns,
            namespace=ns,
            file_path=file_path,
        )


register(
    build_rule(
        id="KS-NET-003",
        title="Namespace without NetworkPolicy",
        severity=Severity.MEDIUM,
        remediation="Apply a default-deny NetworkPolicy per namespace and then "
        "allow only required ingress/egress flows.",
        cross_check=_check_missing_networkpolicy,
        cis=("5.3.2",),
        pss=(),
        nsa_cisa=("Network Separation: default-deny with NetworkPolicies",),
        mitre_attack=("T1046 Network Service Discovery", "T1021 Remote Services"),
    )
)
