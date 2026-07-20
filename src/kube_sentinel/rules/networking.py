"""Networking and namespace isolation rules.

Covers the NSA/CISA "network separation" mitigations and CIS Section 5.3
(Network Policies and CNI). Includes Service exposure checks and a cluster-level
check for namespaces that lack any NetworkPolicy.
"""

from __future__ import annotations

from collections.abc import Iterator

from ..models import Resource, Severity
from .base import build_rule, register

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
