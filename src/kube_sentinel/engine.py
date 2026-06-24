"""Scan engine: runs the rule pack over a set of resources and scores results.

The engine is decoupled from input source (files vs. live cluster) and from
output format. It takes resources, produces findings, and computes a posture
score and letter grade.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .models import ComplianceMapping, Finding, Resource, Severity
from .rules import load_default_rules
from .rules.base import Rule

# A perfect scan starts at 100 and loses points per finding by severity weight,
# floored at 0. This is a deliberately simple, explainable scoring model.
MAX_SCORE = 100

# Cross-resource check identity (namespaces lacking a NetworkPolicy).
NETPOL_RULE_ID = "KS-NET-003"
_NETPOL_MAPPING = ComplianceMapping(
    cis=("5.3.2",),
    pss=(),
    nsa_cisa=("Network Separation: default-deny with NetworkPolicies",),
    mitre_attack=("T1046 Network Service Discovery", "T1021 Remote Services"),
)


@dataclass(frozen=True)
class ScanReport:
    """The full result of a scan."""

    findings: tuple[Finding, ...]
    resource_count: int
    rule_count: int
    severity_counts: dict[Severity, int] = field(default_factory=dict)

    @property
    def score(self) -> int:
        penalty = sum(f.severity.weight for f in self.findings)
        return max(0, MAX_SCORE - penalty)

    @property
    def grade(self) -> str:
        return score_to_grade(self.score)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def count(self, severity: Severity) -> int:
        return self.severity_counts.get(severity, 0)


def score_to_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _sort_key(finding: Finding) -> tuple[int, str, str, str]:
    return (
        finding.severity.rank,
        finding.file_path,
        finding.resource_name,
        finding.rule_id,
    )


def _namespaces_with_workloads(resources: tuple[Resource, ...]) -> set[str]:
    workload_like = {
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "Pod",
        "Job",
        "CronJob",
    }
    out: set[str] = set()
    for r in resources:
        if r.kind in workload_like:
            out.add(r.namespace or "default")
    return out


def _namespaces_with_netpol(resources: tuple[Resource, ...]) -> set[str]:
    return {(r.namespace or "default") for r in resources if r.kind == "NetworkPolicy"}


def _missing_netpol_findings(resources: tuple[Resource, ...]) -> list[Finding]:
    """Flag namespaces that host workloads but have no NetworkPolicy."""
    with_workloads = _namespaces_with_workloads(resources)
    with_netpol = _namespaces_with_netpol(resources)
    missing = sorted(with_workloads - with_netpol)
    findings: list[Finding] = []
    for ns in missing:
        # Attribute the finding to the first file that touches the namespace,
        # for a stable, useful location in reports.
        file_path = next(
            (r.file_path for r in resources if (r.namespace or "default") == ns),
            "<cluster>",
        )
        findings.append(
            Finding(
                rule_id=NETPOL_RULE_ID,
                title="Namespace without NetworkPolicy",
                severity=Severity.MEDIUM,
                message=(
                    f"namespace '{ns}' runs workloads but has no NetworkPolicy; "
                    "pod-to-pod traffic is unrestricted by default"
                ),
                remediation=(
                    "Apply a default-deny NetworkPolicy per namespace and then "
                    "allow only required ingress/egress flows."
                ),
                resource_kind="Namespace",
                resource_name=ns,
                namespace=ns,
                file_path=file_path,
                mapping=_NETPOL_MAPPING,
            )
        )
    return findings


def scan_resources(
    resources: tuple[Resource, ...],
    rules: list[Rule] | None = None,
) -> ScanReport:
    """Run the rule pack over resources and produce a scored report."""
    active_rules = rules if rules is not None else load_default_rules()

    findings: list[Finding] = []
    for resource in resources:
        for rule in active_rules:
            findings.extend(rule.evaluate(resource))

    # Cross-resource checks operate on the whole set.
    findings.extend(_missing_netpol_findings(resources))

    findings.sort(key=_sort_key)
    severity_counts = Counter(f.severity for f in findings)

    return ScanReport(
        findings=tuple(findings),
        resource_count=len(resources),
        rule_count=len(active_rules) + 1,  # +1 for the cross-resource netpol check
        severity_counts=dict(severity_counts),
    )
