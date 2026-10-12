"""Scan engine: runs the rule pack over a set of resources and scores results.

The engine is decoupled from input source (files vs. live cluster) and from
output format. It takes resources, produces findings, and computes a posture
score and letter grade.

It knows nothing about individual rules. Per-resource rules are run once per
resource; cross-resource rules are run once over a ``ScanContext`` holding the
whole set. Both kinds come out of the same registry, so the reported rule count
is simply its size.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .models import Finding, Resource, Severity
from .rules import load_default_rules
from .rules.base import Rule, ScanContext

# A perfect scan starts at 100 and loses points per finding by severity weight,
# floored at 0. This is a deliberately simple, explainable scoring model.
MAX_SCORE = 100


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

    # Correlation rules need every resource at once. Everything they read comes
    # off the context, so adding one never touches the engine.
    context = ScanContext(resources=resources)
    for rule in active_rules:
        findings.extend(rule.evaluate_context(context))

    findings.sort(key=_sort_key)
    severity_counts = Counter(f.severity for f in findings)

    return ScanReport(
        findings=tuple(findings),
        resource_count=len(resources),
        rule_count=len(active_rules),
        severity_counts=dict(severity_counts),
    )
