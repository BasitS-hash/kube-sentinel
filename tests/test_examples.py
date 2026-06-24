"""End-to-end assertions against the shipped example manifests.

These are the headline tests: the insecure set must trip a broad range of rules,
and the hardened set must come back clean.
"""

from __future__ import annotations

from pathlib import Path

from kube_sentinel.engine import scan_resources
from kube_sentinel.models import Severity
from kube_sentinel.parser import parse_path


def _scan(path: Path):
    result = parse_path(path)
    assert not result.errors, f"unexpected parse errors: {result.errors}"
    return scan_resources(result.resources)


def test_insecure_examples_are_flagged(insecure_dir: Path) -> None:
    report = _scan(insecure_dir)

    # The insecure set should be heavily flagged across categories.
    assert len(report.findings) >= 30
    assert report.count(Severity.CRITICAL) >= 3
    assert report.count(Severity.HIGH) >= 10
    assert report.score == 0
    assert report.grade == "F"


def test_insecure_examples_cover_each_rule_family(insecure_dir: Path) -> None:
    report = _scan(insecure_dir)
    triggered = {f.rule_id for f in report.findings}

    # At least one workload, RBAC, and networking rule each must fire.
    assert any(r.startswith("KS-WL-") for r in triggered)
    assert any(r.startswith("KS-RBAC-") for r in triggered)
    assert any(r.startswith("KS-NET-") for r in triggered)


def test_specific_critical_rules_fire(insecure_dir: Path) -> None:
    report = _scan(insecure_dir)
    triggered = {f.rule_id for f in report.findings}

    expected = {
        "KS-WL-001",  # privileged
        "KS-WL-006",  # dangerous caps
        "KS-WL-008",  # host namespaces
        "KS-WL-009",  # hostPath
        "KS-RBAC-001",  # wildcard
        "KS-RBAC-004",  # cluster-admin binding
        "KS-RBAC-005",  # anonymous binding
        "KS-NET-001",  # nodeport/lb
        "KS-NET-002",  # externalIPs
        "KS-NET-003",  # missing netpol
    }
    missing = expected - triggered
    assert not missing, f"expected these rules to fire: {missing}"


def test_hardened_examples_are_clean(hardened_dir: Path) -> None:
    report = _scan(hardened_dir)

    assert not report.has_findings, [f.as_dict() for f in report.findings]
    assert report.score == 100
    assert report.grade == "A+"


def test_findings_are_sorted_by_severity(insecure_dir: Path) -> None:
    report = _scan(insecure_dir)
    ranks = [f.severity.rank for f in report.findings]
    assert ranks == sorted(ranks)
