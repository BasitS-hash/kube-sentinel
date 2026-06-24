"""Tests for the scan engine, scoring, and grading."""

from __future__ import annotations

from kube_sentinel.engine import score_to_grade
from kube_sentinel.models import ComplianceMapping, Finding, Resource, Severity
from kube_sentinel.rules.base import Rule, build_rule


def _resource() -> Resource:
    return Resource(
        kind="Pod",
        name="p",
        namespace="demo",
        api_version="v1",
        file_path="mem://p",
        doc_index=0,
        raw={"kind": "Pod", "spec": {"containers": [{"name": "c"}]}},
    )


def test_grade_boundaries() -> None:
    assert score_to_grade(100) == "A+"
    assert score_to_grade(95) == "A+"
    assert score_to_grade(94) == "A"
    assert score_to_grade(90) == "A"
    assert score_to_grade(85) == "B"
    assert score_to_grade(75) == "C"
    assert score_to_grade(65) == "D"
    assert score_to_grade(0) == "F"


def test_score_floors_at_zero() -> None:
    from kube_sentinel.engine import scan_resources

    # Build a rule that fires CRITICAL many times to drive the score below zero.
    def always(resource: Resource):
        for _ in range(20):
            yield "boom"

    rule = build_rule(
        id="TEST-CRIT",
        title="Test",
        severity=Severity.CRITICAL,
        remediation="fix",
        check=always,
    )
    report = scan_resources((_resource(),), rules=[rule])
    assert report.score == 0
    assert report.grade == "F"
    assert report.count(Severity.CRITICAL) == 20


def test_clean_scan_scores_full() -> None:
    from kube_sentinel.engine import scan_resources

    def never(resource: Resource):
        return iter(())

    rule = build_rule(
        id="TEST-CLEAN",
        title="Clean",
        severity=Severity.LOW,
        remediation="n/a",
        check=never,
    )
    # Use a Service so the cross-resource NetworkPolicy check stays quiet.
    svc = Resource(
        kind="Service",
        name="s",
        namespace="demo",
        api_version="v1",
        file_path="mem://s",
        doc_index=0,
        raw={"kind": "Service", "spec": {"type": "ClusterIP"}},
    )
    report = scan_resources((svc,), rules=[rule])
    assert report.score == 100
    assert report.grade == "A+"
    assert not report.has_findings


def test_severity_weight_ordering() -> None:
    assert Severity.CRITICAL.weight > Severity.HIGH.weight
    assert Severity.HIGH.weight > Severity.MEDIUM.weight
    assert Severity.MEDIUM.weight > Severity.LOW.weight
    assert Severity.LOW.weight > Severity.INFO.weight


def test_finding_as_dict_round_trips_mapping() -> None:
    f = Finding(
        rule_id="X",
        title="t",
        severity=Severity.HIGH,
        message="m",
        remediation="r",
        resource_kind="Pod",
        resource_name="p",
        namespace="demo",
        file_path="f.yaml",
        mapping=ComplianceMapping(cis=("5.2.1",), mitre_attack=("T1611",)),
    )
    d = f.as_dict()
    assert d["mapping"]["cis"] == ["5.2.1"]
    assert d["mapping"]["mitre_attack"] == ["T1611"]
    assert d["severity"] == "HIGH"


def test_rule_applies_to_none_runs_everywhere() -> None:
    seen = []

    def check(resource: Resource):
        seen.append(resource.kind)
        return iter(())

    rule = Rule(
        id="ANY",
        title="any",
        severity=Severity.INFO,
        remediation="n/a",
        mapping=ComplianceMapping(),
        check=check,
        applies_to=None,
    )
    rule.evaluate(_resource())
    assert seen == ["Pod"]
