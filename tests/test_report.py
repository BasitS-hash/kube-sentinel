"""Tests for the report renderers (JSON and SARIF)."""

from __future__ import annotations

import json
from pathlib import Path

from kube_sentinel.engine import scan_resources
from kube_sentinel.parser import parse_path
from kube_sentinel.report import to_json, to_sarif
from kube_sentinel.rules import load_default_rules


def _report(path: Path):
    result = parse_path(path)
    return scan_resources(result.resources)


def test_json_is_valid_and_structured(insecure_dir: Path) -> None:
    report = _report(insecure_dir)
    payload = json.loads(to_json(report))
    assert payload["tool"] == "kube-sentinel"
    assert payload["summary"]["findings"] == len(report.findings)
    assert payload["summary"]["grade"] == "F"
    assert len(payload["findings"]) == len(report.findings)
    first = payload["findings"][0]
    assert {"rule_id", "severity", "message", "remediation", "mapping"} <= set(first)


def test_sarif_is_valid_2_1_0(insecure_dir: Path) -> None:
    report = _report(insecure_dir)
    sarif = json.loads(to_sarif(report, load_default_rules()))

    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "kube-sentinel"

    declared_ids = {r["id"] for r in driver["rules"]}
    result_ids = {r["ruleId"] for r in run["results"]}
    # Every result's ruleId must resolve to a declared rule (GitHub requirement).
    assert result_ids <= declared_ids

    assert len(run["results"]) == len(report.findings)
    for result in run["results"]:
        assert result["level"] in {"error", "warning", "note"}
        loc = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert loc


def test_sarif_includes_cross_resource_rule(insecure_dir: Path) -> None:
    report = _report(insecure_dir)
    sarif = json.loads(to_sarif(report, load_default_rules()))
    driver = sarif["runs"][0]["tool"]["driver"]
    declared_ids = {r["id"] for r in driver["rules"]}
    # The cross-resource netpol rule is not in the registry list but must be
    # declared so its results resolve.
    assert "KS-NET-003" in declared_ids


def test_json_clean_report(hardened_dir: Path) -> None:
    report = _report(hardened_dir)
    payload = json.loads(to_json(report))
    assert payload["summary"]["findings"] == 0
    assert payload["summary"]["score"] == 100
    assert payload["summary"]["severity_counts"] == {}


def test_sarif_security_severity_present(insecure_dir: Path) -> None:
    report = _report(insecure_dir)
    sarif = json.loads(to_sarif(report, load_default_rules()))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        assert "security-severity" in rule["properties"]
