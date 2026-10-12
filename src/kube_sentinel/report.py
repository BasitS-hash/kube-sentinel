"""Output renderers: rich table, JSON, and SARIF 2.1.0.

Each renderer is a pure function of a ScanReport (plus rule metadata for SARIF),
so output is fully testable without touching the terminal.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .engine import ScanReport
from .models import Finding, Severity
from .rules.base import Rule

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
TOOL_NAME = "kube-sentinel"
TOOL_VERSION = "0.1.0"
TOOL_URI = "https://github.com/BasitS-hash/kube-sentinel"

# Namespaced and versioned, per the SARIF guidance on partialFingerprints: the
# version suffix lets us change how the identity is computed later without
# silently re-keying every existing alert.
FINGERPRINT_KEY = "kubeSentinelFindingIdentity/v1"

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_GRADE_STYLE: dict[str, str] = {
    "A+": "bold green",
    "A": "green",
    "B": "green",
    "C": "yellow",
    "D": "yellow",
    "F": "bold red",
}


def render_table(report: ScanReport, console: Console | None = None) -> None:
    """Print a rich table of findings plus a summary panel."""
    console = console or Console()

    if not report.has_findings:
        console.print(
            Panel(
                f"[bold green]No findings.[/] Scanned {report.resource_count} "
                f"resource(s) with {report.rule_count} rules.",
                title="kube-sentinel",
                border_style="green",
            )
        )
        _print_summary(report, console)
        return

    table = Table(
        title="kube-sentinel findings",
        show_lines=False,
        header_style="bold",
        expand=True,
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Resource", overflow="fold")
    table.add_column("Finding", overflow="fold")
    table.add_column("File", overflow="fold", style="dim")

    for f in report.findings:
        style = _SEVERITY_STYLE[f.severity]
        ns = f.namespace or "default"
        table.add_row(
            f"[{style}]{f.severity.value}[/]",
            f.rule_id,
            f"{f.resource_kind}/{f.resource_name}\n[dim]ns: {ns}[/]",
            f.message,
            f.file_path,
        )

    console.print(table)
    _print_summary(report, console)


def _print_summary(report: ScanReport, console: Console) -> None:
    parts = []
    for sev in Severity:
        n = report.count(sev)
        if n:
            style = _SEVERITY_STYLE[sev]
            parts.append(f"[{style}]{sev.value}: {n}[/]")
    counts = "  ".join(parts) if parts else "[green]clean[/]"
    grade_style = _GRADE_STYLE.get(report.grade, "white")
    body = (
        f"Resources: {report.resource_count}   "
        f"Findings: {len(report.findings)}\n"
        f"{counts}\n\n"
        f"Posture score: [bold]{report.score}/100[/]   "
        f"Grade: [{grade_style}]{report.grade}[/]"
    )
    console.print(Panel(body, title="Summary", border_style=grade_style, expand=False))


def to_json(report: ScanReport) -> str:
    """Serialize a report to a stable JSON string."""
    payload: dict[str, Any] = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "summary": {
            "resources": report.resource_count,
            "rules": report.rule_count,
            "findings": len(report.findings),
            "score": report.score,
            "grade": report.grade,
            "severity_counts": {
                sev.value: report.count(sev) for sev in Severity if report.count(sev)
            },
        },
        "findings": [f.as_dict() for f in report.findings],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def _sarif_rules(rules: list[Rule]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rule in rules:
        out.append(
            {
                "id": rule.id,
                "name": rule.title.replace(" ", ""),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.remediation},
                "helpUri": TOOL_URI,
                "help": {"text": rule.remediation},
                "defaultConfiguration": {
                    "level": _default_level(rule.severity),
                },
                "properties": {
                    "security-severity": _security_severity(rule.severity),
                    "tags": ["security", "kubernetes", *rule.mapping.cis],
                    "cis": list(rule.mapping.cis),
                    "pss": list(rule.mapping.pss),
                    "nsa_cisa": list(rule.mapping.nsa_cisa),
                    "mitre_attack": list(rule.mapping.mitre_attack),
                },
            }
        )
    return out


def _default_level(severity: Severity) -> str:
    from .models import _SARIF_LEVEL

    return _SARIF_LEVEL[severity]


def _security_severity(severity: Severity) -> str:
    # GitHub uses a 0.0-10.0 numeric scale for ordering in the Security tab.
    mapping = {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.5",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }
    return mapping[severity]


def _partial_fingerprint(finding: Finding) -> str:
    """A location-independent identity for a finding.

    With no partialFingerprints, GitHub keys an alert on file + line + rule.
    kube-sentinel reports every finding at startLine 1 because a parsed YAML
    document does not carry line numbers back to us, so that fallback would
    collapse every finding in a file onto one alert and re-open all of them the
    moment a manifest is reformatted or moved.

    What actually identifies a finding is the rule, the resource it fired on,
    and the specific thing it said. The message is in the hash because it is
    what separates two containers in one pod; the cost is that rewording a
    message retires the old alert and opens a new one, which is the better
    trade than silently merging distinct findings.
    """
    identity = "\x1f".join(
        (
            finding.rule_id,
            finding.resource_kind,
            finding.resource_name,
            finding.namespace or "default",
            finding.message,
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def to_sarif(report: ScanReport, rules: list[Rule]) -> str:
    """Serialize a report to SARIF 2.1.0 for GitHub code scanning."""
    # SARIF requires every result's ruleId to resolve to a declared rule. Every
    # built-in rule is in the registry, but a caller may pass a narrowed list,
    # so declare anything a result references that `rules` does not cover.
    rule_ids = {r.id for r in rules}
    declared = list(rules)

    sarif_results: list[dict[str, Any]] = []
    extra_rules: dict[str, dict[str, Any]] = {}

    for f in report.findings:
        if f.rule_id not in rule_ids and f.rule_id not in extra_rules:
            extra_rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.remediation},
                "helpUri": TOOL_URI,
                "help": {"text": f.remediation},
                "defaultConfiguration": {"level": f.sarif_level},
                "properties": {
                    "security-severity": _security_severity(f.severity),
                    "tags": ["security", "kubernetes"],
                    "cis": list(f.mapping.cis),
                    "pss": list(f.mapping.pss),
                    "nsa_cisa": list(f.mapping.nsa_cisa),
                    "mitre_attack": list(f.mapping.mitre_attack),
                },
            }
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": f.sarif_level,
                "message": {"text": (f"{f.title}: {f.message}. Remediation: {f.remediation}")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {
                                "name": f"{f.resource_kind}/{f.resource_name}",
                                "kind": "resource",
                            }
                        ],
                    }
                ],
                "partialFingerprints": {FINGERPRINT_KEY: _partial_fingerprint(f)},
                "properties": {
                    "resource": f"{f.resource_kind}/{f.resource_name}",
                    "namespace": f.namespace or "default",
                    "severity": f.severity.value,
                },
            }
        )

    all_rules = _sarif_rules(declared) + list(extra_rules.values())

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": all_rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
