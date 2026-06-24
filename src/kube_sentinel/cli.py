"""Command-line interface for kube-sentinel.

Commands:
  scan     Scan local manifests (files or directories).
  cluster  Scan a live cluster via the active kubeconfig context (optional).
  harden   Emit a hardened version of a manifest.
  rules    List the rule catalog.
"""

from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .engine import ScanReport, scan_resources
from .models import Severity
from .parser import parse_path
from .report import render_table, to_json, to_sarif
from .rules import load_default_rules

app = typer.Typer(
    help="Kubernetes security posture scanner (CIS, PSS, NSA/CISA).",
    add_completion=False,
    no_args_is_help=True,
)

_stdout = Console()
_stderr = Console(stderr=True)


class OutputFormat(str, Enum):
    table = "table"
    json = "json"
    sarif = "sarif"


# Exit codes: 0 clean, 1 findings at/above fail threshold, 2 usage/runtime error.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _emit(report: ScanReport, fmt: OutputFormat, output: Path | None) -> None:
    if fmt is OutputFormat.json:
        text = to_json(report)
        _write(text, output)
    elif fmt is OutputFormat.sarif:
        text = to_sarif(report, load_default_rules())
        _write(text, output)
    else:
        if output is not None:
            with output.open("w", encoding="utf-8") as fh:
                render_table(report, Console(file=fh))
        else:
            render_table(report, _stdout)


def _write(text: str, output: Path | None) -> None:
    if output is not None:
        output.write_text(text + "\n", encoding="utf-8")
    else:
        # Print raw (no rich markup interpretation) for valid JSON/SARIF.
        sys.stdout.write(text + "\n")


def _exceeds_threshold(report: ScanReport, threshold: Severity) -> bool:
    return any(f.severity.rank <= threshold.rank for f in report.findings)


@app.command()
def scan(
    path: Path = typer.Argument(..., help="File or directory of Kubernetes manifests."),
    output_format: OutputFormat = typer.Option(
        OutputFormat.table, "--format", "-f", help="Output format."
    ),
    json_out: bool = typer.Option(False, "--json", help="Shortcut for --format json."),
    sarif: bool = typer.Option(False, "--sarif", help="Shortcut for --format sarif."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write output to a file instead of stdout."
    ),
    fail_on: Severity = typer.Option(
        Severity.HIGH,
        "--fail-on",
        help="Exit non-zero if any finding at or above this severity exists.",
    ),
) -> None:
    """Scan local manifests and report misconfigurations."""
    fmt = output_format
    if json_out:
        fmt = OutputFormat.json
    if sarif:
        fmt = OutputFormat.sarif

    result = parse_path(path)
    if result.errors and fmt is OutputFormat.table:
        for err in result.errors:
            _stderr.print(f"[yellow]warning[/]: {err.file_path}: {err.detail}")

    if not result.resources and not result.errors:
        _stderr.print(f"[yellow]No Kubernetes manifests found at:[/] {path}")

    report = scan_resources(result.resources)
    _emit(report, fmt, output)

    if _exceeds_threshold(report, fail_on):
        raise typer.Exit(EXIT_FINDINGS)
    raise typer.Exit(EXIT_CLEAN)


@app.command()
def cluster(
    context: str | None = typer.Option(
        None, "--context", help="kubeconfig context to use (defaults to current)."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.table, "--format", "-f", help="Output format."
    ),
    json_out: bool = typer.Option(False, "--json", help="Shortcut for --format json."),
    sarif: bool = typer.Option(False, "--sarif", help="Shortcut for --format sarif."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write output to a file instead of stdout."
    ),
    fail_on: Severity = typer.Option(
        Severity.HIGH, "--fail-on", help="Exit non-zero at or above this severity."
    ),
) -> None:
    """Scan a live cluster via the active kubeconfig context (optional feature)."""
    # Imported lazily so the base install works without the kubernetes client.
    from .cluster import ClusterScanError, fetch_cluster_resources

    fmt = output_format
    if json_out:
        fmt = OutputFormat.json
    if sarif:
        fmt = OutputFormat.sarif

    try:
        cluster_data = fetch_cluster_resources(context=context)
    except ClusterScanError as exc:
        _stderr.print(f"[yellow]Cluster scan unavailable:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from None

    _stderr.print(f"[green]Scanning cluster context:[/] {cluster_data.context}")
    report = scan_resources(cluster_data.resources)
    _emit(report, fmt, output)

    if _exceeds_threshold(report, fail_on):
        raise typer.Exit(EXIT_FINDINGS)
    raise typer.Exit(EXIT_CLEAN)


@app.command()
def harden(
    manifest: Path = typer.Argument(..., help="Manifest file to harden."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write hardened YAML to a file."
    ),
) -> None:
    """Emit a hardened version of a manifest (restricted PSS)."""
    from .harden import harden_to_yaml

    result = parse_path(manifest)
    if not result.resources:
        _stderr.print(f"[red]No parseable resources at:[/] {manifest}")
        raise typer.Exit(EXIT_ERROR)

    hardened_yaml = harden_to_yaml(list(result.resources))
    if output is not None:
        output.write_text(hardened_yaml, encoding="utf-8")
        _stderr.print(f"[green]Hardened manifest written to:[/] {output}")
    else:
        sys.stdout.write(hardened_yaml)


@app.command()
def rules() -> None:
    """List the rule catalog with severities and compliance mappings."""
    table = Table(title="kube-sentinel rule catalog", header_style="bold")
    table.add_column("ID", no_wrap=True)
    table.add_column("Title")
    table.add_column("Severity", no_wrap=True)
    table.add_column("CIS")
    table.add_column("PSS")
    table.add_column("NSA/CISA")

    for rule in load_default_rules():
        table.add_row(
            rule.id,
            rule.title,
            rule.severity.value,
            ", ".join(rule.mapping.cis) or "-",
            ", ".join(rule.mapping.pss) or "-",
            "; ".join(rule.mapping.nsa_cisa) or "-",
        )
    _stdout.print(table)


def _version_callback(value: bool) -> None:
    if value:
        _stdout.print(f"kube-sentinel {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version."
    ),
) -> None:
    """kube-sentinel: audit Kubernetes manifests and clusters for misconfigurations."""


if __name__ == "__main__":  # pragma: no cover
    app()
