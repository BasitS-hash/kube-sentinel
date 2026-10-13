"""CLI smoke tests via typer's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kube_sentinel.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "kube-sentinel" in result.stdout


def test_rules_catalog() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "KS-WL-001" in result.stdout
    assert "KS-RBAC-004" in result.stdout


def test_scan_insecure_table_exits_nonzero(insecure_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(insecure_dir), "--fail-on", "HIGH"])
    # Findings at/above HIGH exist, so exit code is 1.
    assert result.exit_code == 1
    assert "findings" in result.stdout.lower()


def test_scan_hardened_table_exits_clean(hardened_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(hardened_dir), "--fail-on", "HIGH"])
    assert result.exit_code == 0
    assert "No findings" in result.stdout


def test_scan_json_output(insecure_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(insecure_dir), "--json", "--fail-on", "CRITICAL"])
    # Parse the JSON from stdout (everything before exit).
    payload = json.loads(result.stdout)
    assert payload["tool"] == "kube-sentinel"
    assert payload["summary"]["findings"] > 0


def test_scan_sarif_to_file(insecure_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.sarif"
    result = runner.invoke(
        app,
        ["scan", str(insecure_dir), "--sarif", "-o", str(out), "--fail-on", "CRITICAL"],
    )
    assert result.exit_code == 1  # findings exist
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"


def test_harden_command_stdout(insecure_dir: Path) -> None:
    result = runner.invoke(app, ["harden", str(insecure_dir / "workloads.yaml")])
    assert result.exit_code == 0
    assert "readOnlyRootFilesystem" in result.stdout


def test_harden_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["harden", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 2


def test_scan_empty_dir(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_cluster_without_client_exits_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    # The no-client path, forced rather than inferred from the environment. This
    # test used to rely on `kubernetes` being absent from the dev env; now that
    # the dev install includes the cluster extra (so the parity tests can run),
    # relying on that would instead have the test load the developer's real
    # kubeconfig and reach for whatever cluster it points at.
    from kube_sentinel import cluster as cluster_mod

    def no_client() -> tuple[object, object]:
        raise cluster_mod.ClusterScanError(
            "The 'kubernetes' client is not installed. Install the cluster "
            "extra: pip install 'kube-sentinel[cluster]'"
        )

    monkeypatch.setattr(cluster_mod, "_import_kubernetes", no_client)

    result = runner.invoke(app, ["cluster"])
    assert result.exit_code == 2
    assert "unavailable" in str(result.output).lower()
    assert "not installed" in str(result.output).lower()


def test_cluster_with_unreachable_cluster_exits_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The client is present but no context loads. Separate from the above
    # because the two produce different messages and only one of them tells the
    # user to install something.
    from kube_sentinel import cluster as cluster_mod

    class _NoConfig:
        @staticmethod
        def load_kube_config(context: str | None = None) -> None:
            raise RuntimeError("no kubeconfig")

        @staticmethod
        def load_incluster_config() -> None:
            raise RuntimeError("not in a cluster")

    monkeypatch.setattr(cluster_mod, "_import_kubernetes", lambda: (object(), _NoConfig))

    result = runner.invoke(app, ["cluster"])
    assert result.exit_code == 2
    assert "no reachable cluster" in str(result.output).lower()
