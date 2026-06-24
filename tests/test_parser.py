"""Tests for the manifest parser."""

from __future__ import annotations

from pathlib import Path

from kube_sentinel.parser import iter_manifest_files, parse_file, parse_path


def test_parse_multi_document(tmp_path: Path) -> None:
    manifest = tmp_path / "multi.yaml"
    manifest.write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n"
        "---\n"
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: b\n"
    )
    resources, errors = parse_file(manifest)
    assert not errors
    kinds = sorted(r.kind for r in resources)
    assert kinds == ["Pod", "Service"]


def test_parse_skips_empty_documents(tmp_path: Path) -> None:
    manifest = tmp_path / "empty.yaml"
    manifest.write_text("---\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n")
    resources, errors = parse_file(manifest)
    assert len(resources) == 1
    assert not errors


def test_parse_ignores_non_k8s_documents(tmp_path: Path) -> None:
    manifest = tmp_path / "config.yaml"
    manifest.write_text("just: a mapping\nwithout: kind or apiVersion\n")
    resources, errors = parse_file(manifest)
    assert not resources
    assert not errors


def test_invalid_yaml_is_reported_not_raised(tmp_path: Path) -> None:
    manifest = tmp_path / "broken.yaml"
    manifest.write_text("key: [unterminated\n")
    resources, errors = parse_file(manifest)
    assert not resources
    assert len(errors) == 1
    assert "invalid YAML" in errors[0].detail


def test_parse_path_missing(tmp_path: Path) -> None:
    result = parse_path(tmp_path / "does-not-exist")
    assert not result.resources
    assert len(result.errors) == 1
    assert "does not exist" in result.errors[0].detail


def test_parse_path_recurses_directories(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.yaml").write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n")
    (tmp_path / "sub" / "b.yml").write_text("apiVersion: v1\nkind: Service\nmetadata:\n  name: b\n")
    (tmp_path / "notyaml.txt").write_text("ignored")
    result = parse_path(tmp_path)
    assert len(result.resources) == 2


def test_iter_manifest_files_single_file(tmp_path: Path) -> None:
    f = tmp_path / "x.yaml"
    f.write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n")
    assert list(iter_manifest_files(f)) == [f]


def test_namespace_defaults_to_none(tmp_path: Path) -> None:
    manifest = tmp_path / "p.yaml"
    manifest.write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n")
    resources, _ = parse_file(manifest)
    assert resources[0].namespace is None
    assert "default" in resources[0].display_name
