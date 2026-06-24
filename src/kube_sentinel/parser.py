"""Parse Kubernetes manifests from files and directories.

Supports multi-document YAML files and recursive directory traversal. Invalid
documents are reported rather than crashing the scan.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .models import Resource

YAML_SUFFIXES: frozenset[str] = frozenset({".yaml", ".yml"})
# Guard against accidentally loading enormous files (e.g. binary blobs).
MAX_FILE_BYTES: int = 10 * 1024 * 1024


@dataclass(frozen=True)
class ParseError:
    """A document that could not be parsed into a Kubernetes resource."""

    file_path: str
    detail: str


@dataclass(frozen=True)
class ParseResult:
    """Outcome of parsing one or more manifest sources."""

    resources: tuple[Resource, ...]
    errors: tuple[ParseError, ...]


def iter_manifest_files(path: Path) -> Iterator[Path]:
    """Yield manifest files under ``path`` (recursively for directories)."""
    if path.is_file():
        if path.suffix.lower() in YAML_SUFFIXES:
            yield path
        return
    for root, _dirs, files in os.walk(path):
        for name in sorted(files):
            candidate = Path(root) / name
            if candidate.suffix.lower() in YAML_SUFFIXES:
                yield candidate


def _coerce_resource(doc: Any, file_path: str, doc_index: int) -> Resource | None:
    """Convert a parsed YAML document into a Resource, or None if not a K8s object."""
    if not isinstance(doc, dict):
        return None
    kind = doc.get("kind")
    api_version = doc.get("apiVersion")
    if not isinstance(kind, str) or not isinstance(api_version, str):
        return None

    metadata = doc.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    name = metadata.get("name")
    name = name if isinstance(name, str) else "<unnamed>"
    namespace = metadata.get("namespace")
    namespace = namespace if isinstance(namespace, str) else None

    return Resource(
        kind=kind,
        name=name,
        namespace=namespace,
        api_version=api_version,
        file_path=file_path,
        doc_index=doc_index,
        raw=doc,
    )


def parse_file(path: Path) -> tuple[list[Resource], list[ParseError]]:
    """Parse a single manifest file into resources and errors."""
    resources: list[Resource] = []
    errors: list[ParseError] = []
    file_path = str(path)

    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            errors.append(ParseError(file_path, "file exceeds maximum size; skipped"))
            return resources, errors
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(ParseError(file_path, f"could not read file: {exc}"))
        return resources, errors

    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        errors.append(ParseError(file_path, f"invalid YAML: {exc}"))
        return resources, errors

    for index, doc in enumerate(documents):
        if doc is None:
            continue
        resource = _coerce_resource(doc, file_path, index)
        if resource is not None:
            resources.append(resource)
    return resources, errors


def parse_path(path: Path) -> ParseResult:
    """Parse all manifests at ``path`` (file or directory)."""
    if not path.exists():
        return ParseResult(
            resources=(),
            errors=(ParseError(str(path), "path does not exist"),),
        )

    all_resources: list[Resource] = []
    all_errors: list[ParseError] = []
    for manifest in iter_manifest_files(path):
        resources, errors = parse_file(manifest)
        all_resources.extend(resources)
        all_errors.extend(errors)

    return ParseResult(resources=tuple(all_resources), errors=tuple(all_errors))
