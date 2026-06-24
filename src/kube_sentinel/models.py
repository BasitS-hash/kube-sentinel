"""Core immutable data models for kube-sentinel.

These types are deliberately small and frozen so findings can be passed around,
serialized, and compared without risk of in-place mutation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity levels for a finding, ordered from most to least critical."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """Numeric weight used for scoring (higher == worse)."""
        return _SEVERITY_WEIGHTS[self]

    @property
    def rank(self) -> int:
        """Sort rank (0 == most critical) for stable ordering."""
        return _SEVERITY_RANK[self]


_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# SARIF only understands a fixed set of levels; map our severities onto them.
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "note",
}


@dataclass(frozen=True)
class ComplianceMapping:
    """Maps a rule to the external frameworks it satisfies."""

    cis: tuple[str, ...] = ()
    pss: tuple[str, ...] = ()
    nsa_cisa: tuple[str, ...] = ()
    mitre_attack: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, list[str]]:
        return {
            "cis": list(self.cis),
            "pss": list(self.pss),
            "nsa_cisa": list(self.nsa_cisa),
            "mitre_attack": list(self.mitre_attack),
        }


@dataclass(frozen=True)
class Resource:
    """A single parsed Kubernetes object."""

    kind: str
    name: str
    namespace: str | None
    api_version: str
    file_path: str
    doc_index: int
    raw: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @property
    def display_name(self) -> str:
        ns = self.namespace or "default"
        return f"{self.kind}/{self.name} (ns: {ns})"


@dataclass(frozen=True)
class Finding:
    """A single rule violation against a resource."""

    rule_id: str
    title: str
    severity: Severity
    message: str
    remediation: str
    resource_kind: str
    resource_name: str
    namespace: str | None
    file_path: str
    mapping: ComplianceMapping

    @property
    def sarif_level(self) -> str:
        return _SARIF_LEVEL[self.severity]

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "message": self.message,
            "remediation": self.remediation,
            "resource_kind": self.resource_kind,
            "resource_name": self.resource_name,
            "namespace": self.namespace,
            "file_path": self.file_path,
            "mapping": self.mapping.as_dict(),
        }
