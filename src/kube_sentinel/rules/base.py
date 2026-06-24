"""Rule abstraction and registry.

A rule is data: it declares its identity, severity, and compliance mapping, and
provides a pure ``evaluate`` function that yields zero or more findings for a
single resource. Rules are registered into a module-level registry so the engine
can run a full pack and so new packs can be added without touching the engine.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from ..models import ComplianceMapping, Finding, Resource, Severity

# A check returns an iterable of (message, remediation_override_or_None) tuples.
# Most rules use the rule's default remediation, so the second item is optional.
CheckResult = Iterator[str]
CheckFn = Callable[[Resource], CheckResult]


@dataclass(frozen=True)
class Rule:
    """A single, data-driven security rule."""

    id: str
    title: str
    severity: Severity
    remediation: str
    mapping: ComplianceMapping
    check: CheckFn
    applies_to: frozenset[str] | None = None  # None == all kinds

    def evaluate(self, resource: Resource) -> list[Finding]:
        """Run this rule against a resource and produce findings."""
        if self.applies_to is not None and resource.kind not in self.applies_to:
            return []
        findings: list[Finding] = []
        for message in self.check(resource):
            findings.append(
                Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    message=message,
                    remediation=self.remediation,
                    resource_kind=resource.kind,
                    resource_name=resource.name,
                    namespace=resource.namespace,
                    file_path=resource.file_path,
                    mapping=self.mapping,
                )
            )
        return findings


_REGISTRY: dict[str, Rule] = {}


def register(rule: Rule) -> Rule:
    """Register a rule, guarding against duplicate IDs."""
    if rule.id in _REGISTRY:
        raise ValueError(f"duplicate rule id: {rule.id}")
    _REGISTRY[rule.id] = rule
    return rule


def all_rules() -> list[Rule]:
    """Return all registered rules sorted by ID for deterministic output."""
    return sorted(_REGISTRY.values(), key=lambda r: r.id)


def get_rule(rule_id: str) -> Rule | None:
    return _REGISTRY.get(rule_id)


def clear_registry() -> None:
    """Test helper: empty the registry."""
    _REGISTRY.clear()


def build_rule(
    *,
    id: str,
    title: str,
    severity: Severity,
    remediation: str,
    check: CheckFn,
    cis: tuple[str, ...] = (),
    pss: tuple[str, ...] = (),
    nsa_cisa: tuple[str, ...] = (),
    mitre_attack: tuple[str, ...] = (),
    applies_to: frozenset[str] | None = None,
) -> Rule:
    """Convenience constructor that builds the mapping inline."""
    return Rule(
        id=id,
        title=title,
        severity=severity,
        remediation=remediation,
        mapping=ComplianceMapping(cis=cis, pss=pss, nsa_cisa=nsa_cisa, mitre_attack=mitre_attack),
        check=check,
        applies_to=applies_to,
    )


def _ensure_loaded() -> None:
    """Import rule modules so they self-register. Idempotent."""
    # Imported lazily to avoid a circular import at module load time.
    from . import networking, rbac, workload  # noqa: F401


def load_default_rules() -> list[Rule]:
    """Ensure all built-in rule packs are registered and return them."""
    _ensure_loaded()
    return all_rules()


# Re-export commonly used symbols for rule modules.
__all__ = [
    "Any",
    "ComplianceMapping",
    "Finding",
    "Resource",
    "Rule",
    "Severity",
    "all_rules",
    "build_rule",
    "clear_registry",
    "get_rule",
    "load_default_rules",
    "register",
]
