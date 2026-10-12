"""Rule abstraction and registry.

A rule is data: it declares its identity, severity, and compliance mapping, and
provides a pure check function that yields zero or more findings. Rules are
registered into a module-level registry so the engine can run a full pack and so
new packs can be added without touching the engine.

Most rules judge one resource at a time. A few cannot: whether a namespace lacks
a NetworkPolicy, or whether a cluster-admin binding is actually reachable from a
running workload, is only answerable with the whole set in view. Those rules
declare a ``cross_check`` instead of a ``check`` and receive a ``ScanContext``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from ..models import ComplianceMapping, Finding, Resource, Severity

# A per-resource check yields one message per violation; the rule supplies the
# severity, remediation, and compliance mapping around it.
CheckResult = Iterator[str]
CheckFn = Callable[[Resource], CheckResult]


@dataclass(frozen=True)
class ScanContext:
    """The whole resource set, handed to cross-resource rules."""

    resources: tuple[Resource, ...]

    def of_kinds(self, kinds: frozenset[str]) -> list[Resource]:
        """Return every resource whose kind is in ``kinds``."""
        return [r for r in self.resources if r.kind in kinds]

    def namespaces_of(self, kinds: frozenset[str]) -> set[str]:
        """Return the namespaces occupied by resources of ``kinds``."""
        return {(r.namespace or "default") for r in self.of_kinds(kinds)}


@dataclass(frozen=True)
class CrossHit:
    """One violation found by a cross-resource check.

    A per-resource check inherits the identity of the resource it ran against.
    A correlation spans several objects, so it has to nominate the one the
    finding is reported on — and that need not be a parsed resource at all:
    KS-NET-003 reports against a Namespace no manifest declares.
    """

    message: str
    resource_kind: str
    resource_name: str
    namespace: str | None
    file_path: str


CrossCheckResult = Iterator[CrossHit]
CrossCheckFn = Callable[[ScanContext], CrossCheckResult]


@dataclass(frozen=True)
class Rule:
    """A single, data-driven security rule.

    A rule carries exactly one check. ``check`` sees one resource, which is all
    the original rule pack needed. ``cross_check`` sees every resource at once,
    because some risks only exist as a combination and cannot be expressed
    per-resource without lying: a cluster-admin binding is inert until a
    workload mounts the bound ServiceAccount, and the absence of a
    NetworkPolicy is a property of a namespace, not of any one object.

    Both shapes live on one dataclass on purpose. The registry, the ``rules``
    command, the compliance mapping and the SARIF rule declarations then treat
    every check identically, and the engine only has to dispatch on which field
    is set — so the rule count stays a single derived number.
    """

    id: str
    title: str
    severity: Severity
    remediation: str
    mapping: ComplianceMapping
    check: CheckFn | None = None
    applies_to: frozenset[str] | None = None  # None == all kinds
    cross_check: CrossCheckFn | None = None

    def __post_init__(self) -> None:
        if (self.check is None) == (self.cross_check is None):
            raise ValueError(f"rule {self.id} must set exactly one of check/cross_check")

    @property
    def is_cross_resource(self) -> bool:
        return self.cross_check is not None

    def evaluate(self, resource: Resource) -> list[Finding]:
        """Run this rule against a single resource and produce findings."""
        if self.check is None:
            return []
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

    def evaluate_context(self, context: ScanContext) -> list[Finding]:
        """Run this rule against the whole resource set and produce findings."""
        if self.cross_check is None:
            return []
        return [
            Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                message=hit.message,
                remediation=self.remediation,
                resource_kind=hit.resource_kind,
                resource_name=hit.resource_name,
                namespace=hit.namespace,
                file_path=hit.file_path,
                mapping=self.mapping,
            )
            for hit in self.cross_check(context)
        ]


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
    check: CheckFn | None = None,
    cross_check: CrossCheckFn | None = None,
    cis: tuple[str, ...] = (),
    pss: tuple[str, ...] = (),
    nsa_cisa: tuple[str, ...] = (),
    mitre_attack: tuple[str, ...] = (),
    applies_to: frozenset[str] | None = None,
) -> Rule:
    """Convenience constructor that builds the mapping inline.

    Pass ``check`` for a per-resource rule or ``cross_check`` for a correlation;
    ``Rule`` rejects neither-or-both.
    """
    return Rule(
        id=id,
        title=title,
        severity=severity,
        remediation=remediation,
        mapping=ComplianceMapping(cis=cis, pss=pss, nsa_cisa=nsa_cisa, mitre_attack=mitre_attack),
        check=check,
        applies_to=applies_to,
        cross_check=cross_check,
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
    "CrossCheckFn",
    "CrossHit",
    "Finding",
    "Resource",
    "Rule",
    "ScanContext",
    "Severity",
    "all_rules",
    "build_rule",
    "clear_registry",
    "get_rule",
    "load_default_rules",
    "register",
]
