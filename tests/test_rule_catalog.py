"""The rule count must be derived, never written down twice.

The README's rule table and the "N data-driven rules" line used to be
maintained by hand against a registry that did not include the cross-resource
NetworkPolicy check, which is how the catalog drifted one row out of step with
reality. These tests make the registry the single source of truth: anything
that states a count or lists a rule is checked against it.
"""

from __future__ import annotations

import re
from pathlib import Path

from kube_sentinel.engine import scan_resources
from kube_sentinel.models import Resource
from kube_sentinel.rules import load_default_rules

README = Path(__file__).resolve().parent.parent / "README.md"

# Matches a rule-table row: | `KS-WL-001` | ... |
_TABLE_ROW = re.compile(r"^\|\s*`(KS-[A-Z]+-\d+)`\s*\|", re.MULTILINE)
# Matches the features bullet that states the catalog size.
_PROSE_COUNT = re.compile(r"\*\*(\d+) data-driven rules\*\*")


def test_report_rule_count_is_the_registry_size() -> None:
    rules = load_default_rules()
    svc = Resource(
        kind="Service",
        name="s",
        namespace="demo",
        api_version="v1",
        file_path="mem://s",
        doc_index=0,
        raw={"kind": "Service", "spec": {"type": "ClusterIP"}},
    )
    report = scan_resources((svc,))
    assert report.rule_count == len(rules)


def test_readme_table_lists_exactly_the_registered_rules() -> None:
    documented = set(_TABLE_ROW.findall(README.read_text(encoding="utf-8")))
    registered = {r.id for r in load_default_rules()}
    assert documented == registered, {
        "undocumented": sorted(registered - documented),
        "stale_rows": sorted(documented - registered),
    }


def test_readme_prose_count_matches_the_registry() -> None:
    matches = _PROSE_COUNT.findall(README.read_text(encoding="utf-8"))
    assert len(matches) == 1, "expected exactly one '**N data-driven rules**' claim"
    assert int(matches[0]) == len(load_default_rules())
