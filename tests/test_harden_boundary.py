"""What survives `harden`, pinned to an explicit allowlist.

The remediator and the detector ship in the same package, so if `harden`
output still trips a rule, the tool told the user it fixed their manifest and
it did not — this project's own defect class, turned inward. These tests run
the real command's path over `tests/fixtures/every-rule.yaml` (which trips all
23 rules) and assert the surviving set is *exactly* `ALLOWED_AFTER_HARDEN`.

Exactly, not "fewer than before": a change that silently stopped setting
`runAsNonRoot` would still reduce the count, and `test_harden.py`'s
no-CRITICAL-or-HIGH assertion would still pass, because KS-WL-003 is a HIGH
that would then simply fire again at a lower total.

The allowlist is not a list of bugs. The restricted Pod Security Standard
governs the pod security context; it says nothing about resource limits,
probes, image tags, RBAC, or Services, and `harden` cannot invent a
NetworkPolicy for a namespace it was never handed. Each entry says why.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from kube_sentinel import k8s
from kube_sentinel.engine import ScanReport, scan_resources
from kube_sentinel.harden import DEFAULT_NON_ROOT_UID, harden_resource, harden_to_yaml
from kube_sentinel.models import Resource
from kube_sentinel.parser import parse_path
from kube_sentinel.rules import load_default_rules

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "every-rule.yaml"

# The rules that may still fire on hardened output, and why. Shrinking this set
# is an improvement; growing it means `harden` stopped doing something, and the
# README section it is checked against has to be changed in the same commit.
ALLOWED_AFTER_HARDEN = frozenset(
    {
        # Out of scope: restricted PSS has nothing to say about these, and
        # harden has no way to guess the right value.
        "KS-WL-010",  # harden fills a wholly-absent resources block; it will
        # not complete a half-specified one, because the author who set a CPU
        # request and no memory limit may have meant it.
        "KS-WL-011",  # it cannot know which image tag you meant.
        "KS-WL-012",  # it cannot invent a health endpoint.
        # Out of scope: harden rewrites pod specs. It passes every other kind
        # through untouched, and KS-NET-003 is about a Namespace no manifest
        # here declares.
        "KS-NET-001",
        "KS-NET-002",
        "KS-NET-003",
        "KS-RBAC-001",
        "KS-RBAC-002",
        "KS-RBAC-003",
        "KS-RBAC-004",
        "KS-RBAC-005",
    }
)

# Matches the README bullets under the harden-scope heading.
_README_SECTION = re.compile(
    r"^#### What `harden` does not touch\n(.*?)(?=^#{1,4} )",
    re.MULTILINE | re.DOTALL,
)
_README_RULE_ID = re.compile(r"`(KS-[A-Z]+-\d+)`")


def _harden_file(path: Path, tmp_path: Path) -> ScanReport:
    """Harden every resource in a manifest and scan the serialized result.

    Goes through `harden_to_yaml` and back out through the parser rather than
    comparing in-memory dicts, so the YAML round-trip the CLI actually performs
    is part of what is under test.
    """
    parsed = parse_path(path)
    assert not parsed.errors, parsed.errors
    hardened = tmp_path / "hardened.yaml"
    hardened.write_text(harden_to_yaml(list(parsed.resources)), encoding="utf-8")
    reparsed = parse_path(hardened)
    assert not reparsed.errors, reparsed.errors
    return scan_resources(reparsed.resources)


def _pod(spec: dict[str, object]) -> Resource:
    return Resource(
        kind="Pod",
        name="p",
        namespace="demo",
        api_version="v1",
        file_path="mem://p",
        doc_index=0,
        raw={"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p"}, "spec": spec},
    )


def test_fixture_trips_every_registered_rule() -> None:
    """The audit is only as wide as its input, so pin the width.

    Without this, adding a rule the fixture does not exercise would leave the
    allowlist test silently blind to it.
    """
    report = scan_resources(parse_path(FIXTURE).resources)
    firing = {f.rule_id for f in report.findings}
    registered = {r.id for r in load_default_rules()}
    assert firing == registered, {"never fired": sorted(registered - firing)}


def test_hardened_output_fires_exactly_the_allowlist(tmp_path: Path) -> None:
    report = _harden_file(FIXTURE, tmp_path)
    surviving = {f.rule_id for f in report.findings}
    assert surviving == set(ALLOWED_AFTER_HARDEN), {
        "newly surviving": sorted(surviving - ALLOWED_AFTER_HARDEN),
        "no longer surviving": sorted(ALLOWED_AFTER_HARDEN - surviving),
    }


def test_hardening_clears_every_pod_security_rule(tmp_path: Path) -> None:
    """Every KS-WL-* rule that restricted PSS actually covers must go quiet."""
    report = _harden_file(FIXTURE, tmp_path)
    surviving = {f.rule_id for f in report.findings if f.rule_id.startswith("KS-WL-")}
    assert surviving == {"KS-WL-010", "KS-WL-011", "KS-WL-012"}


def test_hardening_breaks_the_admin_service_account_correlation(tmp_path: Path) -> None:
    """KS-RBAC-006 needs a mounted token, which hardening takes away.

    The binding is untouched — KS-RBAC-004 still fires on it — but the path
    from a container compromise to the cluster is gone.
    """
    report = _harden_file(FIXTURE, tmp_path)
    assert not [f for f in report.findings if f.rule_id == "KS-RBAC-006"]
    assert [f for f in report.findings if f.rule_id == "KS-RBAC-004"]


def test_hardened_output_never_runs_as_uid_zero(tmp_path: Path) -> None:
    """No scan assertion can stand in for this one.

    KS-WL-003 short-circuits as soon as `runAsNonRoot: true` is set, so a
    hardened pod carrying both `runAsNonRoot: true` and `runAsUser: 0` scans
    clean while the kubelet refuses to start it. The document has to be read
    directly.
    """
    parsed = parse_path(FIXTURE)
    for resource in parsed.resources:
        if resource.kind not in k8s.POD_BEARING_KINDS:
            continue
        pod_spec = k8s.get_pod_spec(harden_resource(resource))
        assert pod_spec is not None
        assert k8s.pod_security_context(pod_spec).get("runAsUser") != 0
        for container in k8s.get_all_containers(pod_spec):
            where = f"{resource.kind}/{resource.name} container {container.get('name')}"
            assert k8s.effective_run_as_user(pod_spec, container) != 0, where
            assert k8s.effective_run_as_non_root(pod_spec, container) is True, where

    # And the serialized output must not contain the literal either.
    text = harden_to_yaml(list(parsed.resources))
    assert "runAsUser: 0" not in text


@pytest.mark.parametrize(
    ("field", "unsafe", "expected"),
    [
        ("runAsNonRoot", False, True),
        ("runAsUser", 0, DEFAULT_NON_ROOT_UID),
        ("seccompProfile", {"type": "Unconfined"}, {"type": "RuntimeDefault"}),
    ],
)
def test_unsafe_pod_level_security_context_is_overridden(
    field: str, unsafe: object, expected: object
) -> None:
    """Pod-level values are defaulted, which must not mean "preserved".

    Each of these three is a restricted-PSS violation on its own, and leaving
    one in place while forcing the container-level opposite emits a pod that
    contradicts itself. A deliberate non-zero UID is a different matter and is
    still respected — see the test below.
    """
    hardened = harden_resource(
        _pod(
            {
                "securityContext": {field: unsafe},
                "containers": [{"name": "c", "image": "nginx:1.27"}],
            }
        )
    )
    pod_spec = k8s.get_pod_spec(hardened)
    assert pod_spec is not None
    assert k8s.pod_security_context(pod_spec)[field] == expected


def test_a_deliberate_non_root_uid_is_respected() -> None:
    """Hardening overrides unsafe values, not every value an author chose."""
    hardened = harden_resource(
        _pod(
            {
                "securityContext": {"runAsUser": 1234, "fsGroup": 2000},
                "containers": [{"name": "c", "image": "nginx:1.27"}],
            }
        )
    )
    pod_spec = k8s.get_pod_spec(hardened)
    assert pod_spec is not None
    pod_sc = k8s.pod_security_context(pod_spec)
    assert pod_sc["runAsUser"] == 1234
    assert pod_sc["fsGroup"] == 2000


def test_explicit_automount_true_survives_hardening() -> None:
    """The one place hardening defers to the manifest, on purpose.

    `automountServiceAccountToken: true` is the only signal in a pod spec that
    the workload genuinely calls the Kubernetes API, and stripping a token the
    app needs breaks it. So harden sets the field when it is absent and leaves
    an explicit `true` alone — which means KS-WL-013, and KS-RBAC-006 if the
    SA is admin-equivalent, can still fire on hardened output. Pinned here so
    it stays a decision rather than becoming an accident.
    """
    hardened = harden_resource(
        _pod(
            {
                "automountServiceAccountToken": True,
                "containers": [{"name": "c", "image": "nginx:1.27"}],
            }
        )
    )
    assert hardened["spec"]["automountServiceAccountToken"] is True

    resource = _pod(hardened["spec"])
    report = scan_resources((resource,))
    assert "KS-WL-013" in {f.rule_id for f in report.findings}


def test_hardened_output_parses_back_as_the_same_kinds(tmp_path: Path) -> None:
    """Hardening is a rewrite, not a filter: nothing may be dropped."""
    parsed = parse_path(FIXTURE)
    text = harden_to_yaml(list(parsed.resources))
    docs = [d for d in yaml.safe_load_all(text) if d]
    assert [d.get("kind") for d in docs] == [r.kind for r in parsed.resources]


def test_readme_documents_the_allowlist() -> None:
    """The allowlist is a promise to the reader, so check the README states it.

    Same reasoning as the rule-catalog tests: anything written down twice
    drifts, so the prose is compared to the set the tests enforce.
    """
    section = _README_SECTION.search(README.read_text(encoding="utf-8"))
    assert section is not None, "README is missing the 'What `harden` does not touch' section"
    documented = set(_README_RULE_ID.findall(section.group(1)))
    assert documented == set(ALLOWED_AFTER_HARDEN), {
        "undocumented": sorted(ALLOWED_AFTER_HARDEN - documented),
        "stale": sorted(documented - ALLOWED_AFTER_HARDEN),
    }
