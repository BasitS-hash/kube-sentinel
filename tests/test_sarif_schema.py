"""Validate emitted SARIF against the official SARIF 2.1.0 JSON schema.

The schema is vendored under ``tests/fixtures`` so the test runs fully offline
and deterministically in CI. GitHub code scanning rejects SARIF that does not
conform, so schema conformance is a load-bearing guarantee, not a nicety.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from kube_sentinel.engine import scan_resources
from kube_sentinel.models import Resource
from kube_sentinel.parser import parse_path
from kube_sentinel.report import to_sarif
from kube_sentinel.rules import load_default_rules

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"


@pytest.fixture(scope="module")
def sarif_validator() -> jsonschema.protocols.Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    return validator_cls(schema)


def test_insecure_sarif_conforms_to_schema(
    insecure_dir: Path, sarif_validator: jsonschema.protocols.Validator
) -> None:
    report = scan_resources(parse_path(insecure_dir).resources)
    document = json.loads(to_sarif(report, load_default_rules()))

    # Raises SchemaError/ValidationError with a precise path on any deviation.
    sarif_validator.validate(document)


def test_clean_sarif_conforms_to_schema(
    hardened_dir: Path, sarif_validator: jsonschema.protocols.Validator
) -> None:
    report = scan_resources(parse_path(hardened_dir).resources)
    document = json.loads(to_sarif(report, load_default_rules()))
    assert document["runs"][0]["results"] == []
    sarif_validator.validate(document)


def test_cross_resource_finding_sarif_conforms(
    sarif_validator: jsonschema.protocols.Validator,
) -> None:
    # A namespace with a workload but no NetworkPolicy produces the
    # cross-resource KS-NET-003 finding, whose rule is declared out-of-band.
    pod = Resource(
        kind="Pod",
        name="p",
        namespace="app",
        api_version="v1",
        file_path="mem://p",
        doc_index=0,
        raw={"kind": "Pod", "spec": {"containers": [{"name": "c"}]}},
    )
    report = scan_resources((pod,))
    document = json.loads(to_sarif(report, load_default_rules()))
    result_ids = {r["ruleId"] for r in document["runs"][0]["results"]}
    declared_ids = {r["id"] for r in document["runs"][0]["tool"]["driver"]["rules"]}
    assert "KS-NET-003" in result_ids
    assert result_ids <= declared_ids
    sarif_validator.validate(document)
