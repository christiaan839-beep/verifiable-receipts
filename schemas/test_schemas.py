"""
Checks the JSON Schemas in schemas/: each is a valid draft 2020-12 schema;
every conformance fixture fits fixture.schema.json; every fixture a
verifier must accept fits the schema for its wire object; and the
fixtures that break an encoding rule (one spelling per hash and
signature, integer indexes) are rejected by the schema too. The schemas
check shape only; signatures and proofs are the verifiers' job.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

SCHEMAS = Path(__file__).parent
FIXTURES = SCHEMAS.parent / "packages" / "verifiable-receipts" / "conformance" / "fixtures"
EXAMPLES = SCHEMAS / "examples"

# Fixtures whose failure is an encoding rule the schemas state, not a
# signature or proof the schemas cannot check.
REJECTED_BY_SCHEMA = {
    "v2-invalid-bad-base64.json",
    "v2-invalid-crlf-base64.json",
    "v2-invalid-noncanonical-base64.json",
    "v2-invalid-wrong-version.json",
    "inclusion-0x-prefix.json",
    "inclusion-boolean-index.json",
    "inclusion-fractional-index.json",
    "inclusion-oversized-leaf.json",
    "inclusion-uppercase-hex.json",
}

PROOF_FIELDS = ("leafHashHex", "leafIndex", "treeSize", "auditPath", "rootHashHex")


def _load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = [
        (schema["$id"], Resource.from_contents(schema))
        for schema in (_load(p) for p in sorted(SCHEMAS.glob("*.schema.json")))
    ]
    return Registry().with_resources(resources)


REGISTRY = _registry()


def _validator(name: str) -> Draft202012Validator:
    schema = _load(SCHEMAS / name)
    return Draft202012Validator(schema, registry=REGISTRY)


def _fixture_files() -> list[Path]:
    files = sorted(FIXTURES.glob("*.json"))
    assert files, f"no fixtures in {FIXTURES}"
    return files


@pytest.mark.parametrize("path", sorted(SCHEMAS.glob("*.schema.json")), ids=lambda p: p.name)
def test_schema_is_valid_draft_2020_12(path: Path) -> None:
    Draft202012Validator.check_schema(_load(path))


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: p.name)
def test_fixture_fits_the_fixture_schema(path: Path) -> None:
    _validator("fixture.schema.json").validate(_load(path))


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: p.name)
def test_wire_object_matches_the_expected_outcome(path: Path) -> None:
    fixture = _load(path)
    assert isinstance(fixture, dict)
    if "receipt" in fixture:
        wire, validator = fixture["receipt"], _validator("receipt.schema.json")
    else:
        wire = {k: fixture[k] for k in PROOF_FIELDS}
        validator = _validator("inclusion-proof.schema.json")
    fits = validator.is_valid(wire)
    if fixture["expected"]["ok"]:
        assert fits, f"{path.name} must be accepted, so its wire object must fit the schema"
    elif path.name in REJECTED_BY_SCHEMA:
        assert not fits, f"{path.name} breaks an encoding rule the schema states"
    else:
        assert fits, f"{path.name} fails a check the schema cannot make, so its shape must fit"


@pytest.mark.parametrize(
    ("example", "schema"),
    [
        ("tree-head.json", "tree-head.schema.json"),
        ("consistency-proof.json", "consistency-proof.schema.json"),
        ("cosignature.json", "cosignature.schema.json"),
    ],
)
def test_example_fits_its_schema(example: str, schema: str) -> None:
    _validator(schema).validate(_load(EXAMPLES / example))


def test_rejected_by_schema_names_real_fixtures() -> None:
    names = {p.name for p in _fixture_files()}
    assert REJECTED_BY_SCHEMA <= names, sorted(REJECTED_BY_SCHEMA - names)
