"""
Checks the JSON Schemas in schemas/: each is a valid draft 2020-12 schema;
every conformance fixture fits fixture.schema.json; every fixture a
verifier must accept fits the schema for its wire object; and the
fixtures that break an encoding rule (one spelling per hash and
signature, integer indexes) are rejected by the schema too. Each schema
also rejects a valid object with one field broken, including a value
with a trailing newline. The schemas check shape only; signatures and
proofs are the verifiers' job.
"""

from __future__ import annotations

import base64
import functools
import json
from pathlib import Path
from typing import Any

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
    "v2-invalid-empty-contenthash.json",
    "v2-invalid-noncanonical-base64.json",
    "v2-invalid-wrong-version.json",
    "inclusion-0x-prefix.json",
    "inclusion-boolean-index.json",
    "inclusion-fractional-index.json",
    "inclusion-oversized-leaf.json",
    "inclusion-uppercase-hex.json",
}

PROOF_FIELDS = ("leafHashHex", "leafIndex", "treeSize", "auditPath", "rootHashHex")


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = [
        (schema["$id"], Resource.from_contents(schema))
        for schema in (_load(p) for p in sorted(SCHEMAS.glob("*.schema.json")))
    ]
    return Registry().with_resources(resources)


REGISTRY = _registry()


@functools.cache
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
    if "receiptText" in fixture:
        wire, validator = json.loads(fixture["receiptText"]), _validator("receipt.schema.json")
    elif "receipt" in fixture:
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
    accepted = sorted(
        n for n in REJECTED_BY_SCHEMA if _load(FIXTURES / n)["expected"]["ok"] is not False
    )
    assert not accepted, f"fixtures a verifier must accept cannot be rejected by schema: {accepted}"


# A valid object of each kind, to break one field of: the examples, and
# a valid fixture for the receipt and the inclusion proof.
SCHEMA_OF = {
    "tree-head": "tree-head.schema.json",
    "consistency-proof": "consistency-proof.schema.json",
    "cosignature": "cosignature.schema.json",
    "receipt": "receipt.schema.json",
    "inclusion-proof": "inclusion-proof.schema.json",
}


def _valid(kind: str) -> dict[str, Any]:
    if kind == "receipt":
        return _load(FIXTURES / "v2-valid-001.json")["receipt"]
    if kind == "inclusion-proof":
        fixture = _load(FIXTURES / "inclusion-2leaf-idx1.json")
        return {k: fixture[k] for k in PROOF_FIELDS}
    return _load(EXAMPLES / f"{kind}.json")


HASH = _valid("tree-head")["rootHash"]
TIMESTAMP = _valid("tree-head")["timestamp"]
V2 = _valid("tree-head")["signature"]
assert V2.endswith("Ag==")
# A correctly shaped v3= signature: the Ed25519 half of V2 and 3309 bytes
# standing in for an ML-DSA-65 signature.
V3 = V2.replace("v2=", "v3=") + "." + base64.b64encode(bytes(range(256)) * 12 + bytes(237)).decode()
assert len(V3) == 4504
NONCANONICAL_V2 = V2[:-4] + "Ah=="  # same bytes, nonzero padding bits
NONCANONICAL_V3 = V3.replace("Ag==.", "Ah==.")

REQUIRED = {
    "tree-head": ["v", "logId", "treeSize", "rootHash", "timestamp"],
    "consistency-proof": ["oldSize", "newSize", "oldRootHex", "newRootHex", "proof"],
    "cosignature": ["witnessId", "sthCanonical", "signature"],
    "receipt": ["canonical", "signature"],
    "inclusion-proof": list(PROOF_FIELDS),
}

# (kind, path to the field, a value the schema must reject there, label)
BROKEN = [
    ("tree-head", ("rootHash",), HASH.upper(), "uppercase"),
    ("tree-head", ("treeSize",), 2**53, "2^53"),
    ("tree-head", ("treeSize",), -1, "-1"),
    ("tree-head", ("v",), 2, "2"),
    ("tree-head", ("timestamp",), "2026-10-23T12:00:00Z", "no milliseconds"),
    ("tree-head", ("logId",), "", "empty"),
    ("tree-head", ("signature",), NONCANONICAL_V2, "v2 ending Ah=="),
    ("tree-head", ("signature",), NONCANONICAL_V3, "v3 Ed25519 half ending Ah=="),
    ("tree-head", ("signature",), V3[:-4], "v3 ML-DSA-65 half short"),
    ("tree-head", ("signature",), V3 + "====", "v3 ML-DSA-65 half padded"),
    ("tree-head", ("signature",), V3.replace(".", ""), "v3 without separator"),
    ("tree-head", ("signature",), V3.replace(".", " "), "v3 with space separator"),
    ("tree-head", ("signature",), "v1=aG1hYw==", "v1"),
    ("tree-head", ("issuer",), "unsigned claim", "unknown field"),
    ("consistency-proof", ("oldSize",), -1, "-1"),
    ("consistency-proof", ("newSize",), 2**53, "2^53"),
    ("consistency-proof", ("newSize",), 1.5, "fraction"),
    ("consistency-proof", ("proof", 0), "0x" + HASH, "0x prefix"),
    ("consistency-proof", ("oldRootHex",), HASH.upper(), "uppercase"),
    ("consistency-proof", ("proof",), [HASH] * 55, "55 entries"),
    ("consistency-proof", ("kind",), "inclusion", "wrong kind"),
    ("consistency-proof", ("issuer",), "unsigned claim", "unknown field"),
    ("cosignature", ("signature",), NONCANONICAL_V2, "v2 ending Ah=="),
    ("cosignature", ("signature",), V3, "v3"),
    ("cosignature", ("signature",), V2[:-1], "v2 one character short"),
    ("cosignature", ("witnessId",), "", "empty"),
    ("cosignature", ("sthCanonical",), "{", "one character"),
    ("cosignature", ("publicKeyUrl",), "http://witness.example/w1.pem", "http"),
    ("cosignature", ("publicKeyUrl",), "https://witness.example/w 1.pem", "space"),
    ("cosignature", ("publicKeyUrl",), "https://witness.example/w\x001.pem", "NUL"),
    ("cosignature", ("publicKeyUrl",), "https://" + "a" * 2041, "2049 characters"),
    ("receipt", ("signature",), NONCANONICAL_V2, "v2 ending Ah=="),
    ("receipt", ("signature",), NONCANONICAL_V3, "v3 Ed25519 half ending Ah=="),
    ("receipt", ("signature",), "v1=aG1hYw==", "v1"),
    ("receipt", ("contentHash",), "sha256:" + HASH.upper(), "uppercase"),
    ("receipt", ("contentHash",), "0x" + HASH, "0x prefix"),
    ("receipt", ("canonical",), "", "empty"),
    ("inclusion-proof", ("leafIndex",), -1, "-1"),
    ("inclusion-proof", ("leafIndex",), True, "boolean"),
    ("inclusion-proof", ("treeSize",), 0, "0"),
    ("inclusion-proof", ("treeSize",), 2**53, "2^53"),
    ("inclusion-proof", ("auditPath", 0), "0x" + HASH, "0x prefix"),
    ("inclusion-proof", ("auditPath",), [HASH] * 54, "54 entries"),
    ("inclusion-proof", ("rootHashHex",), HASH.upper(), "uppercase"),
    ("inclusion-proof", ("issuer",), "unsigned claim", "unknown field"),
]

# (kind, path to the field, a valid value that a trailing newline breaks, label)
NEWLINE = [
    ("tree-head", ("rootHash",), HASH, "hash"),
    ("tree-head", ("timestamp",), TIMESTAMP, "timestamp"),
    ("tree-head", ("signature",), V2, "v2"),
    ("tree-head", ("signature",), V3, "v3"),
    ("consistency-proof", ("proof", 0), HASH, "hash"),
    ("cosignature", ("signature",), V2, "v2"),
    ("cosignature", ("publicKeyUrl",), "https://witness.example/w1.pem", "url"),
    ("receipt", ("contentHash",), "sha256:" + HASH, "sha256: hash"),
    ("receipt", ("contentHash",), HASH, "bare hash"),
    ("receipt", ("signature",), V2, "v2"),
    ("receipt", ("signature",), V3, "v3"),
    ("inclusion-proof", ("leafHashHex",), HASH, "hash"),
]


# (kind, path to the field, a value at the schema's bound that it must accept, label)
AT_BOUND = [
    ("consistency-proof", ("proof",), [HASH] * 54, "54 entries"),
    ("inclusion-proof", ("auditPath",), [HASH] * 53, "53 entries"),
    ("cosignature", ("publicKeyUrl",), "https://" + "a" * 2040, "2048 characters"),
]


def _with(obj: dict[str, Any], path: tuple[str | int, ...], value: object) -> dict[str, Any]:
    target: Any = obj
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return obj


@pytest.mark.parametrize("kind", SCHEMA_OF)
def test_valid_object_fits_its_schema(kind: str) -> None:
    _validator(SCHEMA_OF[kind]).validate(_valid(kind))


@pytest.mark.parametrize(
    ("kind", "path", "value"),
    [case[:3] for case in BROKEN],
    ids=[f"{kind}-{'.'.join(map(str, path))}-{label}" for kind, path, _, label in BROKEN],
)
def test_schema_rejects_a_broken_field(
    kind: str, path: tuple[str | int, ...], value: object
) -> None:
    validator = _validator(SCHEMA_OF[kind])
    assert validator.is_valid(_valid(kind))
    assert not validator.is_valid(_with(_valid(kind), path, value))


@pytest.mark.parametrize(
    ("kind", "path", "value"),
    [case[:3] for case in AT_BOUND],
    ids=[f"{kind}-{'.'.join(map(str, path))}-{label}" for kind, path, _, label in AT_BOUND],
)
def test_schema_accepts_a_field_at_its_bound(
    kind: str, path: tuple[str | int, ...], value: object
) -> None:
    _validator(SCHEMA_OF[kind]).validate(_with(_valid(kind), path, value))


@pytest.mark.parametrize(
    ("kind", "field"),
    [(kind, field) for kind, fields in REQUIRED.items() for field in fields],
    ids=[f"{kind}-without-{field}" for kind, fields in REQUIRED.items() for field in fields],
)
def test_schema_rejects_a_missing_required_field(kind: str, field: str) -> None:
    validator = _validator(SCHEMA_OF[kind])
    broken = _valid(kind)
    del broken[field]
    assert validator.is_valid(_valid(kind))
    assert not validator.is_valid(broken)


@pytest.mark.parametrize(
    ("kind", "path", "value"),
    [case[:3] for case in NEWLINE],
    ids=[f"{kind}-{'.'.join(map(str, path))}-{label}" for kind, path, _, label in NEWLINE],
)
def test_trailing_newline_is_rejected(kind: str, path: tuple[str | int, ...], value: str) -> None:
    # Python's re.search lets $ match before a final newline, so the
    # pattern alone would pass these; the length bounds must catch them.
    validator = _validator(SCHEMA_OF[kind])
    assert validator.is_valid(_with(_valid(kind), path, value))
    assert not validator.is_valid(_with(_valid(kind), path, value + "\n"))


def test_open_shapes_take_extra_fields() -> None:
    # receipts-log serves cosignatures with these fields beside the signed ones.
    served = _valid("cosignature") | {
        "treeSize": 2,
        "rootHash": HASH,
        "timestamp": TIMESTAMP,
        "receivedAt": TIMESTAMP,
    }
    _validator("cosignature.schema.json").validate(served)
    # A receipt repeats fields of its canonical beside the envelope (VAOS 2.0 section 7).
    _validator("receipt.schema.json").validate(_valid("receipt") | {"runId": "r1"})
    _validator("receipt.schema.json").validate(_valid("receipt") | {"contentHash": None})
