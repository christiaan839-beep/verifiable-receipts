# sovereign-matrix-verifiable-receipts (Python)

Python signer and verifier for Sovereign Matrix receipts, the counterpart
to the TypeScript library in [`../verifiable-receipts`](../verifiable-receipts).
Version 0.2.0, Apache-2.0 (see [LICENSE](./LICENSE)).

It signs and verifies Ed25519 (`v2=`) receipts, verifies Guardian
attestations from the TypeScript `runGuardian`, and verifies RFC 9162
transparency-log inclusion proofs. It does not sign or verify ML-DSA-65
(`v3=`) signatures.

Not published to PyPI yet: install it from this repository.

## Install

Python 3.10 or later. One dependency, `cryptography`, which pip installs
for you.

```bash
git clone https://github.com/christiaan839-beep/verifiable-receipts
pip install ./verifiable-receipts/packages/verifiable-receipts-py
```

## Sign a v2 receipt

```python
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from sovereign_matrix.verifiable_receipts import sign_v2_receipt

private_key = load_pem_private_key(open("ed25519-private.pem", "rb").read(), password=None)

receipt = sign_v2_receipt(
    {"verdictId": "v_1", "overall": "pass", "issuedAt": "2026-10-16T00:00:00Z"},
    private_key,  # an Ed25519PrivateKey
)
# {"verdictId": ..., "overall": ..., "issuedAt": ...,
#  "canonical": "{...}", "contentHash": "sha256:...", "signature": "v2=..."}
```

`canonicalize(body)` builds `canonical`: compact JSON with object keys
sorted at every depth (in UTF-16 code-unit order, as JavaScript sorts
them) and non-ASCII text written as UTF-8. It accepts dicts with string
keys, lists, strings, ints, bools and None, and raises `TypeError` on
anything else, floats included: JavaScript and Python print floats
differently (`1` and `1.0`), so a float would canonicalize differently in
each language. Write a fraction as a string or a scaled int.

`sign_v2_receipt` drops any `canonical`, `contentHash` and `signature`
already in the body, signs the UTF-8 bytes of `canonicalize(body)` with
Ed25519, and returns the body's fields plus `canonical`, `contentHash`
(`sha256:` plus the hex SHA-256 of `canonical`) and `signature`
(`v2=` plus the base64 signature). For a body without floats or
integer-like keys (`"2"`, `"10"`) it writes the same `canonical` as the
TypeScript `verifiable-receipts-sign` CLI.

## Verify a v2 receipt

```python
from sovereign_matrix.verifiable_receipts import verify_v2_receipt

public_key_pem = open("ed25519.pem", "rb").read()

result = verify_v2_receipt(receipt, public_key_pem)
print(result.ok)      # True or False
print(result.reason)  # None, or why it failed
```

`verify_v2_receipt` checks, in this order:

1. `canonical` and `signature` are non-empty strings, and `signature` is
   `v2=` followed by standard base64.
2. If `contentHash` is present, it equals the hex SHA-256 of the UTF-8
   bytes of `canonical` (the `sha256:` prefix is optional).
3. The Ed25519 signature verifies over the UTF-8 bytes of `canonical`,
   exactly as given.
4. `canonical` parses as a JSON object.
5. Every other field of the receipt is in that object with an equal JSON
   value (numbers by value, objects regardless of key order). A field
   that disagrees, such as `"overall": "fail"` beside a canonical that
   says `"pass"`, or that the canonical does not contain, fails the
   check.

It does not re-derive `canonical` from the other fields, so it accepts
receipts whose `canonical` uses another key order.

## Verify a Guardian attestation

`verify_guardian_attestation(attestation, public_key_pem)` makes the
same checks on an attestation from the TypeScript `runGuardian`, except
for the fields its canonical does not sign: it skips `totalMs`, compares
each rule in `rules` as `{ruleId, verdict, reason}` (a missing `reason`
reads as null) in any order, and skips each rule's `durationMs` and
`evidence`. No signature covers those skipped fields.

## Verify an inclusion proof

```python
from sovereign_matrix.verifiable_receipts import verify_inclusion_proof

proof = {"leafIndex": 42, "treeSize": 100, "auditPath": ["…", "…"]}
ok = verify_inclusion_proof(proof, leaf_hash_hex, root_hash_hex)
```

## Tests

Measured on 16 October 2026: **66 passed** (pytest, Python 3.13).

```bash
pip install pytest
python -m pytest verifiable-receipts/packages/verifiable-receipts-py/tests
```

The cross-language conformance suite, which runs this verifier against the
shared fixtures, is
[`../verifiable-receipts/conformance/conformance.py`](../verifiable-receipts/conformance/conformance.py)
(15 passed on the same day). The round trip in
[`../verifiable-receipts/conformance/roundtrip/`](../verifiable-receipts/conformance/roundtrip)
signs with this package and checks the result in Go and node.

## License

Apache-2.0; see [LICENSE](./LICENSE). Report suspected bugs in the
verification code privately to `security@sovereignmatrix.agency` (the
security contact in
[SPEC.md](../verifiable-receipts/SPEC.md#contact)) before disclosing them.
