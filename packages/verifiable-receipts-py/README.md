# sovereign-matrix-verifiable-receipts (Python)

Python verifier for Sovereign Matrix receipts, the counterpart to the
TypeScript library in [`../verifiable-receipts`](../verifiable-receipts).
Version 0.1.0, Apache-2.0 (see [LICENSE](./LICENSE)).

It verifies Ed25519-signed v2 receipts, Guardian attestation envelopes and
RFC 9162 transparency-log inclusion proofs. It does not sign receipts, and
it does not verify ML-DSA-65 (`v3=`) signatures yet.

Not published to PyPI yet: install it from this repository.

## Install

Python 3.10 or later. One dependency, `cryptography`, which pip installs
for you.

```bash
git clone https://github.com/christiaan839-beep/verifiable-receipts
pip install ./verifiable-receipts/packages/verifiable-receipts-py
```

## Verify a v2 receipt

A v2 receipt carries `canonical` (the exact UTF-8 JSON that was signed),
`contentHash` (`sha256:` plus the hex SHA-256 of `canonical`) and
`signature` (`v2=` plus the base64 Ed25519 signature over `canonical`).

```python
from sovereign_matrix.verifiable_receipts import verify_v2_receipt

public_key_pem = open("ed25519.pem", "rb").read()

receipt = {
    "verdictId": "v_…",
    "overall": "pass",
    "issuedAt": "2026-…",
    "canonical": "{…}",
    "contentHash": "sha256:…",
    "signature": "v2=…",
}

result = verify_v2_receipt(receipt, public_key_pem)
print(result.ok)      # True or False
print(result.reason)  # None, or why it failed
```

If `contentHash` is present, the verifier also checks it against
`canonical`.

## Verify an inclusion proof

```python
from sovereign_matrix.verifiable_receipts import verify_inclusion_proof

proof = {"leafIndex": 42, "treeSize": 100, "auditPath": ["…", "…"]}
ok = verify_inclusion_proof(proof, leaf_hash_hex, root_hash_hex)
```

## Tests

Measured on 16 October 2026: **22 passed** (pytest, Python 3.13).

```bash
pip install pytest
python -m pytest verifiable-receipts/packages/verifiable-receipts-py/tests
```

The cross-language conformance suite, which runs this verifier against the
shared fixtures, is
[`../verifiable-receipts/conformance/conformance.py`](../verifiable-receipts/conformance/conformance.py)
(12 passed on the same day).

## License

Apache-2.0; see [LICENSE](./LICENSE). Report suspected bugs in the
verification code privately to `security@sovereignmatrix.agency` (the
security contact in
[SPEC.md](../verifiable-receipts/SPEC.md#contact)) before disclosing them.
