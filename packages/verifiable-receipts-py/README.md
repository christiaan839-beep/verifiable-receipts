# sovereign-matrix-verifiable-receipts (Python)

Python signer and verifier for VAOS receipts, the counterpart
to the TypeScript library in [`../verifiable-receipts`](../verifiable-receipts).
Version 0.3.0, Apache-2.0 (see [LICENSE](./LICENSE)).

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

0. The receipt nests at most 64 deep (VAOS 2.0 §7.2): the receipt is one
   level, and each list or dict in it one more.
1. `canonical` and `signature` are non-empty strings, and `signature` is
   `v2=` followed by canonical standard base64 (padding bits zero). The
   public key is a canonical encoding of a point of order L: not of
   small or mixed order, not off the curve (VAOS 2.0 §7.3, the strict
   profile).
2. If `contentHash` is present, it equals the hex SHA-256 of the UTF-8
   bytes of `canonical` (the `sha256:` prefix is optional).
3. The Ed25519 signature verifies over the UTF-8 bytes of `canonical`,
   exactly as given. Before `cryptography` sees it, its R must be a
   canonical encoding of a point of order L (not of small order, the
   identity included, nor of mixed order) and its S below L: so this
   verifier, the TypeScript one on Node.js 22 or 24 and the Go one give
   the same verdict on every signature. `verify_ed25519(public_key,
   message, signature)` makes the same checks on one raw signature.
4. `canonical` nests at most 64 deep, counted on its text before it is
   parsed, and parses as a JSON object.
5. Every other field of the receipt is in that object with an equal JSON
   value (numbers by value, objects regardless of key order; a number of
   magnitude 2^53 or more equals nothing, as in the TypeScript and Go
   verifiers, since JavaScript cannot tell 2^53 from 2^53 + 1). A field
   that disagrees, such as `"overall": "fail"` beside a canonical that
   says `"pass"`, or that the canonical does not contain, fails the
   check.

It does not re-derive `canonical` from the other fields, so it accepts
receipts whose `canonical` uses another key order. It returns a
`VerifyResult` for any input, however deep. To read a receipt from JSON
text, `parse_receipt(text)` counts its depth first and raises
`ValueError("receipt nesting deeper than 64")`, where `json.loads` alone
raises `RecursionError` some thousands of levels down; `sign_v2_receipt` refuses a
body nested deeper than 64 with a `ValueError`.

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

## MCP server

`verifiable-receipts-mcp` serves three read-only tools over stdio to any
[Model Context Protocol](https://modelcontextprotocol.io) client. It makes
no network request and keeps no state. It needs the `mcp` extra.

| Tool | Checks |
|---|---|
| `verify_receipt` | One receipt (its JSON text) against the issuer's public key (PEM). Returns `ok` and the failure `reason`. |
| `verify_receipt_log` | Every receipt in a JSONL log against one key: counts and one verdict per line. |
| `verify_receipt_in_log` | A receipt's RFC 9162 inclusion proof (`leaf_index`, `tree_size`, `audit_path`) against a tree head's root hash. It does not check the tree head's signature. |

Each tool accepts up to 4 MiB of text; `verify_receipt_log` checks up to
10,000 receipts per call.

Add it to Claude Code:

```bash
claude mcp add verifiable-receipts -- uvx --from "sovereign-matrix-verifiable-receipts[mcp]" verifiable-receipts-mcp
```

Before the package is on PyPI, install it from the repository instead:

```bash
claude mcp add verifiable-receipts -- uvx --from "sovereign-matrix-verifiable-receipts[mcp] @ git+https://github.com/christiaan839-beep/verifiable-receipts@main#subdirectory=packages/verifiable-receipts-py" verifiable-receipts-mcp
```

Other clients take the same command in their server configuration:

```json
{
  "mcpServers": {
    "verifiable-receipts": {
      "command": "uvx",
      "args": ["--from", "sovereign-matrix-verifiable-receipts[mcp]", "verifiable-receipts-mcp"]
    }
  }
}
```

A pass proves that the holder of the issuer's private key signed exactly
the receipt's canonical text. It does not prove the content is true or
that a log is complete, and it is only as good as the public key: get the
key from the issuer, not from whoever sent the receipts.

## Tests

Measured on 29 October 2026: **149 passed** (pytest, Python 3.12, with the `mcp`
extra; without it the MCP server's tests are skipped).

```bash
pip install "./verifiable-receipts/packages/verifiable-receipts-py[test,mcp]"
python -m pytest verifiable-receipts/packages/verifiable-receipts-py/tests
```

The cross-language conformance suite, which runs this verifier against the
shared fixtures, is
[`../verifiable-receipts/conformance/conformance.py`](../verifiable-receipts/conformance/conformance.py)
(31 passed on the same day). The round trip in
[`../verifiable-receipts/conformance/roundtrip/`](../verifiable-receipts/conformance/roundtrip)
signs with this package and checks the result in Go and node.

## License

Apache-2.0; see [LICENSE](./LICENSE). Report a suspected vulnerability
privately, as the repository's [SECURITY.md](../../SECURITY.md) says.
