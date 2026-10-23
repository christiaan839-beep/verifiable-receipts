# Cross-language conformance test suite

**License:** Apache 2.0.

One corpus of JSON fixtures, checked by three verifiers written
separately in TypeScript (node), Python and Go. Every fixture has an
`expected.ok` field, and every verifier must agree with it. The
fixtures test the verifiers; they do not show the verifiers are
correct on inputs the corpus does not cover.

## Files

| File                                            | Purpose                                                                       |
| ----------------------------------------------- | ----------------------------------------------------------------------------- |
| `public-key.pem`                                | The single Ed25519 PEM used for signing the v2 fixtures.                      |
| `fixtures/*.json`                               | The corpus. Each file is one self-describing test vector.                     |
| `conformance.test.ts`                           | TypeScript harness (vitest).                                                  |
| `verify-v2.mjs`                                 | The TypeScript harness's v2 verifier (node:crypto), shared with `roundtrip/`. |
| `conformance.py`                                | Python harness (pytest).                                                      |
| `../verifiable-receipts-go/conformance_test.go` | Go harness (`go test`).                                                       |
| `generate-fixtures.mjs`                         | Regenerates the key and the v2 fixtures (see below).                          |
| `roundtrip/`                                    | Signs and verifies across languages with a throwaway key (see below).         |

## Fixture shape

A v2 receipt fixture:

```json
{
  "description": "v2 valid — well-formed Guardian attestation",
  "receipt": {
    "canonical": "<UTF-8 bytes that were signed>",
    "contentHash": "sha256:<hex>",
    "signature": "v2=<base64>"
  },
  "expected": { "ok": true }
}
```

A receipt may carry other fields beside these three, as signed receipts
do (`"overall": "pass"`, and so on). Each verifier checks every such
field against the parsed `canonical`: it must be there, with an equal
JSON value (numbers by value, objects regardless of key order).

An RFC 9162 inclusion-proof fixture:

```json
{
  "description": "inclusion 4-leaf — proof for index 1 (beta)",
  "leafHashHex": "<hex>",
  "leafIndex": 1,
  "treeSize": 4,
  "auditPath": ["<hex>", "<hex>"],
  "rootHashHex": "<hex>",
  "expected": { "ok": true }
}
```

When `expected.ok` is `false`, the optional `expected.reasonContains`
field gives an i-case regex the verifier's failure reason must match.

## Running the three harnesses

From the root of a clone of this repository:

```bash
# 1. TypeScript (vitest), after `npm install` in packages/verifiable-receipts
(cd packages/verifiable-receipts && npx vitest run conformance)

# 2. Python (pytest), with `cryptography` and `pytest` installed
(cd packages/verifiable-receipts-py && PYTHONPATH=. python3 -m pytest \
    ../verifiable-receipts/conformance/conformance.py -v)

# 3. Go (go test)
(cd packages/verifiable-receipts-go && go test ./... -v -run Conformance)
```

Each harness checks every fixture against its `expected.ok`, and all
three MUST agree. Measured on 24 October 2026: TypeScript 25 passed,
Python 25 passed (one fixture-count check plus one test per fixture), Go
2 tests passed with one subtest per fixture.

## Coverage today

Fixtures cover:

- v2 wire format: well-formed accept · canonical-tamper reject ·
  wrong-key reject · base64 malformed · base64 not canonical (same
  bytes, different spelling) · base64 with a line feed inside (same
  bytes) · non-v2 prefix · `contentHash` present but empty (`""` is
  checked as a hash, not taken for an absent field)
- v2 envelope: fields beside `canonical` that repeat it (a nested
  object's keys in another order) accept · a field that disagrees with
  it (`overall` fail against pass) reject · a field it does not contain
  reject
- RFC 9162 inclusion proof: single-leaf · 2-leaf (idx 1) · 4-leaf
  (idx 1) · 7-leaf asymmetric (idx 4) · 7-leaf rightmost leaf (idx 6) ·
  tampered-root reject · out-of-range index
- Proof input encoding (`docs/specs/transparency-log.md` §3.6), each
  reject: uppercase hex · `0x` prefix · a 64-byte leaf with an empty
  audit-path entry (folds to the 2-leaf root) · leafIndex 1.5 ·
  leafIndex `true` · the 2-leaf proof at treeSize 2^32 + 2

24 fixtures, each checked by all 3 verifiers.

## How to add a fixture

1. A fixture that needs a valid signature under `public-key.pem` has
   to reuse a signature already in the corpus, since the private key
   was discarded: the three envelope fixtures repeat `v2-valid-001.json`'s
   `canonical`, `contentHash` and `signature`, and
   `v2-invalid-noncanonical-base64.json` respells its signature. Add the fixture to
   `generate-fixtures.mjs` as well, so a regeneration reproduces it.
2. Write the fixture to `fixtures/<name>.json`.
3. Run all three harnesses. They MUST all agree on the new
   fixture's expected outcome.
4. Commit the fixture.

## Regenerating the corpus

The v2 fixtures are signed with a throwaway Ed25519 keypair whose
public half lives at `public-key.pem` (committed; the private half is
discarded at generation time). If the corpus ever needs re-signing:

```bash
node packages/verifiable-receipts/conformance/generate-fixtures.mjs
```

This rewrites `public-key.pem` and the eleven `v2-*.json` fixtures in
one pass with a new key; inclusion-proof fixtures are key-independent
and untouched. Re-run all three harnesses afterwards.

## Round trip

`roundtrip/run.sh` makes a throwaway Ed25519 key in a temporary
directory, signs `roundtrip/body.json` with the Python signer
(`sign_v2_receipt`) and with `verifiable-receipts-sign`, and signs a
Guardian attestation with `runGuardian`. It checks that the two signers
wrote the same `canonical`, `contentHash` and signature for the body,
then verifies all three files with the Python, Go and node verifiers,
edits one field of each, and checks that all three verifiers reject the
edits: 18 checks. It deletes the key when it finishes. CI runs it in the
`roundtrip` job.

```bash
(cd packages/verifiable-receipts && npm install)   # builds dist/
pip install ./packages/verifiable-receipts-py      # or just `cryptography`
bash packages/verifiable-receipts/conformance/roundtrip/run.sh
```

It needs node, python with `cryptography`, and go; it reads the Python
package from the working tree.

## Differential run

`differential/run.sh` gives the TypeScript, Python and Go verifiers the
same random receipts and inclusion proofs and fails if they disagree on
any of them or if one raises. `gen.py` signs fresh receipts with a
throwaway key and builds valid inclusion proofs for arbitrary indexes and
tree sizes (by folding a random audit path), then mutates most cases
once or twice: signature spellings (line breaks, padding bits, the
URL-safe alphabet, prefixes), `contentHash` forms, canonical text,
envelope fields and their numbers, duplicate keys, hex case and
prefixes, and index and size edge values. Each verifier parses each case
with its own language's JSON parser, as a caller would.

```bash
bash packages/verifiable-receipts/conformance/differential/run.sh 20000 1
```

The arguments are the number of cases and the seed. The `fuzz` workflow
runs 20,000 cases with seed 1 on every pull request and a million with a
new seed every night; disagreements are uploaded as an artifact. Its
first runs found the Python and Go proof verifiers accepting tree sizes
above 2^53 − 1, and the three receipt verifiers comparing integers above
2^53 in envelope fields differently; both are fixed and in the specs.

## Stability

Once a fixture is in a tagged release its bytes (and the key that
signed it) do not change; new cases are added as new fixtures. No
release is tagged yet.

## License

Apache-2.0.
