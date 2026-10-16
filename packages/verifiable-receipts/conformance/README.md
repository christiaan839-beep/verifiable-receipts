# Cross-language conformance test suite

**License:** Apache 2.0.

This directory makes the "three-language symmetric verifier" claim
**publicly auditable**. A single JSON fixture corpus is checked by
three independent reference verifiers — TypeScript, Python, and Go.
Every fixture has an `expected.ok` field; every verifier MUST agree.

## Why this exists

Without a conformance corpus, "we have a Python verifier and a Go
verifier" is a marketing claim. With this corpus, it is a public,
deterministic, byte-level proof. An auditor can clone the repo, run
all three harnesses, and confirm they reach identical conclusions on
every receipt.

Same playbook used by:

- The [Certificate Transparency](https://github.com/google/certificate-transparency-go)
  cross-implementation test vectors.
- The [JOSE](https://github.com/panva/jose) cross-language conformance fixtures.
- The [Sigstore](https://github.com/sigstore/sigstore-conformance) suite.

## Files

| File                                            | Purpose                                                   |
| ----------------------------------------------- | --------------------------------------------------------- |
| `public-key.pem`                                | The single Ed25519 PEM used for signing the v2 fixtures.  |
| `fixtures/*.json`                               | The corpus. Each file is one self-describing test vector. |
| `conformance.test.ts`                           | TypeScript harness (vitest).                              |
| `conformance.py`                                | Python harness (pytest).                                  |
| `../verifiable-receipts-go/conformance_test.go` | Go harness (`go test`).                                   |

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
three MUST agree. Measured on 16 October 2026: TypeScript 12 passed,
Python 12 passed (one fixture-count check plus one test per fixture), Go
2 tests passed with one subtest per fixture.

## Coverage today

Fixtures cover:

- v2 wire format: well-formed accept · canonical-tamper reject ·
  wrong-key reject · base64 malformed · non-v2 prefix
- RFC 9162 inclusion proof: single-leaf · 4-leaf (idx 1) · 7-leaf
  asymmetric (idx 4) · 7-leaf rightmost leaf (idx 6) · tampered-root
  reject · out-of-range index

11 fixtures × 3 verifiers = **33 cross-language conformance checks.**

## How to add a fixture

1. Generate signed bytes via the TypeScript canonical implementation
   (`@sovereign-matrix/verifiable-receipts`). Issuer-side signing is
   the only canonical path.
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

This rewrites `public-key.pem` and the five `v2-*.json` fixtures in
one deterministic pass; inclusion-proof fixtures are key-independent
and untouched. Re-run all three harnesses afterwards.

## Stability guarantee

Fixtures in this corpus are **frozen**. Once a fixture is published
in a tagged release, its byte contents (including the keypair used
to sign it) MUST NOT change. New tests are added; existing fixtures
are never silently mutated.

This guarantee lets external auditors pin a fixture by its
sha256 and re-run the harness against any future verifier version
to detect verification drift.

## License

Apache 2.0 © Sovereign Matrix.
