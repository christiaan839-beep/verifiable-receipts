# verifiable-receipts

Signed receipts for AI calls: a record of what an AI agent was asked,
what it answered and which checks ran, signed so that anyone with the
issuer's public key can verify it later.

The code lives here, in three packages:

| Language   | Path                                                                 | Role                                 |
| ---------- | -------------------------------------------------------------------- | ------------------------------------ |
| TypeScript | [`packages/verifiable-receipts`](packages/verifiable-receipts)       | Signs and verifies (source of truth) |
| Python     | [`packages/verifiable-receipts-py`](packages/verifiable-receipts-py) | Verifies                             |
| Go         | [`packages/verifiable-receipts-go`](packages/verifiable-receipts-go) | Verifies                             |

The v2 wire format is written down in
[`docs/specs/vaos-2.0.md`](docs/specs/vaos-2.0.md), and the formats the
TypeScript package emits and accepts in
[`packages/verifiable-receipts/SPEC.md`](packages/verifiable-receipts/SPEC.md).

## What a signed receipt is

A v2 receipt looks like this (values shortened):

```json
{
  "verdictId": "v_…",
  "overall": "pass",
  "issuedAt": "2026-…",
  "canonical": "{…}",
  "contentHash": "sha256:…",
  "signature": "v2=…"
}
```

- `canonical` is the exact UTF-8 JSON string that was signed.
- `contentHash` is `sha256:` followed by the hex SHA-256 of `canonical`.
- `signature` is `v2=` followed by the base64 Ed25519 signature over
  `canonical`.

A `v3=` receipt signs the same `canonical` twice:
`v3=<ed25519>.<ml-dsa-65>`, where ML-DSA-65 is the post-quantum signature
of FIPS 204.

## How to verify

1. Hash `canonical` with SHA-256 and compare it with `contentHash`.
2. Check the Ed25519 signature after `v2=` over `canonical` with the
   issuer's public key.

If one byte of `canonical` changes, the hash no longer matches; if
another key signed it, the signature does not hold.

## What each verifier checks

- **Python** (`verify_v2_receipt`, `verify_inclusion_proof`): v2
  (Ed25519) receipts, first `contentHash` when the receipt has one, then
  the signature; and RFC 9162 transparency-log inclusion proofs.
  `verify_guardian_attestation` is the same v2 check under another name.
  It does not sign, and it does not verify `v3=` (ML-DSA-65) signatures.
- **Go** (`VerifyV2Receipt`, `VerifyInclusionProof`): the same checks as
  the Python verifier, using only the Go standard library.
  `VerifyGuardianAttestation` is the same v2 check under another name. It
  does not sign, and it does not verify `v3=` signatures.
- **TypeScript**: signs and verifies the `v3=` dual signature. ML-DSA-65
  signing and verification are built in (`signMlDsa65`, `verifyMlDsa65`);
  `verifyDualSig` passes only when both halves hold, and checks the
  Ed25519 half with a function you supply (for example from
  `node:crypto`). Ed25519 is bring-your-own throughout: `runGuardian`
  takes a signer and `verifyGuardianAttestation` a verifier, while the
  `verifiable-receipts-sign` CLI signs `v2=` or `v3=` receipts with
  `node:crypto`. It also provides the transparency log: RFC 9162 Merkle
  tree hashes, inclusion and consistency proofs with their verification,
  and tree heads for the caller to sign.
- **In the browser**: the Sovereign Matrix studio's receipts demo checks
  `v2=` receipts with WebCrypto (SHA-256 against `contentHash`, then
  Ed25519 over `canonical`). That demo belongs to the studio's site, not
  to this repository.

## Install from this repository

None of these are on npm or PyPI yet. Clone the repository:

```bash
git clone https://github.com/christiaan839-beep/verifiable-receipts
cd verifiable-receipts
```

**Python** (3.10 or later):

```bash
pip install ./packages/verifiable-receipts-py
```

```python
from sovereign_matrix.verifiable_receipts import verify_v2_receipt

result = verify_v2_receipt(receipt, open("ed25519.pem", "rb").read())
print(result.ok, result.reason)
```

**TypeScript** (Node 18 or later). `dist/` is not committed, so build it
once in the clone, then install the package into your own project:

```bash
(cd packages/verifiable-receipts && npm install)   # builds dist/
# then, from your own project:
npm install --install-links /path/to/verifiable-receipts/packages/verifiable-receipts
```

**Go** (1.22 or later). Once this code is on `main`:

```bash
go get github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go@latest
```

Until then, point your module at the clone:

```bash
go mod edit -replace github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go=/path/to/verifiable-receipts/packages/verifiable-receipts-go
go mod tidy
```

## Run the tests

```bash
# TypeScript
(cd packages/verifiable-receipts && npm install && npm test)

# Python
pip install ./packages/verifiable-receipts-py pytest
python -m pytest packages/verifiable-receipts-py/tests packages/verifiable-receipts/conformance/conformance.py

# Go
(cd packages/verifiable-receipts-go && go test ./...)
```

Measured on 16 October 2026 (Node 22, Python 3.13, Go 1.24):

| Verifier   | Result                                                  |
| ---------- | ------------------------------------------------------- |
| TypeScript | 681 passed, 4 skipped (22 test files, vitest 3)         |
| Python     | 22 passed, and 12 passed in the conformance suite       |
| Go         | 23 tests passed, one of them with a subtest per fixture |

The four skipped TypeScript tests are the witness CLI's network flow,
skipped in `tests/witness-cli.test.ts`.

All three verifiers run against the same 11 conformance fixtures in
[`packages/verifiable-receipts/conformance/fixtures/`](packages/verifiable-receipts/conformance/fixtures)
(a valid receipt, a tampered one, one signed with another key, bad
base64, a `v1=` prefix, and six inclusion proofs) and agree on each one.

## Status

The TypeScript package is at version 0.3.0 and the Python package at
0.1.0; the Go module has no version tag yet. All three are tested and
none is published to a package registry.

Moved from the sovereign-v2 repository on 16 October 2026, at commit
`8c14ce7156e9533fba7a4465e3b8661a20a0f40c`. In the move the Go module
path changed to
`github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go`,
the Python and Go packages got their own LICENSE files, the TypeScript
package gained the dev dependencies it needs to build and test on its own,
and every link now points here.

## License

Apache-2.0: see [LICENSE](./LICENSE). Each package also carries its own
Apache-2.0 LICENSE file. The spec in [`docs/specs/`](docs/specs) is CC0
1.0, as its header says.
