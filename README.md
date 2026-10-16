# verifiable-receipts

Signed receipts for AI calls: a record of what an AI agent was asked,
what it answered and which checks ran, signed so that anyone with the
issuer's public key can verify it later.

The code lives here, in three packages:

| Language   | Path                                                                 | Role                                 |
| ---------- | -------------------------------------------------------------------- | ------------------------------------ |
| TypeScript | [`packages/verifiable-receipts`](packages/verifiable-receipts)       | Signs and verifies (source of truth) |
| Python     | [`packages/verifiable-receipts-py`](packages/verifiable-receipts-py) | Signs and verifies v2 receipts       |
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
- Every other field (`verdictId`, `overall`, `issuedAt` here) repeats
  the field of the same name in `canonical`.

A `v3=` receipt signs the same `canonical` twice:
`v3=<ed25519>.<ml-dsa-65>`, where ML-DSA-65 is the post-quantum signature
of FIPS 204.

## How to verify

1. Hash `canonical` with SHA-256 and compare it with `contentHash`.
2. Check the Ed25519 signature after `v2=` over `canonical` with the
   issuer's public key.
3. Parse `canonical` as a JSON object.
4. Check that every other field of the receipt is in that object with
   an equal JSON value (numbers by value, objects regardless of key
   order).

If one byte of `canonical` changes, the hash no longer matches; if
another key signed it, the signature does not hold; if a field beside
`canonical` says something `canonical` does not, such as
`"overall": "fail"` beside a signed `"pass"`, or is missing from it,
step 4 fails. Verifiers check `canonical` as given and do not re-derive
it from the other fields
([`docs/specs/vaos-2.0.md`](docs/specs/vaos-2.0.md) §5 and §7).

## What each verifier checks

- **Python** (`verify_v2_receipt`, `verify_inclusion_proof`): v2
  (Ed25519) receipts, the four steps above in that order (`contentHash`
  only when the receipt has one); and RFC 9162 transparency-log
  inclusion proofs. `verify_guardian_attestation` makes the same checks
  on an attestation from the TypeScript `runGuardian`, but skips the
  fields its canonical does not sign (`totalMs`, and each rule's
  `durationMs` and `evidence`) and compares each rule as
  `{ruleId, verdict, reason}` in any order. `sign_v2_receipt` signs v2
  receipts: it builds `canonical` with `canonicalize` (keys sorted at
  every depth; floats refused) and returns the body with `canonical`,
  `contentHash` and `signature`. It does not sign or verify `v3=`
  (ML-DSA-65) signatures.
- **Go** (`VerifyV2Receipt`, `VerifyGuardianAttestation`,
  `VerifyInclusionProof`): the same checks as the Python verifier, using
  only the Go standard library. Unmarshal a receipt's JSON into
  `Receipt` so that its other fields reach `Envelope` and are checked.
  It does not sign, and it does not verify `v3=` signatures.
- **TypeScript**: signs and verifies the `v3=` dual signature. ML-DSA-65
  signing and verification are built in (`signMlDsa65`, `verifyMlDsa65`);
  `verifyDualSig` passes only when both halves hold, and checks the
  Ed25519 half with a function you supply (for example from
  `node:crypto`). Ed25519 is bring-your-own throughout: `runGuardian`
  takes a signer and `verifyGuardianAttestation` a verifier, while the
  `verifiable-receipts-sign` CLI signs `v2=` or `v3=` receipts with
  `node:crypto` and writes `canonical`, `contentHash` and `signature`
  beside the body's fields, so its `v2=` receipts verify in Python and
  Go. `verifyGuardianAttestation` rebuilds the Guardian canonical from
  the attestation's `verdictId`, `overall`, `rules` and `issuedAt`,
  requires it to equal `canonical` byte for byte, then checks
  `contentHash` and the signature; it does not look at any other field
  (the Python and Go Guardian checks reject one that `canonical` does
  not contain). It also provides the transparency log: RFC 9162 Merkle
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
from sovereign_matrix.verifiable_receipts import sign_v2_receipt, verify_v2_receipt

receipt = sign_v2_receipt({"verdictId": "v_1", "overall": "pass"}, private_key)
result = verify_v2_receipt(receipt, open("ed25519.pem", "rb").read())
print(result.ok, result.reason)
```

`private_key` is an Ed25519 private key from `cryptography`; the
package's [README](packages/verifiable-receipts-py) shows how to load
one.

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

# Cross-language round trip (needs all three toolchains, and the
# TypeScript package built by the npm install above)
bash packages/verifiable-receipts/conformance/roundtrip/run.sh
```

Measured on 16 October 2026 (Node 22, Python 3.13, Go 1.24):

| Suite      | Result                                                  |
| ---------- | ------------------------------------------------------- |
| TypeScript | 689 passed, 4 skipped (22 test files, vitest 3)         |
| Python     | 66 passed, and 15 passed in the conformance suite       |
| Go         | 36 tests passed, one of them with a subtest per fixture |
| Round trip | 18 checks passed                                        |

The four skipped TypeScript tests are the witness CLI's network flow,
skipped in `tests/witness-cli.test.ts`.

All three verifiers run against the same 14 conformance fixtures in
[`packages/verifiable-receipts/conformance/fixtures/`](packages/verifiable-receipts/conformance/fixtures)
(a valid receipt, a tampered one, one signed with another key, bad
base64, a `v1=` prefix, three receipts whose fields beside `canonical`
agree with it, disagree with it or are missing from it, and six
inclusion proofs) and agree on each one.

The round trip makes a throwaway Ed25519 key, signs a receipt with the
Python signer and another with `verifiable-receipts-sign`, and a Guardian
attestation with `runGuardian`; it verifies each with the Python, Go and
node verifiers, and checks that all three reject a copy of each with one
field edited. CI runs it on every push.

## Status

The TypeScript package is at version 0.3.1 and the Python package at
0.2.0; the Go module has no version tag yet. All three are tested and
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
