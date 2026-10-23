# verifiable-receipts

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/christiaan839-beep/verifiable-receipts/badge)](https://scorecard.dev/viewer/?uri=github.com/christiaan839-beep/verifiable-receipts)

Sign a record of what an AI agent did, and let anyone with the issuer's
public key check it later.

A receipt is a JSON object whose `canonical` field holds the exact
string that was signed, plus a SHA-256 of it and an Ed25519 signature
(`v2=`) or an Ed25519 and ML-DSA-65 dual signature (`v3=`). Around
that, the TypeScript package provides a Merkle transparency log
(RFC 6962 / RFC 9162 hashing, inclusion and consistency proofs), m-of-n
co-signed receipts, a commitment over the chunks of a streamed output,
and a signed ZIP bundle of receipts. Python and Go packages verify the
same receipts independently, against a shared set of fixtures.

None of the packages is published to a registry yet. This is 0.x
software by one author, not independently reviewed.

| Package                                                                 | Language   | Does                                                         |
| ----------------------------------------------------------------------- | ---------- | ------------------------------------------------------------ |
| [`packages/verifiable-receipts`](packages/verifiable-receipts)          | TypeScript | Signs and verifies `v2=` and `v3=`; log, co-signing, bundles |
| [`packages/verifiable-receipts-py`](packages/verifiable-receipts-py)    | Python     | Signs and verifies `v2=`; verifies inclusion proofs          |
| [`packages/verifiable-receipts-go`](packages/verifiable-receipts-go)    | Go         | Verifies `v2=` and inclusion proofs (standard library only)  |

## The receipt format

```json
{
  "verdictId": "v_1",
  "overall": "pass",
  "canonical": "{\"overall\":\"pass\",\"verdictId\":\"v_1\"}",
  "contentHash": "sha256:…",
  "signature": "v2=…"
}
```

A verifier:

1. checks that `contentHash` (if present) is `sha256:` plus the hex
   SHA-256 of `canonical`;
2. checks the signature over the bytes of `canonical`, exactly as given;
3. parses `canonical` as a JSON object;
4. checks that every other field of the receipt is in that object with
   an equal value, and rejects the receipt otherwise.

The formats are specified in
[`packages/verifiable-receipts/SPEC.md`](packages/verifiable-receipts/SPEC.md)
(what this version emits and accepts) and in [`docs/specs/`](docs/specs):
[VAOS 2.0](docs/specs/vaos-2.0.md) (Ed25519),
[VAOS 3.0](docs/specs/vaos-3.0.md) (dual signature),
[transparency log](docs/specs/transparency-log.md),
[stream attestation](docs/specs/vaos-rsa-1.0.md) and
[payment tokens](docs/specs/vapt-1.0.md).
[`docs/ontology.md`](docs/ontology.md) defines the receipt, transparency-log
and agent terms, how they relate, and the SCITT (RFC 9943) equivalent of
each protocol term.

## Install

Clone the repository; nothing is on npm, PyPI or a Go proxy yet.

```bash
git clone https://github.com/christiaan839-beep/verifiable-receipts
cd verifiable-receipts
```

- **TypeScript** (Node 22.12 or later):
  `(cd packages/verifiable-receipts && npm ci)` installs and builds
  `dist/`. From your own project:
  `npm install --install-links /path/to/verifiable-receipts/packages/verifiable-receipts`.
  One runtime dependency: `@noble/post-quantum` (ML-DSA-65).
- **Python** (3.10 or later): `pip install ./packages/verifiable-receipts-py`.
  One dependency: `cryptography`.
- **Go** (1.22 or later): point your module at the clone with
  `go mod edit -replace github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go=/path/to/clone/packages/verifiable-receipts-go`,
  then `go mod tidy`.

## Sign and verify

**CLI** (TypeScript package):

```bash
npx verifiable-receipts-sign --input body.json --key ed25519-private.pem --out receipt.json
# add --mldsa-key mldsa65-secret.b64 for a v3= dual signature
```

**TypeScript**: Ed25519 comes from the caller (here `node:crypto`).

```ts
import { runGuardian, verifyGuardianAttestation, outputSizeRule } from "@sovereign-matrix/verifiable-receipts";
import { generateKeyPairSync, sign, verify } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const att = await runGuardian(
  [outputSizeRule(10_000)],
  { runId: "run_1", agentSlug: "example-agent", tokenId: "tok_1", input: {}, output: { text: "hi" } },
  (c) => "v2=" + sign(null, Buffer.from(c), privateKey).toString("base64"),
);
const check = verifyGuardianAttestation(att, (c, s) =>
  s.startsWith("v2=") && verify(null, Buffer.from(c), publicKey, Buffer.from(s.slice(3), "base64")),
);
console.log(check.ok);
```

**Python**:

```python
from sovereign_matrix.verifiable_receipts import sign_v2_receipt, verify_v2_receipt

receipt = sign_v2_receipt({"verdictId": "v_1", "overall": "pass"}, private_key)  # Ed25519PrivateKey
result = verify_v2_receipt(receipt, open("ed25519.pem", "rb").read())
print(result.ok, result.reason)
```

**Go**:

```go
pub, _ := vaos.LoadEd25519PublicKeyFromPEM(pemBytes)
var r vaos.Receipt
_ = json.Unmarshal(receiptJSON, &r) // fields other than canonical/contentHash/signature land in r.Envelope
res := vaos.VerifyV2Receipt(r, pub)
fmt.Println(res.OK, res.Reason)
```

Each package's README has the full API.

## The transparency log

`transparency.ts` implements RFC 6962 §2.1 hashing (`0x00` before a
leaf, `0x01` before an inner node), RFC 9162 inclusion and consistency
proofs, and tree heads that the caller signs. `log-store.ts` adds an
append-only file store (one 64-hex-character leaf per line, fsync on
every append, one writer per file) and a `TransparencyLog` class over
it. `bin/witness.mjs` polls a log's tree head over HTTP, checks a
consistency proof against the last head it saw, and signs the new one.

There is no log server, gossip between witnesses, or monitor in this
repository. The Python and Go packages verify inclusion proofs only.

## Security model

What a valid receipt shows: whoever held the issuer's secret key signed
exactly the bytes in `canonical`, and the receipt's other fields say
nothing that `canonical` does not.

What it does not show:

- **That the content is true.** The issuer signs what it is given. A
  receipt says what the issuer claimed, not what the model did.
- **When it was signed.** `issuedAt` is a signed claim, not a
  timestamp from a third party. After a key compromise, old and new
  receipts look the same unless a witnessed log entry predates the
  compromise.
- **That nothing was withheld.** An issuer can decline to sign or to
  log a receipt. The log makes rewriting history detectable only for
  parties that compare tree heads (witnesses); this repository has no
  gossip.
- **Key distribution.** Verifiers take the issuer's public key as
  input. How they get the right key is out of scope.

Limits of the implementation:

- **`v3=` downgrade.** The Ed25519 half of a `v3=` signature is a valid
  `v2=` signature by itself. ML-DSA-65 only helps against a broken
  Ed25519 if the verifier refuses `v2=` from an issuer that signs
  `v3=`. The `verifiable-receipts verify` CLI refuses `v3=` manifests
  rather than check half of them.
- **ML-DSA-65** comes from `@noble/post-quantum` 0.6.1, which its
  authors describe as self-audited, not independently audited. Only
  the TypeScript package signs or verifies it.
- **Threshold envelopes** carry their own policy (`m`, `n`, issuer
  list). The verifier checks that the policy is well formed and met;
  the relying party must check that it is the policy it expects.
- **Canonicalization** differs at the edges between languages: the
  TypeScript signer sorts keys by UTF-16 code unit, the Python signer
  by code point and refuses floats. The `v2=` verifiers never rebuild
  `canonical`, so this affects only which signer produced a receipt,
  not whether it verifies. (The TypeScript `verifyGuardianAttestation`
  does rebuild the Guardian canonical, and requires it byte for byte.)
- **Bundles**: `verifyManifest` checks the manifest's hash and
  signature, not the ZIP's contents or each receipt's own signature.
- **VAPT** payment tokens enforce amount, currency, merchant and a
  one-hour lifetime; single use is the settlement layer's job.
- `proofs/` holds hand-written proof sketches, not machine-checked
  proofs. Two were wrong before 0.4.0 and are corrected, with notes.

Report a vulnerability privately: see [SECURITY.md](SECURITY.md).

## Conformance

[`packages/verifiable-receipts/conformance/fixtures/`](packages/verifiable-receipts/conformance/fixtures)
holds 23 JSON fixtures: valid receipts, a tampered one, one signed with
another key, malformed and non-canonical base64 (padding bits, a line
feed inside), a `v1=` prefix, fields
beside `canonical` that agree or disagree with it, and thirteen
inclusion proofs, six of them malformed (uppercase or prefixed hex, a
64-byte leaf, a fractional or boolean index, a tree size past 2^32). The node, Python and Go verifiers each run every fixture and
must reach its `expected.ok`. The fixtures were signed with a key whose
private half was discarded; `public-key.pem` is the public half.

[`conformance/roundtrip/run.sh`](packages/verifiable-receipts/conformance/roundtrip/run.sh)
makes a throwaway Ed25519 key, signs a receipt with the Python signer
and another with the CLI, and a Guardian attestation with
`runGuardian`; it verifies each in Python, Go and node and checks that
all three reject a copy with one field edited (18 checks).

## Tests

```bash
(cd packages/verifiable-receipts && npm ci && npm run check)   # typecheck, lint, build, vitest
pip install ./packages/verifiable-receipts-py pytest ruff
ruff check .
python -m pytest packages/verifiable-receipts-py/tests packages/verifiable-receipts/conformance/conformance.py
(cd packages/verifiable-receipts-go && go vet ./... && go test ./...)
bash packages/verifiable-receipts/conformance/roundtrip/run.sh
```

Measured on 23 October 2026 (Node 22, Python 3.13, Go 1.24):

| Suite      | Result                                                      |
| ---------- | ----------------------------------------------------------- |
| TypeScript | 323 passed, 4 skipped (10 files, vitest 5)                  |
| Python     | 66 passed; conformance 16 passed                            |
| Go         | 36 tests passed, one with a subtest per fixture             |
| Round trip | 18 checks passed                                            |

The four skipped TypeScript tests were the witness CLI's network flow
(`tests/witness-cli.test.ts`); they now run (24 October 2026:
TypeScript 379 passed, none skipped, 12 files). CI (`.github/workflows/test.yml`) runs
all of the above on every push and pull request.

## License

Apache-2.0: see [LICENSE](LICENSE); each package carries a copy. The
specifications in `docs/specs/` carry their own licence line (CC0 1.0
or Apache-2.0).
