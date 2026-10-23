# @sovereign-matrix/verifiable-receipts

TypeScript library for signing receipts for AI agent actions and
verifying them later. Version 0.4.0, Apache-2.0. Not on npm yet:
install it from the repository (see the [root README](../../README.md)).

Node 22.12 or later. One runtime dependency,
`@noble/post-quantum`, for ML-DSA-65. Ed25519 is supplied by the caller
(`node:crypto`, a KMS, an HSM), except in the CLIs, which use
`node:crypto`.

The wire formats are in [`SPEC.md`](./SPEC.md).

## Modules

| Import path                                  | What it does                                                                                     |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `…/pq-sign`                                  | ML-DSA-65 sign/verify; `verifyDualSig` for `v3=<ed25519>.<ml-dsa-65>` (both halves must hold)     |
| `…/guardian`                                 | `runGuardian` runs rules over an agent run and signs the verdict; `verifyGuardianAttestation`    |
| `…/bundle`                                   | Deterministic STORE-method ZIP; `buildSignedBundle` / `verifyManifest`                           |
| `…/transparency`                             | RFC 6962 hashes, RFC 9162 inclusion and consistency proofs, unsigned tree heads                   |
| `…/log-store`                                | `InMemoryLogStore`, append-only `FileLogStore`, `TransparencyLog`                                |
| `…/threshold`                                | m-of-n co-signed envelopes (`trs1`); each cosigner signs `trsSigningBytes`, which binds the policy |
| `…/stream-attestation`                       | Merkle commitment over a stream's chunks; per-chunk inclusion proofs                             |
| `…/vapt`                                     | Short-lived Ed25519 payment tokens with amount, currency, merchant and lifetime limits           |

`…` is `@sovereign-matrix/verifiable-receipts`; everything is also
exported from the package root.

## Sign and verify a verdict

```ts
import { runGuardian, verifyGuardianAttestation, outputSizeRule, requireTokenRule } from "@sovereign-matrix/verifiable-receipts";
import { generateKeyPairSync, sign, verify } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");

const verdict = await runGuardian(
  [outputSizeRule(10_000), requireTokenRule],
  { runId: "run_1", agentSlug: "example-agent", tokenId: "tok_1", input: {}, output: { text: "hi" } },
  (canonical) => `v2=${sign(null, Buffer.from(canonical), privateKey).toString("base64")}`,
);

const result = verifyGuardianAttestation(verdict, (canonical, signature) =>
  signature.startsWith("v2=") &&
  verify(null, Buffer.from(canonical), publicKey, Buffer.from(signature.slice(3), "base64")),
);
console.log(verdict.overall, result.ok); // "pass" true
```

A rule is `{ id, description, evaluate(ctx) }`. A rule that throws
becomes a `warn` verdict; the overall verdict is `block` if any rule
blocks, else `warn` if any warns, else `pass`. The signed canonical
covers each rule's `ruleId`, `verdict` and `reason`; it does not cover
`durationMs`, `evidence` or `totalMs`.

## Dual signature

```ts
import { generateMlDsa65Keypair, signMlDsa65, formatV3Wire, verifyDualSig } from "@sovereign-matrix/verifiable-receipts";

const ml = generateMlDsa65Keypair();
const edSig = sign(null, Buffer.from(canonical), privateKey).toString("base64");
const wire = formatV3Wire(edSig, signMlDsa65(canonical, Buffer.from(ml.secretKeyB64, "base64")));

const v = verifyDualSig(canonical, wire, Buffer.from(ml.publicKeyB64, "base64"), (c, s) =>
  verify(null, Buffer.from(c), publicKey, Buffer.from(s.slice(3), "base64")),
);
// { ok, ed25519, mldsa65 }
```

The Ed25519 half of a `v3=` signature is a valid `v2=` signature on
its own. A dual signature protects against a broken Ed25519 only if
your verifier refuses `v2=` from issuers that sign `v3=`.

## Transparency log

```ts
import { TransparencyLog, FileLogStore, verifyInclusionProof } from "@sovereign-matrix/verifiable-receipts";

const log = new TransparencyLog("example-log", new FileLogStore("./log.txt"));
const { index, leafHashHex, sth } = log.append(receipt.canonical); // RFC 6962 leaf hash
const path = log.proveInclusion(index);
verifyInclusionProof(leafHashHex, index, sth.treeSize, path, sth.rootHash); // true
```

Tree heads are returned unsigned; sign `canonicalizeSth(sth)` yourself.
`FileLogStore` takes no file lock: one writer per file.

## CLIs

```bash
npx verifiable-receipts-sign --input body.json --key ed25519-private.pem [--mldsa-key mldsa65.b64] [--out receipt.json]
npx verifiable-receipts verify --manifest MANIFEST.signed.json --pubkey ed25519.pem [--json]
npx verifiable-receipts-witness --url https://log.example --key witness.pem --witness-id example-witness --once
```

- `verifiable-receipts-sign` drops `canonical`, `contentHash` and
  `signature` from the body, sorts keys at every depth, signs the
  compact JSON and writes the body's fields plus those three. Its `v2=`
  output verifies in Python and Go.
- `verifiable-receipts verify` checks a bundle manifest's hash and its
  `v2=` signature (exit 0 valid, 1 invalid, 2 usage error). It does not
  open the ZIP and it refuses `v3=` manifests.
- `verifiable-receipts-witness` polls a log's tree head, checks a
  consistency proof from the last head it saw, and posts a signature.

## Development

```bash
npm ci
npm run check    # tsc (src + tests), eslint, build, vitest
```

`conformance/` runs the shared cross-language fixtures (see its
README); `proofs/` holds informal proof sketches. CHANGELOG.md lists
changes per version.

Report a vulnerability privately: see the repository's
[SECURITY.md](../../SECURITY.md).
