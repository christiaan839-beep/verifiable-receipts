# @sovereignos/verifiable-receipts

TypeScript library for signing receipts for AI agent actions and
verifying them later. Version 0.5.1, Apache-2.0. Not on npm yet:
install it from the repository (see the [root README](../../README.md)).

Node 22.12 or later. One runtime dependency,
`@noble/post-quantum`, for ML-DSA-65. Ed25519 is supplied by the caller
(`node:crypto`, a KMS, an HSM), except in the CLIs, which use
`node:crypto`.

To verify an Ed25519 signature, use `verifyEd25519(publicKey, message,
signature)` rather than `crypto.verify` alone. It makes the checks of
VAOS 2.0 §7.3, the strict profile, before `node:crypto` sees the
signature: the key and the signature's R must be canonical encodings
of points of order L (no small-order or mixed-order points, nothing off
the curve), and S must be below L. Node.js 24.22.1 (OpenSSL 3.5.9)
and 26.10.0 (OpenSSL 3.5.8) refuse R = identity, which Node.js 22.23.2
accepts; with these checks, every Node line, the Python verifier and the Go verifier give the same
verdict. It returns `{ ok, reason }`, with the reasons of the Python
and Go verifiers. `loadEd25519PublicKey` refuses the same keys when it
loads them, and `ed25519PublicKeyProblem` and
`ed25519SignatureProblem` say why a key or a signature is refused.

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

`…` is `@sovereignos/verifiable-receipts`; everything is also
exported from the package root.

## Sign and verify a verdict

```ts
import { runGuardian, verifyEd25519, verifyGuardianAttestation, outputSizeRule, requireTokenRule } from "@sovereignos/verifiable-receipts";
import { generateKeyPairSync, sign } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");

const verdict = await runGuardian(
  [outputSizeRule(10_000), requireTokenRule],
  { runId: "run_1", agentSlug: "example-agent", tokenId: "tok_1", input: {}, output: { text: "hi" } },
  (canonical) => `v2=${sign(null, Buffer.from(canonical), privateKey).toString("base64")}`,
);

const result = verifyGuardianAttestation(verdict, (canonical, signature) =>
  signature.startsWith("v2=") &&
  verifyEd25519(publicKey, Buffer.from(canonical), Buffer.from(signature.slice(3), "base64")).ok,
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
import { generateMlDsa65Keypair, signMlDsa65, formatV3Wire, verifyDualSig, verifyEd25519 } from "@sovereignos/verifiable-receipts";

const ml = generateMlDsa65Keypair();
const edSig = sign(null, Buffer.from(canonical), privateKey).toString("base64");
const wire = formatV3Wire(edSig, signMlDsa65(canonical, Buffer.from(ml.secretKeyB64, "base64")));

const v = verifyDualSig(canonical, wire, Buffer.from(ml.publicKeyB64, "base64"), (c, s) =>
  verifyEd25519(publicKey, Buffer.from(c), Buffer.from(s.slice(3), "base64")).ok,
);
// { ok, ed25519, mldsa65 }
```

The Ed25519 half of a `v3=` signature is a valid `v2=` signature on
its own. A dual signature protects against a broken Ed25519 only if
your verifier refuses `v2=` from issuers that sign `v3=`.

## Transparency log

```ts
import { TransparencyLog, FileLogStore, verifyInclusionProof } from "@sovereignos/verifiable-receipts";

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
npx verifiable-receipts-witness --url https://log.example --key witness.pem --witness-id example-witness [--log-id log-id] [--log-public-key log.pub.pem] --once
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
  Before it signs it checks each field's spelling (and that the head
  has no fields beyond the schema's seven, an empty tree has the
  SHA-256 of no bytes as its root, and the `logId` has no control
  characters), rebuilds the canonical from the fields and requires the
  log's copy to match it byte for byte (it signs the rebuilt one), and
  refuses: a different `logId` from its state file or from `--log-id`;
  a different root at a size it already signed; a timestamp earlier
  than the one it saved. It saves the new head atomically before the
  signature leaves the process; a failed submission is resubmitted
  exactly as saved, even if the log has since re-dated the head. Each
  poll holds `<state>.lock` (on the state file's real path, so a
  symlink and its target share it), so a second witness process on the
  same state file is refused. The lock is a lease: its holder touches
  its mtime every 5 s, and it is stale only when its mtime is older
  than `LEASE_MS` = 3 × `--timeout` + 30 s (120 s by default; a poll
  makes at most three requests, each bounded by `--timeout`, plus local
  work). The pid and hostname in it are shown, never trusted, because
  containers and pid namespaces repeat them. A stale lock is broken
  under `<state>.lock.break` (itself taken over once older than the
  lease); a held one is refused as `state-locked`, saying when its
  lease runs out, so a restarted witness recovers by itself. SIGTERM
  and SIGINT release the lock. `--break-lock` removes it whatever holds
  it: if another witness is still running on that state file, two
  witnesses can sign, so use it only when you are sure none is. Leases
  are judged by file mtimes against the local clock, so on shared
  storage they assume clock skew between hosts far below `LEASE_MS`.
  A process whose lease ran out and whose lock another took neither
  saves nor signs (`lock-lost`, exit 2), and no save moves the state
  file to a smaller tree size or to another root at the same size. On a
  file system without hard links the lock is created with an exclusive
  open instead, and can be seen empty for a moment (it is then refused
  as unreadable until its lease runs out). With `--log-public-key <pem>` it also verifies
  the log's `v2=` signature; without it, it prints that the log
  signature was not checked. A state file that exists but is
  unreadable or malformed is refused, not treated as a first run.
  Requests time out after `--timeout` seconds (1 to 3600, default 30),
  never follow a redirect, and bodies over 1 MiB are refused. Exit 0
  witnessed or no change; 1 the log misbehaved; 2 usage error,
  `lock-lost`, a fetch that failed, timed out, was redirected or too
  large, malformed head, bad, unsavable, locked (`state-locked`) or
  unwritable (`state-unwritable`) state file, failed submission, or a
  `v3=` head with `--log-public-key`. With `--json` each poll prints
  one JSON verdict line on stdout, and the daemon's banner goes to
  stderr. The daemon writes a stderr line for every non-zero verdict,
  halts on 1 and retries the rest.

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
