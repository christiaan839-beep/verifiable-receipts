# Receipt Transparency Log — design + threat model

| Field       | Value                                                                       |
| ----------- | --------------------------------------------------------------------------- |
| Version     | 0.1                                                                         |
| Status      | Draft — primitives in `@sovereign-matrix/verifiable-receipts` (`transparency`, `log-store`) |
| Editor      | Sovereign Matrix — `sovereign.systems007@gmail.com`                         |
| License     | CC0 1.0 (public domain)                                                     |
| Inspired by | RFC 6962 / RFC 9162 (Certificate Transparency)                              |

> The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, **MAY**, **OPTIONAL** are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

---

## 1. Problem

A party that checks an issuer's receipts has to trust that the
issuer's own records are complete: an issuer could drop a receipt,
rewrite its history, or show different records to different parties.

VAOS 2.0 / 3.0 (`docs/specs/vaos-2.0.md`, `docs/specs/vaos-3.0.md`)
answer "was this receipt signed by this issuer over these bytes?".
They do not answer "was this receipt published?". A receipt the
issuer signs and then withholds is still a valid receipt; it just
never reaches an auditor.

Certificate Transparency solved the analogous problem for SSL/TLS
in 2013: every certificate authority must submit issued certificates
to one or more public append-only Merkle logs, and browsers (Chrome
since 2018) refuse certificates not embedded in such a log. The
public log + independent witnesses make CA misissuance detectable
even when the CA itself is compromised.

This log applies the same Merkle structure to receipt hashes.

## 2. Roles

| Role         | Responsibility                                                          |
| ------------ | ----------------------------------------------------------------------- |
| **Issuer**   | Signs receipts (VAOS 2.0 / 3.0). Appends every receipt hash to the log. |
| **Log**      | Stores leaves append-only, computes the Merkle root, publishes STHs.    |
| **Witness**  | Independently signs the log's STHs at intervals. Counts forks.          |
| **Monitor**  | Walks the log, watches for unexpected receipts (regulator role).        |
| **Verifier** | Given a receipt and an STH, checks inclusion proof + signatures.        |

An ecosystem with N independent witnesses and an honest monitor
catches any vendor-controlled fork — the misbehaving log either has
no witness signatures (visibly suspicious) or has fork-divergent
STHs the monitor will detect.

## 3. Wire formats

### 3.1 Leaf hash

Every receipt is appended to the log as a single leaf. The leaf
data is the canonical projection of the receipt (per VAOS 2.0 §5).
The leaf hash is RFC 6962 §2.1:

```
leafHash(data) = SHA-256(0x00 || data)
```

The `0x00` byte is a domain separator; without it an attacker could
hand a verifier an internal-node hash and claim it's a leaf.

### 3.2 Internal node hash

```
innerHash(left, right) = SHA-256(0x01 || left || right)
```

The `0x01` domain separator pairs with `0x00` for second-preimage
resistance.

### 3.3 Signed Tree Head (STH)

The log publishes an STH at append-time and periodically thereafter:

```jsonc
{
  "v": 1,
  "logId": "string — stable identifier for this log",
  "treeSize": <number — count of leaves currently in the log>,
  "rootHash": "<hex — RFC 6962 Merkle root over all leaves>",
  "timestamp": "<ISO 8601 — when this STH was emitted>",
  "signature": "v2=<base64-Ed25519>"
    // or "v3=<base64-Ed25519>.<base64-ML-DSA-65>"
}
```

The canonical projection for signing (mirrors VAOS 2.0 §5):

```
canonicalize(sth) = JSON.stringify({
  logId: sth.logId,
  rootHash: sth.rootHash,
  timestamp: sth.timestamp,
  treeSize: sth.treeSize,
  v: sth.v,
})
```

(`signature` is omitted before signing. Keys sorted lexicographically.)

The Ed25519 / ML-DSA-65 verification keys are published at the
issuer's `.well-known/sovereign-receipts/` endpoint per VAOS 2.0 §6.3
and VAOS 3.0 §6.3.

### 3.4 Inclusion proof

Given a receipt's leaf hash `h`, its index `i` in the log, and an
STH committing to size `n` and root `r`, the inclusion proof is the
ordered list of sibling hashes needed to fold `h` up to `r`.

Verifier algorithm: standard CT decomposition into an "inner"
segment that walks the bits of `i` and a "border" segment of
left-siblings up the right edge. See `verifyInclusionProof()` in
the reference implementation.

### 3.5 Consistency proof

Given two STHs from the same `logId` at sizes `M` (old) and `N`
(new, with `M ≤ N`), a consistency proof is a list of hashes that
folds to both `oldRoot` and `newRoot`. Any successful verification
proves the log only appended between the two STHs — it could not
have rewritten or removed any leaf.

Verifier algorithm: recursive walk that mirrors RFC 6962 §2.1.2's
subproof structure. See `verifyConsistencyProof()` in the reference
implementation.

### 3.6 Encoding of proof inputs

These rules give every input one valid spelling. A verifier MUST check
them before it hashes anything, and MUST answer "invalid" (not raise or
throw) when one fails.

- Every hash (a leaf hash, a root hash, each audit-path entry, each
  consistency-proof entry) MUST be exactly 64 lowercase hexadecimal
  digits (`[0-9a-f]{64}`, 32 bytes). Uppercase digits, a `0x` or
  `sha256:` prefix, and any other length MUST be rejected. Without the
  length rule a 64-byte "leaf" made of two hashes joined, with an empty
  audit-path entry, folds to the root of the two-leaf tree.
- `leafIndex`, `treeSize` and the sizes of a consistency proof MUST be
  JSON integers from 0 to 2^53 − 1 (the integers a double holds
  exactly). Fractions, booleans, strings, NaN and infinities MUST be
  rejected. An inclusion proof also needs `treeSize` ≥ 1 and
  `leafIndex` < `treeSize`.
- Index arithmetic MUST be exact over that whole range: 32-bit
  operations accept a proof for a small tree as a proof for a tree of
  2^32 + 2 leaves.

Test vectors: `packages/verifiable-receipts/conformance/fixtures/`.
`inclusion-uppercase-hex.json`, `inclusion-0x-prefix.json`,
`inclusion-oversized-leaf.json`, `inclusion-fractional-index.json`,
`inclusion-boolean-index.json` and `inclusion-huge-treesize.json` MUST
be rejected; `inclusion-2leaf-idx1.json`, the valid proof the last one
is built from, MUST be accepted. The TypeScript, Python and Go
verifiers are checked against every fixture.

## 4. Append protocol

1. Issuer computes the canonical projection of a receipt.
2. Issuer computes `leafHash(canonical)`.
3. Issuer POSTs `leafHash` to the log's append endpoint (TBD —
   suggested: `POST /log/<logId>/leaves`).
4. The log appends the leaf and emits a new STH covering the
   updated tree.
5. The log returns to the issuer: `{ index, newSth }`.
6. The issuer SHOULD store `{ index, newSth }` alongside the receipt
   so any subsequent verifier can construct the inclusion proof.

The append is **non-reversible**. A log MUST NOT remove a leaf
under any circumstance. A leaf containing PII that must not be
disclosed is the issuer's responsibility — only append hashes of
PII-redacted canonical projections.

## 5. Witness protocol

A witness is any independent party that subscribes to STHs from one
or more logs and co-signs them. The protocol:

1. Witness fetches the log's latest STH at interval ≥ 1 hour.
2. Witness fetches a consistency proof from the most recent
   previously-signed STH (size `M`) to the current STH (size `N`).
3. Witness verifies the consistency proof. If it passes:
   - Witness signs the STH with its own keypair.
   - Witness publishes `{ logSth, witnessSignature }` to a public
     bulletin board (TBD — suggested: a Git repo, IPFS, or a
     dedicated witness API).
4. If the consistency proof fails:
   - Witness publishes a fork notice. Monitors and clients SHOULD
     treat the log as compromised.

A monitor with N witnesses sees N independent STH signatures over
every published tree head. A vendor that forks its log either fools
all N witnesses (cryptographically infeasible — they're independent
parties) or one of them publishes a fork notice.

## 6. Threat model

| Threat                                 | Mitigation                                                                                                                                                                                                                                                                                            |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Issuer rewrites history                | Detected by any witness holding an earlier signed STH: no valid consistency proof leads from it to the rewritten tree. Not detected by parties that never saw an earlier STH.                                                                                                                       |
| Issuer forks the log                   | Detected only when two parties compare STHs and find two different roots for the same `treeSize` and `logId`. This package has no gossip or fork-notice mechanism; deployments must provide one.                                                                                                   |
| Witness collusion                      | Use several independent witnesses. Colluding witnesses can cosign a fork; detection then depends on a party that talks to an honest witness.                                                                                                                                                        |
| Compromised issuer signing key         | Out of scope at the log layer. Receipts logged and witnessed before the compromise can be told apart from later ones by their position in the log; unlogged receipts cannot.                                                                                                                        |
| Compromised log operator               | The log's STH key is separate from the receipt key. A compromised operator can sign a fork; it is detected under the conditions in the fork row.                                                                                                                                                   |
| Censorship / receipt-suppression       | The log does not prevent an issuer from never issuing or never logging a receipt. It makes removal of a logged receipt detectable by parties that hold a later STH. Requiring that every decision in scope produces a logged receipt is a matter for contracts, not this format.                 |
| Post-quantum forgery of STH signatures | STHs MAY be signed as VAOS 3.0 (`v3=`); the downgrade caveat of VAOS 3.0 §9 applies.                                                                                                                                                                                                               |
| Leaf-data inference (PII leak)         | The log stores only `leafHash`, not the canonical projection. The issuer MUST publish only hashes of PII-redacted projections; raw PII MUST NOT enter the log.                                                                                                                                     |

## 7. Reference implementation

The primitives ship in `@sovereign-matrix/verifiable-receipts`:

```ts
import {
  leafHash,
  innerHash,
  treeRoot,
  inclusionProof,
  verifyInclusionProof,
  consistencyProof,
  verifyConsistencyProof,
  buildSth,
  canonicalizeSth,
} from "@sovereign-matrix/verifiable-receipts/transparency";
```

A log server, a witness API and a monitor are out of scope: the
package provides the hashes, proofs, unsigned tree heads, an
append-only file store (`FileLogStore`) and a witness CLI that polls
a log over HTTP. The tests (`tests/transparency.test.ts`) check
consistency proofs for every (oldSize, newSize) pair up to 16 and
inclusion proofs against shared fixtures in TypeScript, Python and
Go.

## 8. Comparison to RFC 6962 / 9162

| Aspect              | RFC 9162 (CT)                                  | This spec                                               |
| ------------------- | ---------------------------------------------- | ------------------------------------------------------- |
| Leaf content        | X.509 certificate or pre-certificate           | VAOS-canonical receipt hash                             |
| Browser enforcement | Chrome / Safari refuse non-CT certificates     | Out of scope — adoption is contract-driven, not browser |
| Witness model       | Gossip and witnessing left to deployments      | A witness cosigns tree heads (`bin/witness.mjs`)        |
| Signature           | ECDSA-P256 / RSA on the SCT                    | Ed25519 (v2) or Ed25519 + ML-DSA-65 (v3)                |
| Hash domains        | 0x00 leaf / 0x01 inner (SHA-256)               | Identical                                               |
| Sunlight            | Public log audited by Google, Cloudflare, etc. | Federated — issuer-operated logs + N-of-M witnesses     |

The hash domains and proof algorithms are those of RFC 6962 / RFC
9162, so their proofs can be checked by code written for CT. The
tree-head format and leaf contents are not CT's, so CT log software
does not serve this log as is.

## 9. Roadmap

- Done: the primitives, a file-backed store and a witness CLI.
- Not built: a log server, a multi-witness aggregator, a monitor.

## 10. Contact

Editorial feedback: an issue on the repository. Security reports: a private GitHub security advisory (see `SECURITY.md`).
