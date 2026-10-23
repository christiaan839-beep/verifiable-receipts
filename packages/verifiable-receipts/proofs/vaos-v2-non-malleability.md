# Proof — VAOS v2 wire format non-malleability

**Claim.** Given a VAOS v2 receipt `R = (canonical, contentHash,
signature)` that verifies under public key `P`, no
polynomial-time adversary (without access to the secret key `K`
paired with `P`) can produce a different receipt `R' = (canonical',
contentHash', signature')` with `R' ≠ R` that also verifies under
`P` AND describes the same Guardian verdict.

Equivalently: the wire format is **non-malleable** — there is no
way to "remix" a valid receipt into a different valid receipt
that still represents the same audit claim.

## Notation

- `canonical`: UTF-8 byte string. The bytes that were signed.
- `contentHash := "sha256:" + hex(SHA-256(canonical))`.
- `signature := "v2=" + base64(Ed25519.sign(K, canonical))`.
- `verify(R, P) = true` iff:
  1. `canonical` is non-empty,
  2. `contentHash` equals the recomputed hash (when present),
  3. signature parses as `v2=<base64>`,
  4. `Ed25519.verify(P, canonical, decode(signature)) = true`.

## Assumptions

1. **C1 (EUF-CMA).** Ed25519 is existentially unforgeable under
   chosen-message attack. Given oracle access to
   `Ed25519.sign(K, ·)`, no PPT adversary outputs a pair
   `(m', σ')` with `Ed25519.verify(P, m', σ') = true` AND `m'`
   never queried, except with negligible probability.
2. **C2 (Ed25519 strong unforgeability).** Beyond EUF-CMA,
   Ed25519 is **SUF-CMA** (strongly unforgeable): even given
   `(m, σ)`, no PPT adversary produces `(m, σ')` with `σ' ≠ σ`
   and `verify(P, m, σ') = true` except negligibly. (This is a
   property of the RFC 8032 deterministic-nonce scheme.)
3. **C3 (SHA-256 second-preimage resistance.)** No PPT adversary
   finds `canonical' ≠ canonical` with
   `SHA-256(canonical') = SHA-256(canonical)`.
4. **C4 (Canonical encodings).** Each signature byte string has
   exactly one accepted base64 spelling, and each hash one accepted
   hex spelling. Plain base64 decoding is *not* injective: a 64-byte
   signature ends in a character with four unused bits, so several
   strings decode to the same bytes. The verifiers enforce C4 by
   rejecting base64 that does not re-encode to itself (Go
   `StdEncoding.Strict()`, Python and node re-encode and compare;
   added in 0.4.0, fixture `v2-invalid-noncanonical-base64.json`).
   Before 0.4.0, C4 did not hold and Case II's string-level claim
   was false; the byte-level claim (no second valid signature on the
   same canonical) still held by C2.

## Proof by case analysis on the differing field

Suppose for contradiction an adversary produces `R' ≠ R` with
`verify(R', P) = true`. There must be at least one field that
differs.

### Case I — `canonical' ≠ canonical`

Then `Ed25519.verify(P, canonical', decode(signature'))` must be
true for verification to succeed.

- **Subcase I.a — `signature' = signature`.** Then by C1 with
  oracle query `canonical` and adversary output `(canonical', σ)`,
  the adversary has produced a forgery on `canonical'`. This
  contradicts C1.
- **Subcase I.b — `signature' ≠ signature`.** Then the adversary
  has produced a _new_ signature on a _new_ message — a stronger
  forgery, still contradicting C1.

In either subcase, the adversary breaks EUF-CMA. ∎ Case I

### Case II — `canonical' = canonical` but `signature' ≠ signature`

For verification to succeed, `decode(signature')` must be a valid
Ed25519 signature on `canonical` under `P`.

By C4, a `signature'` that the verifier accepts and that differs from
`signature` decodes to different bytes: `decode(signature') ≠ decode(signature)`.

The adversary has produced a pair `(canonical, σ')` with
`σ' ≠ σ` and `verify(P, canonical, σ') = true`, where σ is the
signature embedded in the original `R`. This is exactly the
SUF-CMA distinguisher, contradicting C2. ∎ Case II

### Case III — `canonical' = canonical` and `signature' = signature` but `contentHash' ≠ contentHash`

If both `contentHash` and `contentHash'` are present, the
verifier recomputes `SHA-256(canonical)` and compares against
each. Since `canonical' = canonical`, the recomputation is
identical; the verifier rejects whichever `contentHash` value
doesn't match.

By C3, the only `contentHash` value that satisfies the verifier's
equality check is `"sha256:" + hex(SHA-256(canonical))`. By C4
this value is unique. Therefore one of `R` or `R'` fails the
content-hash check; the verifying receipt has the canonical
`contentHash`. The receipts cannot both verify with different
contentHash values. ∎ Case III

By exhaustion of cases, no `R' ≠ R` can simultaneously verify
under `P` and describe the same canonical. ∎

## What this rules out

- **Signature re-spelling attacks.** No way to produce a
  byte-different signature that still verifies the same canonical.
  (Defeated by SUF-CMA.)
- **Canonical-tamper-with-old-signature.** No way to tamper the
  canonical and reuse the original signature. (Defeated by
  EUF-CMA.)
- **contentHash desync.** No way to publish a receipt with a
  contentHash that disagrees with the canonical bytes. (Caught
  by the verifier's recomputation.)
- **Same-meaning-different-bytes.** Because the canonical
  projection is byte-deterministic (per VAOS 2.0 §3.1 — lexicographic
  field sort + RFC 7159 JSON), two semantically-equivalent
  receipts produce identical canonical bytes. There is no
  "different but equivalent" form.

## What this does NOT cover

- **Out-of-band metadata.** A receipt can be wrapped in a
  bundle, an HTTP envelope, or a Slack message; that wrapper is
  outside the wire format. Tampering of metadata that travels
  alongside the receipt is the bundle/envelope layer's problem.
- **Key compromise.** Non-malleability assumes the adversary
  doesn't hold `K`. Key-compromise impersonation is addressed by
  the TRS m-of-n primitive proved in `trs-soundness.md`.
- **Quantum adversaries.** Ed25519 is broken by sufficiently
  large quantum computers. VAOS 3.0 adds ML-DSA-65 dual-signing;
  the equivalent non-malleability for v3 follows from the same
  case structure with both signatures bound to the same
  canonical.

## Reference implementation

- `verify_v2_receipt` (Python), `VerifyV2Receipt` (Go) and
  `conformance/verify-v2.mjs` (node).
- The conformance fixtures in `conformance/fixtures/` exercise:
  tampered canonical, wrong key, bad and non-canonical base64, a
  `v1=` prefix, and envelope fields that disagree with `canonical`.
