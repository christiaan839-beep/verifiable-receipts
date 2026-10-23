# Proof — TRS threshold check soundness

**Claim.** If `verifyThresholdAttestation(att, opts)` returns `ok = true`,
then **at least `m` of the `n` issuers in `att.authorizedIssuers`
have each signed the bytes `B = trsSigningBytes(att.canonical,
att.threshold, att.authorizedIssuers)` under their own secret key**,
where `m = att.threshold.m ≥ 1` and `n = att.threshold.n`. `B`
contains `att.canonical`, `m`, `n` and the sorted issuer list, so
each of those issuers agreed to this canonical under this policy.

**Scope.** `m` and `A` are read from the envelope. The claim says the
envelope's own policy was met; it does not say that policy is the one
the relying party wants. A relying party MUST compare `m` and `A`
with its own policy. (Before 0.4.0 the verifier did not check that
`m ≥ 1`, so an envelope with `m = 0` returned `ok = true` with no
signatures; the claim was false for such envelopes.)

## Notation

- Let `C = att.canonical` (UTF-8 bytes).
- Let `A = att.authorizedIssuers` (set of n distinct issuer ids).
- Let `K_i` be the secret key of issuer i ∈ A. Let `P_i` be the
  corresponding public key.
- Let `B = trsSigningBytes(C, {m, n}, A)`.
- Let `Sig_i(B)` denote a string `"v2=" + base64(Ed25519.sign(K_i, B))`.
- Let `V(B, s, i)` denote the verifier callback
  `opts.verifyIssuerSignature(B, s, i)` — returns true iff `s`
  decodes to bytes σ with `Ed25519.verify(P_i, B, σ) = true`.

## Assumptions

1. **A1 (EUF-CMA).** Ed25519 is existentially unforgeable under
   chosen-message attack. For all probabilistic polynomial-time
   adversaries A, the probability A produces a pair `(C', σ')` with
   `Ed25519.verify(P_i, C', σ') = true` AND `C'` never queried under
   key `K_i` is negligible.
2. **A2 (PKI correctness).** `V(C, s, i) = true` implies the
   signature s was produced under `K_i` (the secret key paired with
   `P_i`). This is exactly EUF-CMA composed with a correct pubkey
   resolution mapping `i → P_i`.
3. **A3 (SHA-256 second-preimage).** It is infeasible to find
   `C' ≠ C` with `sha256(C') = sha256(C)`.

## Proof

Let `verifyThresholdAttestation(att, opts) = { ok: true, ... }`.

By the implementation in `src/threshold.ts`:

**Step 1 — Scheme, policy and contentHash gate.** Verification can
only return ok = true if:

- `att.scheme === "trs1"`, AND
- `m` and `n` are integers with `1 ≤ m ≤ n`, and `A` lists exactly
  `n` distinct ids, AND
- `sha256(att.canonical) === att.contentHash`.

The contentHash check eliminates the case where `C` was tampered
to `C' ≠ C` while keeping `att.contentHash` unchanged: by A3 this
would require a sha256 second-preimage. □ (contentHash bound)

**Step 2 — Per-cosigner authorization gate.** For each cosigner
`c ∈ att.cosigners`, the verifier loop records `c` as "verifying"
only if:

- `c.issuerId ∈ A` (authorizedIssuers set membership), AND
- `c.issuerId ∉ seen` (no duplicate), AND
- `V(B, c.signature, c.issuerId) = true`.

By A2, the third condition implies `c.signature` was produced under
`K_{c.issuerId}` over the exact bytes `B`. □ (authentic-signer
bound)

**Step 3 — Cardinality.** Let `verifying = { c.issuerId : c was
counted as verifying }`. By the duplicate-rejection in Step 2,
`|verifying|` equals the count of distinct issuer ids that
verified. The implementation returns `ok = true` iff
`|verifying| ≥ m`, and `m ≥ 1` by Step 1. □ (threshold bound)

**Combining the three bounds.** OK = true implies there exist at
least m distinct issuer ids `i_1, …, i_m ∈ A` such that each
`Sig_{i_k}(B)` is a valid signature under `P_{i_k}`. By A2, each
of those signatures must have been produced by a process holding
`K_{i_k}`. By A1, the only such process is the legitimate issuer
i_k (or a holder of i_k's secret key, which we collapse into
"i_k is honest" by definition).

Therefore at least m of the n authorized issuers signed the exact
bytes `B`, which contain `att.canonical`. ∎

## What this rules out

- **Single-issuer forgery.** A compromised single issuer cannot
  unilaterally produce an OK envelope. The forger would need to
  also collect m-1 valid signatures from other authorized issuers
  on the same canonical bytes.
- **Rogue-cosigner padding.** Appending more `cosigners` entries
  with valid signatures under keys NOT in `authorizedIssuers` does
  not increase the verifying count. The set-membership check
  in Step 2 forecloses this.
- **Duplicate-counting.** A single issuer cannot count themselves
  twice by submitting two valid signatures. The `seen` set in
  Step 2 forecloses this.
- **Canonical drift.** A canonical bytes `C' ≠ C` paired with a
  signature for `C` does not verify by A1. A `contentHash` that
  matches `C` but a different `canonical` field is caught by Step 1.

## What this does NOT cover

- **Compromise of m distinct issuer keys.** This is the cost of
  selecting `m`. Operators MUST pick `m ≥ ⌈(n + 1) / 2⌉` for
  Byzantine fault tolerance against half-of-issuers compromise.
- **Pubkey resolution attacks.** If the verifier's `i → P_i`
  mapping is compromised (e.g. a malicious DNS rebind hijacks
  `publicKeyUrl`), A2 fails. Mitigated by pinning each issuer's
  public key rather than fetching it at verification time.

## Reference implementation

`verifyThresholdAttestation` and `thresholdPolicyError` in
`packages/verifiable-receipts/src/threshold.ts`.
`packages/verifiable-receipts/tests/threshold.test.ts` exercises
every clause: insufficient-count → ok=false; rogue-cosigner →
rejected; duplicate-cosigner → counted once + reported as
rejected; canonical-tamper → contentHash failure; unknown-scheme
→ ok=false. `tests/core.test.ts` checks that `m = 0`, `m > n` and a
short issuer list are rejected.
