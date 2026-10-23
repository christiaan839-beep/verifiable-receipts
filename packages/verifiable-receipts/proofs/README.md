# Proof sketches

**License:** Apache 2.0 (free to republish, re-derive, or formalize in Lean / Coq / Isabelle).

Informal, hand-written proof sketches of the security properties
the implementation claims. They are not machine-checked. Two had
errors that were found and corrected in 0.4.0 (see the notes in
`trs-soundness.md` and `vaos-v2-non-malleability.md`); read them as
arguments to check, not as guarantees.

Each proof follows the structure:

1. **Claim** — what property we're proving
2. **Notation** — symbols + types
3. **Assumptions** — what we're taking as given (e.g. SHA-256 collision
   resistance, Ed25519 EUF-CMA security)
4. **Proof** — argument by cases / induction / contradiction
5. **What this rules out** — concrete attack scenarios this proof
   forecloses

They are not Lean or Coq files.

## Proofs in this corpus

| File                                                                           | Property proved                                                                                    |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| [`trs-soundness.md`](./trs-soundness.md)                                       | TRS threshold check is sound — OK implies ≥ m authorized issuers signed under the envelope's policy. |
| [`rfc9162-inclusion-completeness.md`](./rfc9162-inclusion-completeness.md)     | RFC 9162 inclusion proof is complete — every honest leaf is provable.                              |
| [`vaos-v2-non-malleability.md`](./vaos-v2-non-malleability.md)                 | VAOS v2 signatures are non-malleable, given strict base64 decoding.                                |
| [`vapt-replay-resistance.md`](./vapt-replay-resistance.md)                     | VAPT lifetime + singleUse constraints bound replay risk to a 1-hour window.                        |
| [`stream-attestation-non-injection.md`](./stream-attestation-non-injection.md) | A chunk not in the signed stream has no valid inclusion proof under the signed root.               |

## Why a corpus, not a single doc

Each property is independent. A reviewer of the TRS spec can read
`trs-soundness.md` without the others.

## License

Apache 2.0 © Sovereign Matrix. Republish, formalize, fork.

If you find a flaw in a proof, report it as a security issue
(`SECURITY.md`): through a private GitHub security advisory.
