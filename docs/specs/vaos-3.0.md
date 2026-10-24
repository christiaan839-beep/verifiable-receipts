# VAOS 3.0 — Verifiable Agent Output Specification (Ed25519 + ML-DSA-65 dual signature)

| Field          | Value                                                          |
| -------------- | -------------------------------------------------------------- |
| Version        | 3.0                                                            |
| Supersedes     | VAOS 2.0 (Ed25519) — see `docs/specs/vaos-2.0.md`              |
| Status         | Draft (open for comment)                                       |
| Editor         | Sovereign Matrix — `sovereign.systems007@gmail.com`            |
| License        | CC0 1.0 (public domain)                                        |
| Reference impl | `@sovereign-matrix/verifiable-receipts` (Apache-2.0)           |
| Discussion     | https://github.com/christiaan839-beep/verifiable-receipts/issues |

> The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

---

## 1. Abstract

VAOS 3.0 promotes the signature primitive of VAOS 2.0 from
single-signature Ed25519 to **dual-signature Ed25519 + ML-DSA-65**,
the module-lattice signature of
[NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

Why: receipts may need to verify for many years. A
cryptographically relevant quantum computer (CRQC) running Shor's
algorithm would break Ed25519, and with it any receipt whose only
signature is Ed25519: an attacker could then sign new receipts under
the issuer's published key.

VAOS 3.0 signs every receipt with **both** Ed25519 and ML-DSA-65
over the same bytes. The dual signature resists forgery for as long
as **either** algorithm holds, **provided the verifier requires the
`v3=` form** for that issuer. The Ed25519 half of a `v3=` signature
is a valid `v2=` signature on its own (§9, downgrade), so a verifier
that still accepts `v2=` from an issuer gains nothing from ML-DSA-65.

VAOS 3.0 is **fully wire-compatible** with VAOS 2.0 verifiers via
the version prefix system: a v3 verifier MUST accept v2 receipts;
a v2 verifier MAY reject v3 receipts or attempt fallback to the
Ed25519 half. See §6.

This document is in the public domain. Implementations are
encouraged.

---

## 2. Motivation

NIST published FIPS 204 (ML-DSA) in August 2024. Pairing a classical
signature with a post-quantum one is a common migration pattern (see
NIST SP 1800-38 and the IETF composite-signature drafts): the pair is
as strong as the stronger of the two, as long as verifiers require
both.

The cost is size (an ML-DSA-65 signature is 3309 bytes, against 64
for Ed25519; the public key is 1952 bytes) and signing time.

---

## 3. Terminology

VAOS 2.0 §3 carries forward. Additions:

- **PQ secret key** — issuer's ML-DSA-65 secret key, 4032 bytes.
- **PQ verification key** — issuer's ML-DSA-65 public key, 1952
  bytes. Published at
  `https://<issuer>/.well-known/sovereign-receipts/mldsa65.b64`.
- **Dual signature** — a string of the form
  `v3=<base64-ed25519>.<base64-mldsa65>` carrying both signatures
  concatenated with a literal `.` separator. The Ed25519 half is
  the same 64-byte signature that would be emitted under VAOS 2.0;
  the ML-DSA-65 half is the 3309-byte ML-DSA-65 signature output.

---

## 4. Receipt Structure

Receipt JSON shape is unchanged from VAOS 2.0 §4. Only the format
of `signature` is upgraded:

- VAOS 1.0: `v1=<base64-hmac>`
- VAOS 2.0: `v2=<base64-ed25519>`
- VAOS 3.0: `v3=<base64-ed25519>.<base64-mldsa65>`

A receipt MUST carry exactly one signature field with exactly one
version prefix.

---

## 5. Canonical Projection

The canonicalization algorithm of VAOS 1.0 §6 carries forward
unchanged. Both signatures in a VAOS 3.0 dual signature MUST be
computed over **the same** UTF-8 byte string produced by that
projection. Implementations MUST NOT recanonicalize the payload
between the two signing operations. The receipt body MUST NOT nest
deeper than 64 (VAOS 2.0 §7.2).

---

## 6. Signature

### 6.1 Generation

The issuer:

1. Computes the canonical projection per §5.
2. Signs the resulting UTF-8 byte string with their Ed25519 secret
   key per [RFC 8032 §5.1.6](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6).
3. Signs the **same** UTF-8 byte string with their ML-DSA-65 secret
   key per [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
   ML-DSA.Sign (pure ML-DSA, not HashML-DSA) with an empty context
   string.
4. Base64-encodes each signature with the standard alphabet
   (RFC 4648 §4).
5. Constructs the wire string
   `v3=<base64-ed25519>.<base64-mldsa65>`.
6. Sets the receipt's `signature` field to the resulting string.

### 6.2 Wire format

```
v3=<base64-of-64-byte-Ed25519-sig>.<base64-of-3309-byte-ML-DSA-65-sig>
```

A verifier MUST treat the literal `.` as the only valid separator
and MUST reject any wire string whose halves do not decode to the
expected algorithm output lengths.

### 6.3 Key publication

VAOS 2.0 §6.3 carries forward for the Ed25519 verification key.
Additionally, the ML-DSA-65 verification key MUST be published at:

```
https://<issuer-domain>/.well-known/sovereign-receipts/mldsa65.b64
```

The published key MUST be base64-encoded (raw 1952 bytes, standard
alphabet) and MUST be served with `Content-Type: text/plain;
charset=utf-8` and `Access-Control-Allow-Origin: *`.

---

## 7. Verification Procedure

Given a v3 receipt, the Ed25519 verification key, and the ML-DSA-65
verification key, a verifier first rejects the receipt if it nests
deeper than 64, before it reads any field, as VAOS 2.0 §7.2 says; the
canonical bytes of step 4 MUST NOT nest deeper than 64 either. It
then:

1. Parses the version prefix.
   - `v1=` → fall back to VAOS 1.0 §8.
   - `v2=` → fall back to VAOS 2.0 §7.
   - `v3=` → continue.
   - Anything else → reject.
2. Splits the post-prefix string on the literal `.` separator.
   Expect exactly two halves; reject if not.
3. Base64-decodes each half. Reject if either fails to decode.
4. Recomputes the canonical projection of the receipt per §5.
5. Calls the host's Ed25519 verifier with the canonical bytes, the
   decoded Ed25519 signature, and the Ed25519 verification key. It
   MUST verify as VAOS 2.0 §7.3 says: `S` less than the group order,
   the cofactorless check, and `R` compared as encoded.
6. Calls the host's ML-DSA-65 verifier with the canonical bytes,
   the decoded ML-DSA-65 signature, and the ML-DSA-65 verification
   key.
7. Returns a verdict object:

```ts
interface DualSigVerdict {
  ok: boolean; // true iff BOTH primitives returned true
  ed25519: boolean; // result of the Ed25519 check
  mldsa65: boolean; // result of the ML-DSA-65 check
}
```

### 7.1 Asymmetric verification (forward-compatibility)

A conforming verifier MUST report the per-primitive results even
when one half fails, so that a relying party can tell which half
failed. `ok` is true only when both hold; the reference
`verifyDualSig` follows this rule.

A result of `ed25519: false, mldsa65: true` means the receipt or its
Ed25519 half was altered, or the wrong Ed25519 key was used. It is
not evidence of a quantum adversary: such an adversary would produce
a *valid* Ed25519 signature.

---

## 8. Visibility

VAOS 2.0 §8 carries forward. Additions:

The ML-DSA-65 verification key (1952 bytes) is, by construction,
public. Issuers MAY mirror it via CDN, IPFS, or any other content-
addressable system.

The ML-DSA-65 secret key MUST NOT be transmitted, logged, or
stored outside the issuer's signing infrastructure. If one secret
key is compromised, an attacker still needs the other to produce a
valid `v3=` signature; the issuer SHOULD rotate both.

---

## 9. Threat Model

| Threat                                             | Mitigation                                                                                                                       |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --- | --------------------------- |
| Classical-adversary forgery (no CRQC)              | Forging a `v3=` signature requires forging both Ed25519 and ML-DSA-65 over the same bytes.                                                                                                                       |
| CRQC adversary forging new receipts                | The adversary can forge Ed25519 but not ML-DSA-65, so a forged `v3=` signature fails (`ok: false`). This holds only for verifiers that reject `v2=` from the issuer (next row).                                  |
| Downgrade to `v2=`                                 | **Not prevented by the format.** The Ed25519 half of any `v3=` signature is a valid `v2=` signature over the same canonical. A verifier MUST require `v3=` from an issuer that publishes an ML-DSA-65 key, or the dual signature adds nothing. |
| Substitution of one half                           | Both halves sign the same canonical bytes; `ok` requires both to verify.                                                                                                                                        |
| Side-channel leakage from ML-DSA-65 signer         | Out of scope for the format. The reference implementation uses `@noble/post-quantum`, which its authors describe as self-audited, not independently audited; JavaScript gives no constant-time guarantees.   |
| Canonicalization drift                             | Both halves consume the same projected bytes from §5.                                                                                                                                                           |

---

## 10. Versioning

VAOS 3.0 is the last specified version under the current signature-
prefix scheme. Future revisions (VAOS 4.0+) reserve the `v4=`
prefix for the next post-quantum signature family — anticipated
candidates include FN-DSA (Falcon) and SLH-DSA (SPHINCS+, FIPS 205).

A conforming v3 verifier MUST reject any wire prefix it does not
recognize. Forward-compatibility is **opt-in by major version**, not
implicit.

---

## 11. Test Vectors

### 11.1 Vector A — Ed25519 half

Use VAOS 2.0 Test Vector A (§11.1) unchanged. The Ed25519 half of a
v3 wire string is byte-equivalent to a v2 wire string.

### 11.2 Vector B — ML-DSA-65 half

Reference implementation `@noble/post-quantum` exposes
`ml_dsa65.sign(secretKey, message)` and `ml_dsa65.verify(publicKey,
message, signature)`. A conforming verifier MUST produce
`mldsa65: true` for any signature produced by this primitive over
the canonical projection bytes.

### 11.3 Vector C — verifier conformance

Run the reference implementation's `verifyDualSig()` helper against
both halves of a v3 receipt with both keys. A conforming verifier
MUST produce the same `DualSigVerdict` envelope as the reference
implementation across all 64 possible 2×2 cases (Ed25519 valid /
invalid × ML-DSA-65 valid / invalid).

---

## 12. Acknowledgements

VAOS 3.0 is informed by the design of:

- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) —
  ML-DSA standardization.
- [NIST SP 1800-38](https://www.nccoe.nist.gov/projects/migration-post-quantum-cryptography)
  — dual-signature migration playbook.
- The IETF [hybrid PKIX working group](https://datatracker.ietf.org/wg/lamps/about/)
  — composite signature schemes in X.509.
- [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)
  — the audited ML-DSA-65 reference implementation used by Sovereign
  Matrix.

---

## 13. Contact

Editorial feedback: an issue on the repository. Security reports: a private GitHub security advisory (see `SECURITY.md`).
