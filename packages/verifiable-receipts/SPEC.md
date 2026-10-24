# Wire formats of `@sovereignos/verifiable-receipts` 0.4

This file ships with the package and describes the formats this
version emits and accepts. The full specifications are in the
repository's [`docs/specs/`](https://github.com/christiaan839-beep/verifiable-receipts/tree/main/docs/specs):
[VAOS 2.0](https://github.com/christiaan839-beep/verifiable-receipts/blob/main/docs/specs/vaos-2.0.md)
(Ed25519 receipts), [VAOS 3.0](https://github.com/christiaan839-beep/verifiable-receipts/blob/main/docs/specs/vaos-3.0.md)
(dual signature), [the transparency log](https://github.com/christiaan839-beep/verifiable-receipts/blob/main/docs/specs/transparency-log.md),
[VAOS-RSA 1.0](https://github.com/christiaan839-beep/verifiable-receipts/blob/main/docs/specs/vaos-rsa-1.0.md)
(stream attestation) and [VAPT 1.0](https://github.com/christiaan839-beep/verifiable-receipts/blob/main/docs/specs/vapt-1.0.md)
(payment tokens). Where this file and the code disagree, the code is
right and this file has a bug.
Terms are defined in
[`docs/ontology.md`](https://github.com/christiaan839-beep/verifiable-receipts/blob/main/docs/ontology.md).

> The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

---

## Quick reference

| Wire prefix | Algorithm                     | Signature bytes | Produced by                                 |
| ----------- | ----------------------------- | --------------- | ------------------------------------------- |
| `v2=`       | Ed25519 (RFC 8032)            | 64              | `verifiable-receipts-sign`, Python signer   |
| `v3=`       | Ed25519 + ML-DSA-65 (FIPS 204) | 64 + 3309       | `verifiable-receipts-sign --mldsa-key`      |

`v1=` (HMAC-SHA256, VAOS 1.0) is not produced or verified by this
package; the Python and Go verifiers reject it.

---

## Receipt

A signed receipt is a JSON object with three fields the signer adds:

- `canonical`: the exact UTF-8 string that was signed;
- `contentHash`: `sha256:` followed by the lowercase hex SHA-256 of
  `canonical`;
- `signature`: `v2=<base64>` or `v3=<base64>.<base64>`, standard
  base64 alphabet with padding (RFC 4648 §4).

Every other field of the receipt repeats a field of the parsed
`canonical`. Verifiers check `canonical` as given and do not rebuild
it; they reject a receipt whose other fields disagree with the parsed
`canonical` or are missing from it (VAOS 2.0 §5 and §7). Neither the
receipt nor `canonical` may nest deeper than 64 (VAOS 2.0 §7.2).

### Canonical projection

`verifiable-receipts-sign` builds `canonical` from a JSON body:

1. Drop `canonical`, `contentHash` and `signature` from the body.
2. Sort object keys at every depth (JavaScript `Array.prototype.sort`,
   which orders by UTF-16 code unit). A `__proto__` key is kept as an
   ordinary key.
3. `JSON.stringify` with no whitespace. A body nested deeper than 64 is
   refused with an error.

The Python `canonicalize` sorts by code point and refuses floats. The
two agree on keys made only of characters in the Basic Multilingual
Plane and on bodies whose numbers are integers; outside that, sign
with one implementation and verify the `canonical` string as given.

---

## `v2=`: Ed25519

```
v2=<base64 of the 64-byte Ed25519 signature over canonical>
```

```ts
import { sign, verify } from "node:crypto";
const wire = "v2=" + sign(null, Buffer.from(canonical, "utf8"), privateKey).toString("base64");
const ok = verify(null, Buffer.from(canonical, "utf8"), publicKey, Buffer.from(wire.slice(3), "base64"));
```

---

## `v3=`: Ed25519 + ML-DSA-65

```
v3=<base64 Ed25519 signature>.<base64 ML-DSA-65 signature>
```

Both halves sign the same `canonical` bytes. ML-DSA-65 is pure
ML-DSA (FIPS 204 ML-DSA.Sign) with an empty context string, as
implemented by `@noble/post-quantum` 0.6. The literal `.` is the only
separator.

```ts
import { sign, verify } from "node:crypto";
import { signMlDsa65, verifyDualSig, formatV3Wire } from "@sovereignos/verifiable-receipts/pq-sign";

const ed = sign(null, Buffer.from(canonical, "utf8"), edPrivateKey).toString("base64");
const wire = formatV3Wire(ed, signMlDsa65(canonical, mldsaSecretKey));

const verdict = verifyDualSig(canonical, wire, mldsaPublicKey, (c, sig) =>
  sig.startsWith("v2=") &&
  verify(null, Buffer.from(c, "utf8"), edPublicKey, Buffer.from(sig.slice(3), "base64")),
);
// { ok, ed25519, mldsa65 }: ok is true only when both halves verify.
```

`verifyDualSig` rejects a half that is not canonical padded base64,
an Ed25519 half that is not 64 bytes and an ML-DSA-65 half that is
not 3309 bytes.

**Downgrade.** The Ed25519 half of a `v3=` signature is itself a
valid `v2=` signature over the same `canonical`. The dual signature
protects against a broken Ed25519 only if the verifier refuses `v2=`
receipts from an issuer that signs with ML-DSA-65. The format cannot
enforce this; the relying party's policy must.

---

## Signed bundle: `MANIFEST.signed.json`

`buildSignedBundle` writes a STORE-method ZIP with three files per
receipt (`receipts/<id>.canonical.txt`, `.signature.txt`,
`.meta.json`) and a manifest:

```jsonc
{
  "v": 1,
  "type": "verifiable-receipt-bundle",
  "generatedAt": "2026-05-17T00:00:00.000Z",
  "receiptCount": 2,
  "bundleDigest": "<hex sha256 over each entry's path, NUL, bytes, NUL>",
  "receipts": [
    { "id": "…", "agentName": "…", "modelUsed": "…", "issuedAt": "…", "signature": "v2=…" }
  ],
  "manifestHash": "<hex sha256 of the fields above, keys sorted at every depth>",
  "signature": "<the caller's signature over manifestHash>"
}
```

`verifyManifest` and the `verifiable-receipts verify` CLI:

1. check `type` and `v`;
2. recompute `manifestHash` over every field except `manifestHash` and
   `signature`, and compare;
3. check `signature` over the `manifestHash` string with the caller's
   verifier (the CLI uses Ed25519 `v2=`).

They do not open the ZIP: recompute `bundleDigest` over the archive's
entries to check the files. They do not check each receipt's own
signature. Receipt ids are mapped to file names by replacing every
character outside `[A-Za-z0-9_-]` with `_`, so two ids can collide.

The CLI exits 0 when the manifest verifies, 1 when it does not and 2
on a usage error; `--json` prints a JSON result.

---

## Other formats

- **Guardian attestation** (`runGuardian`): `canonical` is
  `{"v":1,"type":"guardian-verdict",verdictId,runId,agentSlug,tokenId,overall,rules,issuedAt}`
  with `rules` sorted by `ruleId` (UTF-16 code unit) and reduced to
  `{ruleId, verdict, reason}`; `contentHash` is the bare hex SHA-256.
- **Transparency log**: RFC 6962 §2.1 hashing (`0x00` leaf prefix,
  `0x01` inner prefix), RFC 9162 §2.1.3 inclusion and §2.1.4
  consistency proofs. Tree heads are returned unsigned. Every hash is
  64 lowercase hex digits and every index or size a safe integer;
  anything else is rejected (`docs/specs/transparency-log.md` §3.6).
- **Threshold envelope** (`trs1`): each cosigner signs
  `trsSigningBytes(canonical, {m, n}, authorizedIssuers)`.
- **Stream attestation** (`rsa1`) and **VAPT** (`vapt1.`): see their
  specs in `docs/specs/`.

---

## License

The specifications are CC0 1.0. The code is Apache-2.0.

## Contact

Report a suspected vulnerability through a private GitHub security
advisory on
[christiaan839-beep/verifiable-receipts](https://github.com/christiaan839-beep/verifiable-receipts/security/advisories/new).
See `SECURITY.md` in the repository.
