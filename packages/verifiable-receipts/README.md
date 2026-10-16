# @sovereign-matrix/verifiable-receipts

TypeScript library for signed AI agent receipts. Version 0.3.1,
Apache-2.0. Not published to npm yet: install it from this repository.

A receipt records an agent run (inputs, output, the checks that ran and
their verdicts) as a canonical JSON string, and signs that string. Anyone
with the issuer's public key can verify it later.

## What is in it

- **Signing and verification.** Ed25519 (`v2=`) and Ed25519 plus
  ML-DSA-65, FIPS 204 (`v3=<ed25519>.<ml-dsa-65>`). The wire format is in
  [`SPEC.md`](./SPEC.md).
- **Transparency log proofs.** RFC 9162 inclusion and consistency proofs,
  and signed tree heads (`src/transparency.ts`).
- **Signed bundles.** A deterministic ZIP of receipts with a signed
  `MANIFEST.signed.json` (`src/bundle.ts`).
- **Rule runner and packs.** `runGuardian` runs a set of rules over an
  agent run and returns a signed verdict. `src/packs.ts` exports 42 rule
  packs (listed below); each rule's description names the clause it
  checks. They are pattern checks that help gather evidence, not legal
  advice or a compliance guarantee.
- **C2PA bridge.** Converts a signed verdict to and from a C2PA manifest
  assertion labelled `org.sovereignmatrix.vaos.v1`.
- **Three CLIs.** `verifiable-receipts` (verify a bundle manifest),
  `verifiable-receipts-sign` (sign a JSON body) and
  `verifiable-receipts-witness` (cosign a transparency log's tree heads).

Other modules in `src/`: `anomaly`, `audit-dsl`, `log-store`, `red-team`,
`stream-attestation`, `threshold`, `vapt`. [`proofs/`](./proofs) holds five
written proof sketches in Markdown; they are not machine-checked.

## Receipt shape (v2)

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

`canonical` is the exact UTF-8 JSON that was signed, `contentHash` is
`sha256:` plus the hex SHA-256 of `canonical`, and `signature` is `v2=`
plus the base64 Ed25519 signature over `canonical`. Every other field
repeats a field of `canonical`: the Python and Go verifiers reject a
receipt with a field that disagrees with the parsed `canonical` or that
`canonical` does not contain.

## Install from the repository

```bash
git clone https://github.com/christiaan839-beep/verifiable-receipts
cd verifiable-receipts/packages/verifiable-receipts
npm install    # installs the dev tools and builds dist/
# then, from your own project:
npm install --install-links /path/to/verifiable-receipts/packages/verifiable-receipts
```

`dist/` is not committed: `npm install` in the package builds it (the
`prepare` script runs `tsc`), and the second command packs the built
package into your project. Node 18 or later. One runtime dependency:
`@noble/post-quantum` (for ML-DSA-65).

## Tests

Measured on 16 October 2026: **689 passed, 4 skipped** (vitest 3, 22 test
files, including the cross-language conformance suite; Node 22). The four
skipped tests are the witness CLI's network flow, skipped in
`tests/witness-cli.test.ts`. To run them, from a clone of this repository:

```bash
cd packages/verifiable-receipts
npm install
npm test
```

The [`conformance/`](./conformance) folder has 14 JSON fixtures (valid
and tampered receipts, wrong keys, fields beside `canonical` that agree
or disagree with it, inclusion proofs). The TypeScript, Python
([`../verifiable-receipts-py`](../verifiable-receipts-py)) and Go
([`../verifiable-receipts-go`](../verifiable-receipts-go)) verifiers all
run against them and must agree. [`conformance/roundtrip/`](./conformance/roundtrip)
signs receipts with the Python signer, `verifiable-receipts-sign` and
`runGuardian` under a throwaway key and verifies each in Python, Go and
node; CI runs it.

## Sign and verify a verdict

```ts
import {
  runGuardian,
  verifyGuardianAttestation,
  composePacks,
  hipaaPack,
  sr117Pack,
} from "@sovereign-matrix/verifiable-receipts";
import { generateKeyPairSync, sign, verify } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const rules = composePacks(hipaaPack, sr117Pack);

const verdict = await runGuardian(
  rules,
  {
    runId: "run_1",
    agentSlug: "loan-underwriter",
    tokenId: "tok_1",
    input: { applicantId: "u1" },
    output: { decision: "approved" },
  },
  // Bring your own signer: node:crypto, a KMS, an HSM.
  (canonical) =>
    `v2=${sign(null, Buffer.from(canonical), privateKey).toString("base64")}`,
);

console.log(verdict.overall); // "pass" | "warn" | "block"

const result = verifyGuardianAttestation(verdict, (canonical, signature) =>
  signature.startsWith("v2=") &&
  verify(
    null,
    Buffer.from(canonical),
    publicKey,
    Buffer.from(signature.slice(3), "base64"),
  ),
);
console.log(result.ok); // true
```

## Post-quantum signature

```ts
import {
  generateMlDsa65Keypair,
  signMlDsa65,
  verifyMlDsa65,
} from "@sovereign-matrix/verifiable-receipts";

const { secretKeyB64, publicKeyB64 } = generateMlDsa65Keypair();
const sig = signMlDsa65(canonical, Buffer.from(secretKeyB64, "base64"));
const ok = verifyMlDsa65(canonical, sig, Buffer.from(publicKeyB64, "base64"));
```

## Signed bundle

```ts
import { buildSignedBundle, verifyManifest } from "@sovereign-matrix/verifiable-receipts";

const { zip, manifest } = buildSignedBundle(rows, (manifestHash) => sign(manifestHash));
const check = verifyManifest(manifest, (canonical, signature) => verify(canonical, signature));
```

## CLIs

After installing, the binaries are on your project's `node_modules/.bin`:

```bash
npx verifiable-receipts verify --manifest ./MANIFEST.signed.json --pubkey ./ed25519.pem
npx verifiable-receipts-sign --input ./body.json --key ./ed25519-private.pem --out ./signed.json
npx verifiable-receipts-witness --url https://issuer.example --key ./witness.pem --witness-id "Name" --once
```

Run any of them with `--help` for the full flags (`verifiable-receipts-sign
--mldsa-key` adds the ML-DSA-65 signature for a `v3=` receipt).
`verifiable-receipts verify` exits `0` (verifies), `1` (fails) or `2`
(usage error).

`verifiable-receipts-sign` drops any `canonical`, `contentHash` and
`signature` from the body, sorts its keys at every depth, signs the
compact JSON, and writes the body's fields plus `canonical`,
`contentHash` and `signature`. A `v2=` receipt from it verifies with the
Python `verify_v2_receipt` and the Go `VerifyV2Receipt`.

## Rule packs

The 42 packs exported from `src/packs.ts`:

- **United States:** `hipaaPack`, `sr117Pack`, `naicPack`, `dscsaPack`,
  `cfpbPack`, `nydfsPack`, `nycAedtPack`, `ferpaPack`, `fdaSaMDPack`,
  `fdaPccpPack`, `coloradoAiPack`, `californiaAb2013Pack`,
  `illinoisAiPack`, `texasAiPack`, `nistAiRmfPack`, `carmackLogisticsPack`,
  `ambientScribePack`
- **Canada:** `canadaAidaPack`, `quebecLaw25Pack`
- **Latin America:** `brazilLgpdAiPack`
- **Europe and UK:** `euAiActPack`, `doraPack`, `csrdPack`, `fcaPack`, `ukIcoPack`
- **Asia-Pacific:** `masPack`, `japanAppiPack`, `koreaPipaPack`,
  `indiaDpdpAiPack`, `chinaPiplGenAiPack`, `vietnamCyberPack`, `apraCps230Pack`
- **Middle East and Africa:** `southAfricaPopiaPack`, `uaePdplPack`, `saudiPdplPack`
- **Standards and cross-cutting:** `iso42001Pack`, `pciDssPack`,
  `owaspAgenticTop10Pack`, `mcpGovernancePack`, `multiAgentCascadePack`,
  `pedagogicalAiPack`, `industrialFoundationPack`

Compose them with `composePacks(...)`. Subpath imports are available:
`/pq-sign`, `/guardian`, `/bundle`, `/packs`.

## License

Apache-2.0; see [LICENSE](./LICENSE). Report suspected bugs in the
cryptography privately to `security@sovereignmatrix.agency` (the security
contact in [SPEC.md](./SPEC.md#contact)) before disclosing them.
