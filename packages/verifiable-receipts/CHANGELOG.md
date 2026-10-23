# Changelog

All notable changes to `@sovereign-matrix/verifiable-receipts` are documented
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 2026-10-23

### Removed (breaking)

- `src/packs.ts` and the `./packs` export: the 42 "regulatory packs"
  (`hipaaPack`, `euAiActPack`, `composePacks`, `ALL_PACKS` and the
  rest). They were substring and regex checks with regulation text in
  their descriptions; they did not check compliance with anything.
  Write the rules you need as `GuardianRule`s.
- `src/red-team.ts` (`runRedTeam`, `defaultAdversarialCorpus`),
  `src/anomaly.ts` (`detectAnomalies`), `src/audit-dsl.ts`
  (`queryReceipts`, `parseQuery`) and `src/c2pa-bridge.ts`
  (`toC2PAManifest`, `fromC2PAManifest`), with their tests. Nothing in
  the signing, verification or log code used them.

### Security

- `verifyThresholdAttestation` rejects an envelope whose policy is not
  well formed: `m` and `n` must be integers with `1 <= m <= n`, and
  `authorizedIssuers` must list exactly `n` distinct ids. Before, an
  envelope with `m = 0` returned `ok: true` with no signatures.
- `verifyDualSig` and `verifyMlDsa65` reject base64 that is not
  canonical padded standard base64, an Ed25519 half that is not 64
  bytes and an ML-DSA-65 half that is not 3309 bytes.
- The `v2=` verifiers (Python, Go, the conformance harness and the
  `verifiable-receipts verify` CLI) reject base64 signatures with
  non-zero padding bits or with CR or LF inside, so a signature has one
  valid spelling. Go's decoder skips CR and LF even in strict mode, so
  the Go verifier also checks that the decoded bytes re-encode to the
  exact text. New fixtures: `v2-invalid-noncanonical-base64.json` and
  `v2-invalid-crlf-base64.json` (16 in all).
- `verifiable-receipts verify` refuses `v3=` manifests (it used to
  accept one on its Ed25519 half alone) and signatures without the
  `v2=` prefix.
- `verifyGuardianAttestation` returns `canonical-mismatch` instead of
  throwing when `canonical` is not a JSON object; `parseVapt` returns
  `null` for a payload that is JSON but not an object.
- `runGuardian` sorts rules by UTF-16 code unit instead of
  `localeCompare`, so the canonical no longer depends on the signer's
  locale. An attestation whose rule ids sort differently under the two
  orders, signed by 0.3.x, no longer passes the TypeScript
  `verifyGuardianAttestation`; the Python and Go verifiers are not
  affected.
- `buildSignedBundle` / `verifyManifest` keep a `__proto__` key in the
  hashed manifest instead of dropping it.

### Changed

- Specs and docs: removed claims the code does not back. The ML-DSA-65
  signature is 3309 bytes (FIPS 204), not 3293; "forward-secure" is
  gone; VAOS 3.0 now states that a `v3=` signature can be downgraded to
  `v2=` unless the verifier refuses `v2=`; `@noble/post-quantum` is
  described as self-audited, as its authors say. The TRS soundness and
  v2 non-malleability proof sketches were wrong in the cases above and
  carry correction notes.
- `SPEC.md` rewritten to match what this version emits and accepts.
- `engines.node` is `>=20.19` (what `@noble/post-quantum` 0.6 needs).
  Exports added for `./threshold`, `./stream-attestation` and `./vapt`.
- Dev tooling: vitest 5 (vitest 3 depended on a tinypool with a
  critical advisory), ESLint with typescript-eslint, `npm run
  typecheck` over sources and tests, `npm run check`. A
  `package-lock.json` is committed and CI uses `npm ci`.
- CI pins every action to a commit SHA and runs typecheck, ESLint,
  `npm audit`, `ruff`, `gofmt` and the existing suites.
- The Python package (0.2.1) and the Go module apply the same strict
  base64 rule; the Python code is lint-clean under the new root
  `ruff.toml`.

## [0.3.1] — 2026-10-16

### Fixed

- `verifiable-receipts-sign` writes `canonical` (the exact string it
  signed) and `contentHash` (`sha256:` plus the hex SHA-256 of
  `canonical`) beside the body's fields and `signature`. Its output
  used to carry only the body and `signature`, which the Python and Go
  verifiers reject ("missing canonical projection"). It now verifies in
  Python, Go and node. `v3=` signing is unchanged and signs the same
  `canonical`.
- `verifiable-receipts-sign` keeps a `__proto__` key of the body in the
  canonical. It used to drop it, so the output's `__proto__` field was
  unsigned.

### Added

- Three conformance fixtures for envelope consistency, 14 in all: a
  receipt whose fields beside `canonical` repeat it, one whose
  `overall` disagrees with it, and one with a field it does not
  contain. The conformance harness's v2 verifier moved to
  `conformance/verify-v2.mjs` and now checks those fields against the
  parsed canonical, as the Python and Go verifiers do.
- `conformance/roundtrip/`: signs with the Python signer, this CLI and
  `runGuardian` under a throwaway key, and verifies in Python, Go and
  node. CI runs it. Neither ships in the npm package.

### Changed

- `verifiable-receipts-sign` drops `canonical` and `contentHash` from
  its input before signing, as it already dropped `signature`, so
  signing its own output again gives the same canonical.
- The package moved from `sovereign-v2` to its own repository,
  [`christiaan839-beep/verifiable-receipts`](https://github.com/christiaan839-beep/verifiable-receipts),
  on 16 October 2026. The `repository`, `homepage` and `bugs` fields
  point there.
- `@types/node` and `vitest` are now dev dependencies and `npm test`
  runs the suite, so the package builds and tests on its own, outside
  the old npm workspace.

## [0.3.0] — 2026-05-19

The version number now reflects what is actually in the package. The
public surface area has grown well past `0.1.0`; this release bumps to
`0.3.0` to align with every workspace consumer that already declares
`@sovereign-matrix/verifiable-receipts: ">=0.3.0"` as a peer dependency.

### Added

- **VAOS-TRS 1.0** — Threshold Receipt Signatures (m-of-n cosigning) with
  canonical-binding via `trsSigningBytes(canonical, threshold, authorized)`
  so cosigner signatures cannot be reused across different policies.
- **VAOS-RSA 1.0** — Receipt Streaming Attestation, Merkle-rooted, for
  multi-chunk streaming outputs.
- **VAPT 1.0** — Verifiable Agentic Payment Tokens.
- **Receipt-Audit DSL** — SQL-like queries over signed receipt sets.
- **Anomaly detection** — statistical outlier detection over block-rate
  spikes, rule-failure drift, volume bursts, quiet periods.
- **C2PA bridge** — content provenance interop for image/video outputs.
- **Witness federation primitive** — independent third-party witnessing.
- **RFC 9162 transparency log** — inner/border bit-decomposition,
  byte-deterministic across the TS / Python / Go ports.
- **42 Guardian rule packs** across 7 continents: HIPAA, SR 11-7,
  EU AI Act, CFPB, NAIC, FDA SaMD, FERPA, NYC AEDT, Colorado SB 24-205,
  NIST AI RMF, OWASP Agentic Top 10, MCP governance, ISO/IEC 42001, and 30 more.

### Changed

- Subpath exports (`./transparency`, `./log-store`, `./packs`, etc.)
  now resolve through the package `exports` map.
- The `prepare` lifecycle script builds `dist/` automatically when the
  workspace is installed without it, so monorepo consumers don't have
  to remember to run `npm run build` first.

### Fixed

- Cross-language inclusion proofs: TS / Python / Go now produce
  byte-identical witnesses for the same Merkle leaf, including the
  previously-failing `idx=6` case in 7-leaf trees.

## [0.1.0] — initial release

- Ed25519 + ML-DSA-65 dual-signing
- Guardian verdict envelopes
- ZIP-bundle export with signed manifest
- Post-quantum forward-secure verification
