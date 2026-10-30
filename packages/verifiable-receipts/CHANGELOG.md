# Changelog

All notable changes to `@sovereignos/verifiable-receipts` are documented
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] — 2026-10-30

This version releases the 0.5.0 changes below, and adds the strict
Ed25519 profile of VAOS 2.0 §7.3. 0.5.0 was tagged but never
published: the release workflow failed before publishing (fixed in
#35).

### Security

- Ed25519 signatures are verified under a strict profile (VAOS 2.0
  §7.3, amended 30 October 2026), so every verifier gives one verdict.
  Before, `node:crypto` on Node.js 24.22.1 (OpenSSL 3.5.9) rejected a
  signature with R = identity that Node.js 22, the Python and Go
  verifiers and the browsers accepted, and WebKit on Linux rejected one
  under a mixed-order key that the rest accepted. Now, before
  `node:crypto` sees a signature, the key and the signature's R must be
  canonical encodings of points of order L, and S must be below L. A
  signature an honest signer makes is never refused.
  - New: `verifyEd25519(publicKey, message, signature)`, returning
    `{ ok, reason }`, and `ed25519SignatureProblem(signature)`.
  - `ed25519PublicKeyProblem` and `loadEd25519PublicKey` also refuse a
    key off the curve (`public key is not a point on the curve`) and a
    key of mixed order (`public key is not in the prime-order
    subgroup`). Their answers are cached per key.
  - New reasons for R: `signature R is not a canonical encoding`, `...
    is not a point on the curve`, `... is a small-order point`, `... is
    not in the prime-order subgroup`. `S >= L` keeps `signature does
    not verify under the supplied public key`.
  - The `verifiable-receipts` CLI and `verifiable-receipts-witness`
    (its `--log-public-key` check) verify through `verifyEd25519`.
  - Pure BigInt edwards25519 arithmetic (`src/edwards25519.ts`), no new
    dependency.
- The conformance suite has twenty Ed25519 edge fixtures
  (`conformance/fixtures/ed25519-*.json`, written by
  `generate-ed25519-fixtures.py`) and a fixture kind, `ed25519`, for
  RFC 8032's test vectors. The differential run builds Ed25519 edge
  cases and runs the TypeScript verifier on Node.js 22 and 24.

### Fixed

- The release workflow creates the `npm pack` destination directory
  before packing. `npm pack --pack-destination` does not create it, so
  the build of `js-v0.5.0` failed with ENOENT before anything was
  published (#35).

## [0.5.0] — 2026-10-30

### Changed

- The package is published as `@sovereignos/verifiable-receipts`, the
  npm organisation that exists. No version was ever published under the
  old `@sovereign-matrix` scope, so nothing moves for existing users.

### Security

- `verifiable-receipts-witness` cosigns only the tree head it checked.
  It rebuilds the canonical from the fields and signs that, after
  requiring the log's `canonical` to match it byte for byte; before,
  a log could pass the consistency proof with one root and have the
  witness sign a canonical naming another. It also refuses: a field
  with more than one spelling, or a field the schema does not allow;
  an empty tree whose root is not SHA-256 of no bytes; a `logId` with
  control characters, one that differs from its state file, or one
  that differs from the new `--log-id`; a different root at a size it
  already signed; a timestamp earlier than the one it saved; and, with
  the new `--log-public-key`, a log signature that does not verify, or
  a `v3=` head.
- The witness saves the new head atomically before the signature
  leaves the process, so a log that stores a cosignature but answers
  an error cannot get a second one on another root at that size. A
  failed submission is resubmitted exactly as saved, with the same
  bytes and signature, even if the log has re-dated the head. Each
  poll holds a lock file beside the state file's real path, as a
  lease renewed every 5 s, so two witness processes on one state file
  do not both sign while each renews its lease: including two that
  share a pid and hostname in separate pid namespaces. A lock is stale
  only when its lease (3 × `--timeout` + 30 s) has run out; it is then
  broken under a second lock file, and only if unchanged. A process
  that finds its lock taken over (its own lease ran out) neither
  saves nor signs, and no save moves the state file to a smaller tree
  size or to another root at the same size.
  SIGTERM and SIGINT release the lock. `--break-lock` is the explicit
  way out; if another witness is still running, two can sign. The
  lease is judged by file mtimes, so on a network file system it is
  only as good as the hosts' clocks and the file system's exclusive
  create.
- A state file that exists but cannot be read or is malformed is
  refused instead of treated as a first run.
- Requests time out (`--timeout`, 1 to 3600 s, default 30), never
  follow a redirect, and refuse bodies over 1 MiB. Every `[witness]`
  line escapes control characters, U+2028/U+2029 and the
  bidirectional controls, and strings from the log are printed quoted. `--interval` below 60 or not a number is
  a usage error.
- `verifyGuardianAttestation` returns `{ ok: false, reason:
  "nesting-too-deep" }`, checked first, for an attestation nested deeper
  than 64 (VAOS 2.0 §7.2), or a `canonical` whose text nests deeper than
  64; a `canonical` that is not a string gets `"canonical-mismatch"`. Before, a signed attestation whose
  `runId` nested 64 deep was accepted, which the Python and Go verifiers
  reject, and one nested 20,000 deep made it throw `RangeError` (stack
  overflow).
- `verifyManifest` returns `{ ok: false, reason: "nesting-too-deep" }`
  for a manifest nested deeper than 64, checked first. Before, one
  nested 5,000 deep made it throw `RangeError`. `"nesting-too-deep"` is a
  new member of its reason type.
- The `verifiable-receipts` CLI refuses a `--pubkey` that is a point of
  small order or a non-canonical encoding (VAOS 2.0 §7.3). Under the
  identity key, for one, a signature verifies every message.
- The `verifiable-receipts` and `verifiable-receipts-sign` CLIs count the
  depth of the manifest or body on its text before parsing it, so a
  duplicate key that `JSON.parse` discards still counts: a manifest
  deeper than 64 fails with `nesting-too-deep`, a body is refused.
- The conformance v2 verifier (`conformance/verify-v2.mjs`) rejects a
  receipt nested deeper than 64 before any other check, and a
  `canonical` whose text nests deeper than 64 before parsing it, with
  the reasons `receipt nesting deeper than 64` and `canonical nesting
  deeper than 64`, as the Python and Go verifiers now do. Before, a
  receipt whose canonical and field nested 5,000 deep made it throw
  `RangeError`. Its `jsonEqual` treats arrays and objects deeper than 64
  as unequal, so no caller can make it recurse deeper, and it refuses a
  weak public key as `loadEd25519PublicKey` does. It also exports
  `nestsTooDeep`, `textNestsTooDeep` and `parseReceipt`, which reads a
  receipt from text with its depth counted on the text first, as
  Python's `parse_receipt` and Go's `ParseReceipt` do.

### Added

- `loadEd25519PublicKey(pem)` loads an Ed25519 verification key and
  throws on a key that is a point of small order or a non-canonical
  encoding; `ed25519PublicKeyProblem(raw)` says why a raw key is refused
  (VAOS 2.0 §7.3).

### Changed

- `canonicalJson`, and with it `verifiable-receipts-sign`, refuses a
  body nested deeper than 64 with an error instead of overflowing the
  stack at a few thousand levels: no verifier accepts such a receipt.

### Fixed

- `SPEC.md` names `@noble/post-quantum` 0.7, the version the package
  depends on (`^0.7.1`); it said 0.6.

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
- `TransparencyLog.rootHash()`: it returned `currentSth().rootHash`,
  which stays.
- `ZipEntry.data` is renamed `ZipEntry.content`, the name
  `StreamChunk` uses for the same thing.

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
  `v2-invalid-crlf-base64.json`.
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
- The inclusion and consistency proof verifiers (TypeScript, Python,
  Go) require every hash to be 64 lowercase hex digits and every index
  or size to be an integer in range; anything else returns false. Before,
  a 64-byte "leaf" with an empty audit-path entry verified against a
  two-leaf root in all three; uppercase and `0x`-prefixed hex were
  accepted; TypeScript accepted a fractional or NaN index and wrapped
  index arithmetic at 32 bits (a two-leaf proof verified for a tree of
  2^32 + 2 leaves); `verifyConsistencyProof` threw on such sizes; Python
  raised `OverflowError` on an infinite index and read `true`, `"1"` and
  `1.5` as 1. Seven new fixtures (23 in all); the rules are in
  `docs/specs/transparency-log.md` §3.6.
- A differential run (`conformance/differential/`) gives the three
  verifiers the same random receipts and proofs and fails on any
  disagreement; CI runs it on every pull request and nightly. Its first
  runs found two: the Python and Go proof verifiers accepted tree sizes
  above 2^53 − 1 (now rejected, as TypeScript did), and envelope fields
  holding an integer of 2^53 or more compared differently (TypeScript
  reads 2^53 + 1 as 2^53). Such a number in a repeated field now fails
  the comparison in all three (`docs/specs/vaos-2.0.md` §7 step 6). An
  index or size written as `284.0` is the integer 284 in all three.

### Changed

- Specs and docs: removed claims the code does not back. The ML-DSA-65
  signature is 3309 bytes (FIPS 204), not 3293; "forward-secure" is
  gone; VAOS 3.0 now states that a `v3=` signature can be downgraded to
  `v2=` unless the verifier refuses `v2=`; `@noble/post-quantum` is
  described as self-audited, as its authors say. The TRS soundness and
  v2 non-malleability proof sketches were wrong in the cases above and
  carry correction notes.
- `SPEC.md` rewritten to match what this version emits and accepts.
- `engines.node` is `>=22.12`: Node 20 reached end of life on 30 April
  2026, and CI tests Node 22 and 24. `@noble/post-quantum` is 0.7.1
  (its ML-DSA fixes include an intermediate overflow in NTT
  multiplication); signatures made with 0.6.1 verify under 0.7.1 and the
  other way round.
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
- `verifiable-receipts-sign` requires `--mldsa-key` to decode to an
  ML-DSA-65 secret key, exactly 4032 bytes; it used to accept anything
  of 32 bytes or more.
- The Go module drops `ErrEmptyAuditPath`, which nothing returned (its
  doc named a `VerifyInclusionProofStrict` that does not exist).
- Doc comments that described what the code does not do are corrected:
  TRS cosigners sign `trsSigningBytes()`, not the bare VAOS 2.0
  canonical; `verifyVapt` does not act on `singleUse`, `userId` or
  `agentId`; `FileLogStore` appends are not crash-atomic, but a torn
  last line is rejected on load.
- The three CLIs share their argument parsing (`bin/cli.mjs`), and
  `verifiable-receipts-sign` and `buildSignedBundle` share one
  key-sorting canonicalizer (`src/canonical-json.ts`); neither is
  exported.

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
`@sovereignos/verifiable-receipts: ">=0.3.0"` as a peer dependency.

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
