# Changelog

Notable changes to the Python package `sovereign-matrix-verifiable-receipts`
(`packages/verifiable-receipts-py`). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Earlier changes
are in the git history only.

## [Unreleased]

## [0.3.0] — 2026-10-30

### Security

- `verify_v2_receipt` and `verify_guardian_attestation` reject a receipt
  nested deeper than 64, and a `canonical` whose text nests deeper than
  64, with the reasons `receipt nesting deeper than 64` and `canonical
  nesting deeper than 64` (VAOS 2.0 §7.2). The attestation is counted
  as given, its unsigned fields included. Before, a deep receipt
  reached the recursion limit (an uncaught `RecursionError` in
  `verify_guardian_attestation`), and verdicts differed from the
  TypeScript and Go verifiers.
- The verifiers refuse a public key that is a point of small order (the
  libsodium blocklist, sign bit cleared) or a non-canonical encoding
  (y >= p), with the reasons `public key is a small-order point` and
  `public key is not a canonical encoding` (VAOS 2.0 §7.3). Under the
  identity key, for one, a signature verifies every message.
- Ed25519 signatures are verified under the strict profile of VAOS 2.0
  §7.3 (amended 30 October 2026), so this verifier, the TypeScript one
  on Node.js 22 or 24.22 and the Go one give one verdict on every
  signature. Before `cryptography` sees a signature, its R must be a
  canonical encoding of a point of order L (not of small order, the
  identity included, nor of mixed order) and its S below L; a key must
  be a point of order L too. Before, R = identity with S = k*a verified
  here and in Go; Node.js 24.22.1 (OpenSSL 3.5.9) and 26.10.0 (OpenSSL
  3.5.8) refuse R = identity, which Node.js 22.23.2 accepts. New
  reasons: `public key is not a point on the curve`, `public key is not
  in the prime-order subgroup`, `signature R is not a canonical
  encoding`, `signature R is not a point on the curve`, `signature R is
  a small-order point`, `signature R is not in the prime-order
  subgroup`. PEM loading refuses the new keys too; its answer is cached
  per key. The arithmetic is pure Python (`edwards25519.py`).

### Added

- `verify_ed25519(public_key, message, signature)`: one raw Ed25519
  signature under the strict profile, returning a `VerifyResult`.
- `ed25519_public_key_problem(raw)` and `ed25519_signature_problem(signature)`,
  the two pre-checks of `verify_ed25519` on their own: why a raw key, or
  a signature's R and S, is refused, or `None`. The same reasons, in the
  same order, as TypeScript `ed25519PublicKeyProblem` and
  `ed25519SignatureProblem`. An argument that is not bytes, bytearray or
  memoryview gets the reason of a wrong length, as in TypeScript and Go:
  `public key is not 32 bytes` for a key, `signature does not verify
  under the supplied public key` for a signature; neither raises.
- `parse_receipt(text)` reads a receipt from JSON text, counting its
  depth on the text first: it raises `ValueError("receipt nesting
  deeper than 64")` at any depth, a duplicate key the parser discards
  included, where `json.loads` alone raises `RecursionError` some
  thousands of levels down.
- `verifiable-receipts-mcp`, a Model Context Protocol server over stdio
  with three read-only tools: `verify_receipt`, `verify_receipt_log` (a
  JSONL log, one verdict per line) and `verify_receipt_in_log` (an RFC
  9162 inclusion proof against a tree head's root hash). Install it with
  the new `mcp` extra. Inputs are capped at 4 MiB of text and 10,000
  receipts per call.

### Changed

- Signature base64 failures now have the TypeScript and Go reasons:
  `signature base64 invalid` when the text is not padded standard
  base64, and `signature base64 invalid: not canonical` when it decodes
  but re-encodes differently. Before, the reason carried the decoder's
  message (`signature base64 invalid: Incorrect padding`, and others).
- `sign_v2_receipt` and `canonicalize` refuse a body nested deeper than
  64 with a `ValueError`.

### Release

- The release is built reproducibly, with SLSA v1.0 Build Level 3
  provenance (signed by the reusable workflow
  `.github/workflows/build.yml`) and a CycloneDX SBOM, itself attested,
  for each file. The GitHub release for `py-v0.3.0` has
  `sovereign_matrix_verifiable_receipts-0.3.0.tar.gz` and
  `…-py3-none-any.whl`, an SBOM (`FILE.cdx.json`) and the provenance and
  SBOM attestation bundles (`FILE.provenance.sigstore.json`,
  `FILE.sbom.sigstore.json`) for each, and `SHA256SUMS`. The files on
  PyPI are the attested ones. RELEASING.md ("Verifying a release",
  "Rebuilding a release") has the commands.
