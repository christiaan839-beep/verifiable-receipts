# Changelog

Notable changes to the Go module
`github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go`.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Earlier changes are in the git history only.

## [Unreleased]

## [0.2.0] — 2026-10-30

### Security

- Ed25519 signatures are verified under the strict profile of VAOS 2.0
  §7.3 (amended 30 October 2026), so this verifier, the TypeScript one
  on Node.js 22 or 24.22 and the Python one give one verdict on every
  signature. Before `crypto/ed25519` sees a signature, its R must be a
  canonical encoding of a point of order L (not of small order, the
  identity included, nor of mixed order) and its S below L; a key must
  be a point of order L too. v0.1.0 accepted R = identity with
  S = k*a, and Node.js 24.22.1 (OpenSSL 3.5.9) and 26.10.0 (OpenSSL
  3.5.8) refuse R = identity, which Node.js 22.23.2 accepts; it also
  accepted keys of mixed order. So v0.1.0 is retracted
  (`go.mod`). New reasons: `public key is not a point on the curve`,
  `public key is not in the prime-order subgroup`, `signature R is not
  a canonical encoding`, `signature R is not a point on the curve`,
  `signature R is a small-order point`, `signature R is not in the
  prime-order subgroup`. `LoadEd25519PublicKeyFromPEM` refuses the new
  keys too; the key's answer is cached. The arithmetic uses
  `math/big` (`edwards25519.go`); the module still has no dependencies.

### Added

- `VerifyEd25519(pub, message, sig)`: one raw Ed25519 signature under
  the strict profile, returning a `VerifyResult`.
- `Ed25519PublicKeyProblem(pub)` and `Ed25519SignatureProblem(sig)`, the
  two pre-checks of `VerifyEd25519` on their own: why a raw key, or a
  signature's R and S, is refused, or `""`. The same reasons, in the
  same order, as TypeScript `ed25519PublicKeyProblem` and
  `ed25519SignatureProblem`; a key that is not 32 bytes gets `public key
  is not 32 bytes`.

### Release

- The release is built reproducibly, with SLSA v1.0 Build Level 3
  provenance (signed by the reusable workflow
  `.github/workflows/build.yml`) and a CycloneDX SBOM, itself attested,
  for each file. The GitHub release for
  `packages/verifiable-receipts-go/v0.2.0` has
  `verifiable-receipts-go-v0.2.0.zip`, an SBOM (`FILE.cdx.json`) and the
  provenance and SBOM attestation bundles
  (`FILE.provenance.sigstore.json`, `FILE.sbom.sigstore.json`) for each,
  and `SHA256SUMS`. The zip is the module zip, the same bytes
  `proxy.golang.org` serves (the release workflow checks it) and the zip
  the `go.sum` hash covers. RELEASING.md ("Verifying a release",
  "Rebuilding a release") has the commands.

## [0.1.0] — 2026-10-30

### Security

- `VerifyV2Receipt` and `VerifyGuardianAttestation` reject a receipt
  nested deeper than 64, and a `Canonical` whose text nests deeper than
  64, with the reasons `receipt nesting deeper than 64` and `canonical
  nesting deeper than 64` (VAOS 2.0 §7.2). Before, Go accepted receipts
  thousands of levels deep that the TypeScript verifier crashed on and
  the Python verifier rejected.
- `LoadEd25519PublicKeyFromPEM` and `VerifyV2Receipt` refuse a public key
  that is a point of small order (the libsodium blocklist, sign bit
  cleared) or a non-canonical encoding (y >= p), with the reasons
  `public key is a small-order point` and `public key is not a canonical
  encoding` (VAOS 2.0 §7.3).

### Added

- `ParseReceipt(data)` reads a receipt from JSON text, counting its depth
  on the text before `encoding/json` sees it, so it returns `vaos:
  receipt nesting deeper than 64` at any depth (json.Unmarshal stops at
  10,000 levels with its own error), a duplicate key the parser discards
  included.

### Changed

- `(*Receipt).UnmarshalJSON` returns `vaos: receipt nesting deeper than
  64` for a receipt nested deeper than 64. It no longer fails on a
  `canonical`, `signature` or `contentHash` that is not a string: the
  receipt parses and `VerifyV2Receipt` rejects it with the TypeScript
  and Python reasons (`missing canonical projection`, `missing
  signature`, `contentHash must be a string`), at the same step. Callers
  that relied on the old `receipt field "…" is not a string` error get a
  failed verdict instead.
- Signature base64 failures now have the TypeScript and Python reasons:
  `signature base64 invalid` when the text is not padded standard base64
  (CR and LF included), and `signature base64 invalid: not canonical`
  when it decodes but re-encodes differently. Before, the reason carried
  the decoder's message.
