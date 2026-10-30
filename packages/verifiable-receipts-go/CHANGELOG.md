# Changelog

Notable changes to the Go module
`github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go`.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Earlier changes are in the git history only.

## [Unreleased]

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
