# Changelog

Notable changes to the Python package `sovereign-matrix-verifiable-receipts`
(`packages/verifiable-receipts-py`). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Earlier changes
are in the git history only.

## [Unreleased]

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

### Added

- `parse_receipt(text)` reads a receipt from JSON text, counting its
  depth on the text first: it raises `ValueError("receipt nesting
  deeper than 64")` at any depth, a duplicate key the parser discards
  included, where `json.loads` alone raises `RecursionError` some
  thousands of levels down.

### Changed

- Signature base64 failures now have the TypeScript and Go reasons:
  `signature base64 invalid` when the text is not padded standard
  base64, and `signature base64 invalid: not canonical` when it decodes
  but re-encodes differently. Before, the reason carried the decoder's
  message (`signature base64 invalid: Incorrect padding`, and others).
- `sign_v2_receipt` and `canonicalize` refuse a body nested deeper than
  64 with a `ValueError`.
