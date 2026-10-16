# sovereign-matrix verifiable-receipts (Go)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go 1.22+](https://img.shields.io/badge/go-1.22+-blue.svg)](https://go.dev/)

**Pure-Go verifier for VAOS receipts** — the Go counterpart to
[`@sovereign-matrix/verifiable-receipts`](../verifiable-receipts)
(TypeScript) and
[`sovereign-matrix-verifiable-receipts`](../verifiable-receipts-py)
(Python). The TypeScript and Python packages are not on npm or PyPI yet.

Verify Ed25519-signed receipts (VAOS 2.0), check Guardian attestation
envelopes, and walk RFC 9162 transparency-log inclusion proofs from
any Go process. Measured on 16 October 2026: 36 tests passed
(`go test ./...`, Go 1.24), one of them with a subtest per conformance
fixture. Zero external dependencies — pure Go stdlib
(`crypto/ed25519`, `crypto/sha256`).

Built for cloud / SRE / regulator tooling where Go is the lingua
franca and pulling in a Node toolchain just to verify a receipt is
absurd.

## Install

Once this module is on the `main` branch of the public repository:

```bash
go get github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go@latest
```

Until then, use a clone: run the tests in this folder with
`go test ./...`, or point your own module at the clone with
`go mod edit -replace github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go=/path/to/verifiable-receipts/packages/verifiable-receipts-go`
and then `go mod tidy`.

## Quick start — verify a VAOS 2.0 receipt

```go
package main

import (
    "encoding/json"
    "fmt"
    "os"

    vaos "github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go"
)

func main() {
    pemBytes, _ := os.ReadFile("./ed25519.pem")
    pubKey, _ := vaos.LoadEd25519PublicKeyFromPEM(pemBytes)

    // Unmarshal the whole receipt: canonical, contentHash and signature
    // fill their fields, and every other field lands in Envelope.
    data, _ := os.ReadFile("./receipt.json")
    var receipt vaos.Receipt
    if err := json.Unmarshal(data, &receipt); err != nil {
        panic(err)
    }

    result := vaos.VerifyV2Receipt(receipt, pubKey)
    fmt.Println(result.OK)      // true | false
    fmt.Println(result.Reason)  // "" | "signature does not verify under the supplied public key" | ...
}
```

`VerifyV2Receipt` checks, in this order:

1. `Canonical` and `Signature` are non-empty, and `Signature` is `v2=`
   followed by standard base64.
2. If `ContentHash` is set, it equals the hex SHA-256 of `Canonical`
   (the `sha256:` prefix is optional).
3. The Ed25519 signature verifies over the bytes of `Canonical`, exactly
   as given.
4. `Canonical` parses as a JSON object.
5. Every field in `Envelope` is in that object with an equal JSON value
   (numbers by value, integers exactly, objects regardless of key
   order). A field that disagrees, such as `"overall": "fail"` beside a
   canonical that says `"pass"`, or that the canonical does not contain,
   fails the check.

It does not re-derive `Canonical` from the other fields, so it accepts
receipts whose canonical uses another key order. A `Receipt` built by
hand without `Envelope` has no envelope fields to check: unmarshal the
receipt's JSON to check them.

`VerifyGuardianAttestation` makes the same checks on an attestation from
the TypeScript `runGuardian`, except for the fields its canonical does
not sign: it skips `totalMs`, compares each rule in `rules` as
`{ruleId, verdict, reason}` (a missing `reason` reads as null) in any
order, and skips each rule's `durationMs` and `evidence`. No signature
covers those skipped fields.

## Quick start — verify a transparency-log inclusion proof

```go
proof := vaos.InclusionProof{
    LeafIndex: 42,
    TreeSize:  100,
    AuditPath: []string{"aa11...", "bb22...", "cc33..."},
}

ok := vaos.VerifyInclusionProof(proof, leafHashHex, rootHashHex)
fmt.Println(ok) // true if leaf provably appears in the tree
```

## What this package is NOT

- **Not an issuer.** The TypeScript package
  (`@sovereign-matrix/verifiable-receipts`, including its
  `verifiable-receipts-sign` CLI) and the Python package
  (`sign_v2_receipt`) sign receipts; this module verifies what either
  signs. The round trip in
  [`../verifiable-receipts/conformance/roundtrip/`](../verifiable-receipts/conformance/roundtrip)
  checks that in CI.
- **Not a ML-DSA-65 verifier in v0.1.** Post-quantum verification
  requires a non-stdlib dependency (`cloudflare/circl` ships Go-native
  Dilithium); that lands in v0.2.

## License

Apache 2.0 © Sovereign Matrix; see [LICENSE](./LICENSE).

Bug in verification math? Report to `sovereign.systems007@gmail.com`
before public disclosure.
