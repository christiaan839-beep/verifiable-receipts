# sovereign-matrix verifiable-receipts (Go)

**Go verifier for VAOS receipts** — the Go counterpart to
[`@sovereignos/verifiable-receipts`](../verifiable-receipts)
(TypeScript) and
[`sovereign-matrix-verifiable-receipts`](../verifiable-receipts-py)
(Python). The TypeScript and Python packages are not on npm or PyPI yet.

Verify Ed25519-signed receipts (VAOS 2.0), check Guardian attestation
envelopes, and walk RFC 9162 transparency-log inclusion proofs from
any Go process. Measured on 23 October 2026: 36 tests passed
(`go test ./...`, Go 1.24), one of them with a subtest per conformance
fixture. Standard library only (`crypto/ed25519`, `crypto/sha256`).

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

0. The receipt nests at most 64 deep (VAOS 2.0 §7.2): the receipt is one
   level, and each array or object in an `Envelope` field one more.
1. `Canonical` and `Signature` are non-empty, and `Signature` is `v2=`
   followed by canonical standard base64 (padding bits zero). The public
   key is a canonical encoding of a point of order L: not of small or
   mixed order, not off the curve (VAOS 2.0 §7.3, the strict profile);
   `LoadEd25519PublicKeyFromPEM` refuses such keys too.
2. If the receipt has a contentHash, it equals the hex SHA-256 of
   `Canonical` (the `sha256:` prefix is optional). It has one when the
   receipt's JSON has a string `contentHash`, even `""`, or when
   `ContentHash` is non-empty; an absent or `null` `contentHash` is not
   checked.
3. The Ed25519 signature verifies over the bytes of `Canonical`, exactly
   as given. Before `crypto/ed25519` sees it, its R must be a canonical
   encoding of a point of order L (not of small order, the identity
   included, nor of mixed order) and its S below L: so this verifier,
   the TypeScript one on Node.js 22 or 24 and the Python one give the
   same verdict on every signature. `VerifyEd25519(pub, message, sig)`
   makes the same checks on one raw signature, and
   `Ed25519PublicKeyProblem(pub)` and `Ed25519SignatureProblem(sig)`
   make the key check and the R and S check on their own, returning the
   reason or `""` (the same reasons as TypeScript and Python). The
   checks on R and S depend only on the signature, so a caller that
   tries one signature under several keys can make them once; a key's
   answer is cached.
4. `Canonical` nests at most 64 deep, counted on its text before it is
   decoded, and parses as a JSON object.
5. Every field in `Envelope` is in that object with an equal JSON value
   (numbers by value, objects regardless of key order; a number of
   magnitude 2^53 or more equals nothing, as in the TypeScript and
   Python verifiers, since JavaScript cannot tell 2^53 from 2^53 + 1).
   A field that disagrees, such as `"overall": "fail"` beside a
   canonical that says `"pass"`, or that the canonical does not contain,
   fails the check.

It does not re-derive `Canonical` from the other fields, so it accepts
receipts whose canonical uses another key order. A `Receipt` built by
hand without `Envelope` has no envelope fields to check: unmarshal the
receipt's JSON to check them. `ParseReceipt` and `UnmarshalJSON` refuse a
receipt nested deeper than 64 with the error `vaos: receipt nesting
deeper than 64`; `ParseReceipt` counts the depth before `encoding/json`
reads the text, so the error is the same at any depth.

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
  (`@sovereignos/verifiable-receipts`, including its
  `verifiable-receipts-sign` CLI) and the Python package
  (`sign_v2_receipt`) sign receipts; this module verifies what either
  signs. The round trip in
  [`../verifiable-receipts/conformance/roundtrip/`](../verifiable-receipts/conformance/roundtrip)
  checks that in CI.
- **Not an ML-DSA-65 verifier.** It does not check `v3=` signatures;
  that would need a dependency outside the standard library.

## License

Apache-2.0; see [LICENSE](./LICENSE). Report a suspected vulnerability
privately, as the repository's [SECURITY.md](../../SECURITY.md) says.
