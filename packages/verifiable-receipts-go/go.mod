module github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go

go 1.22

// Pure-stdlib Ed25519 + RFC 9162 inclusion-proof verifier. Zero
// external dependencies. It verifies the signature over a receipt's
// canonical string as given and checks the receipt's other fields
// against it; it does not re-derive the canonical.
