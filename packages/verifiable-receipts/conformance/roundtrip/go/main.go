// Command roundtrip verifies a receipt or Guardian attestation with the
// Go verifier in packages/verifiable-receipts-go (wired in by go.mod's
// replace directive).
//
// Usage: go run . <ed25519-public.pem> <receipt|guardian> <file.json>
// Prints "ok" and exits 0, or prints "rejected: <reason>" and exits 1.
package main

import (
	"fmt"
	"os"

	vaos "github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go"
)

func main() {
	if len(os.Args) != 4 || (os.Args[2] != "receipt" && os.Args[2] != "guardian") {
		fmt.Fprintln(os.Stderr, "usage: go run . <ed25519-public.pem> <receipt|guardian> <file.json>")
		os.Exit(2)
	}
	pemBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	pub, err := vaos.LoadEd25519PublicKeyFromPEM(pemBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	receipt, err := vaos.ParseReceipt(data)
	if err != nil {
		fmt.Println("rejected:", err)
		os.Exit(1)
	}

	var result vaos.VerifyResult
	if os.Args[2] == "receipt" {
		result = vaos.VerifyV2Receipt(receipt, pub)
	} else {
		result = vaos.VerifyGuardianAttestation(receipt, pub)
	}
	if !result.OK {
		fmt.Println("rejected:", result.Reason)
		os.Exit(1)
	}
	fmt.Println("ok")
}
