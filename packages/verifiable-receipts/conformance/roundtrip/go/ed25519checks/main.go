// Command ed25519checks runs the Ed25519 fixtures through the Go
// pre-checks in packages/verifiable-receipts-go.
//
// Usage: go run ./ed25519checks <fixtures-dir>
// For each fixtures/ed25519-*.json, in name order, prints one line:
// "<name>\t<key reason>\t<signature reason>", with "none" for no
// problem, from Ed25519PublicKeyProblem and Ed25519SignatureProblem. The
// round trip checks that Python and node print the same lines.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	vaos "github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go"
)

type fixture struct {
	Ed25519 *struct {
		PublicKey string `json:"publicKey"`
		Signature string `json:"signature"`
	} `json:"ed25519"`
	PublicKeyPem string `json:"publicKeyPem"`
	Receipt      struct {
		Signature string `json:"signature"`
	} `json:"receipt"`
}

func keyAndSignature(path string) (pub, sig []byte, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, err
	}
	if f.Ed25519 != nil {
		if pub, err = hex.DecodeString(f.Ed25519.PublicKey); err != nil {
			return nil, nil, err
		}
		sig, err = hex.DecodeString(f.Ed25519.Signature)
		return pub, sig, err
	}
	block, _ := pem.Decode([]byte(f.PublicKeyPem))
	if block == nil || len(block.Bytes) < 32 {
		return nil, nil, errors.New("no public key")
	}
	pub = block.Bytes[len(block.Bytes)-32:] // SPKI: a 12-byte prefix, then the key
	sig, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(f.Receipt.Signature, "v2="))
	return pub, sig, err
}

func orNone(reason string) string {
	if reason == "" {
		return "none"
	}
	return reason
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./ed25519checks <fixtures-dir>")
		os.Exit(2)
	}
	paths, err := filepath.Glob(filepath.Join(os.Args[1], "ed25519-*.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	sort.Strings(paths)
	for _, path := range paths {
		pub, sig, err := keyAndSignature(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", path, err)
			os.Exit(2)
		}
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		fmt.Printf("%s\t%s\t%s\n", name, orNone(vaos.Ed25519PublicKeyProblem(pub)), orNone(vaos.Ed25519SignatureProblem(sig)))
	}
}
