package vaos

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Cross-language conformance harness — Go verifier side.
//
// Reads the JSON fixtures from
// ../verifiable-receipts/conformance/fixtures and asserts that the
// Go reference implementation agrees with the TypeScript canonical
// implementation on every fixture's expected outcome.
//
// Same corpus exercised by:
//   - TypeScript: packages/verifiable-receipts/conformance/conformance.test.ts
//   - Python:     packages/verifiable-receipts/conformance/conformance.py
//
// All three harnesses MUST produce identical pass/fail results per
// fixture. This is what makes the "three-language symmetric verifier"
// claim auditable.

const fixturesDir = "../verifiable-receipts/conformance/fixtures"
const publicKeyPath = "../verifiable-receipts/conformance/public-key.pem"

type v2Expected struct {
	OK             bool   `json:"ok"`
	ReasonContains string `json:"reasonContains,omitempty"`
}

// Receipt decodes through (*Receipt).UnmarshalJSON, so every field
// beside canonical, contentHash and signature lands in Envelope and is
// checked against the signed canonical.
type v2Fixture struct {
	Description string `json:"description"`
	// PublicKeyPem is a key fixture's own key, used instead of
	// public-key.pem. It is parsed without LoadEd25519PublicKeyFromPEM,
	// which refuses weak keys, so VerifyV2Receipt gives the reason.
	PublicKeyPem string     `json:"publicKeyPem,omitempty"`
	Receipt      Receipt    `json:"receipt"`
	Expected     v2Expected `json:"expected"`
}

type inclusionFixture struct {
	Description string   `json:"description"`
	LeafHashHex string   `json:"leafHashHex"`
	LeafIndex   int      `json:"leafIndex"`
	TreeSize    int      `json:"treeSize"`
	AuditPath   []string `json:"auditPath"`
	RootHashHex string   `json:"rootHashHex"`
	Expected    struct {
		OK bool `json:"ok"`
	} `json:"expected"`
}

func TestConformance_LoadsAtLeast10Fixtures(t *testing.T) {
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read fixtures dir: %v", err)
	}
	count := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			count++
		}
	}
	if count < 10 {
		t.Fatalf("expected at least 10 fixtures, got %d", count)
	}
}

func TestConformance_EveryFixtureMatchesExpected(t *testing.T) {
	pemBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	pub, err := LoadEd25519PublicKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("load public key: %v", err)
	}

	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read fixtures dir: %v", err)
	}

	// Stable order — same as the TS + Python harnesses.
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		name := name // capture for parallel safety
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(fixturesDir, name))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}

			// Discriminate v2 vs inclusion by presence of the "receipt"
			// key. We do a soft-peek by unmarshalling into a map first.
			var probe map[string]json.RawMessage
			if err := json.Unmarshal(raw, &probe); err != nil {
				t.Fatalf("unmarshal probe: %v", err)
			}

			if _, isEd25519 := probe["ed25519"]; isEd25519 {
				// One Ed25519 signature, as hex, checked with VerifyEd25519.
				var shape struct {
					Ed25519 struct {
						PublicKey string `json:"publicKey"`
						Message   string `json:"message"`
						Signature string `json:"signature"`
					} `json:"ed25519"`
					Expected v2Expected `json:"expected"`
				}
				if err := json.Unmarshal(raw, &shape); err != nil {
					t.Fatalf("unmarshal ed25519: %v", err)
				}
				pub, err1 := hex.DecodeString(shape.Ed25519.PublicKey)
				msg, err2 := hex.DecodeString(shape.Ed25519.Message)
				sig, err3 := hex.DecodeString(shape.Ed25519.Signature)
				if err := errors.Join(err1, err2, err3); err != nil {
					t.Fatalf("ed25519 hex: %v", err)
				}
				result := VerifyEd25519(pub, msg, sig)
				if result.OK != shape.Expected.OK || (!result.OK && shape.Expected.ReasonContains != "" &&
					!regexp.MustCompile("(?i)"+shape.Expected.ReasonContains).MatchString(result.Reason)) {
					t.Fatalf("%s: got %+v, want %+v", name, result, shape.Expected)
				}
				return
			}

			if text, isText := probe["receiptText"]; isText {
				// A receipt given as text, read with ParseReceipt, which
				// counts depth on the text; a refusal is a rejection.
				var shape struct {
					ReceiptText string     `json:"receiptText"`
					Expected    v2Expected `json:"expected"`
				}
				if err := json.Unmarshal(raw, &shape); err != nil || len(text) == 0 {
					t.Fatalf("unmarshal receiptText: %v", err)
				}
				var result VerifyResult
				if r, err := ParseReceipt([]byte(shape.ReceiptText)); err != nil {
					result = VerifyResult{OK: false, Reason: strings.TrimPrefix(err.Error(), "vaos: ")}
				} else {
					result = VerifyV2Receipt(r, pub)
				}
				if result.OK != shape.Expected.OK || (!result.OK && shape.Expected.ReasonContains != "" &&
					!regexp.MustCompile("(?i)"+shape.Expected.ReasonContains).MatchString(result.Reason)) {
					t.Fatalf("%s: got %+v, want %+v", name, result, shape.Expected)
				}
				return
			}

			if _, isV2 := probe["receipt"]; isV2 {
				var fixture v2Fixture
				var result VerifyResult
				if err := json.Unmarshal(raw, &fixture); errors.Is(err, errReceiptTooDeep) {
					// Parsing refuses a receipt nested deeper than 64 with
					// the verifiers' reason; read the expectation alone.
					var shape struct {
						Expected v2Expected `json:"expected"`
					}
					if json.Unmarshal(raw, &shape) != nil {
						t.Fatalf("unmarshal v2: %v", err)
					}
					fixture.Expected = shape.Expected
					result = VerifyResult{OK: false, Reason: strings.TrimPrefix(err.Error(), "vaos: ")}
				} else if err != nil {
					t.Fatalf("unmarshal v2: %v", err)
				} else if fixture.PublicKeyPem != "" {
					block, _ := pem.Decode([]byte(fixture.PublicKeyPem))
					if block == nil {
						t.Fatalf("publicKeyPem: no PEM block")
					}
					key, err := x509.ParsePKIXPublicKey(block.Bytes)
					if err != nil {
						t.Fatalf("publicKeyPem: %v", err)
					}
					result = VerifyV2Receipt(fixture.Receipt, key.(ed25519.PublicKey))
				} else {
					result = VerifyV2Receipt(fixture.Receipt, pub)
				}
				if result.OK != fixture.Expected.OK {
					t.Fatalf(
						"%s: expected ok=%v, got ok=%v reason=%q",
						name, fixture.Expected.OK, result.OK, result.Reason,
					)
				}
				if fixture.Expected.ReasonContains != "" && !result.OK {
					rx, err := regexp.Compile("(?i)" + fixture.Expected.ReasonContains)
					if err != nil {
						t.Fatalf("compile reason regex: %v", err)
					}
					if !rx.MatchString(result.Reason) {
						t.Fatalf(
							"%s: expected reason to match %q, got %q",
							name, fixture.Expected.ReasonContains, result.Reason,
						)
					}
				}
				return
			}

			if _, isInclusion := probe["leafHashHex"]; isInclusion {
				var fixture inclusionFixture
				// A proof that does not decode into InclusionProof (an index
				// of 1.5, say) is rejected before it reaches the verifier.
				var actual bool
				if err := json.Unmarshal(raw, &fixture); err != nil {
					var shape struct {
						Expected struct {
							OK bool `json:"ok"`
						} `json:"expected"`
					}
					if json.Unmarshal(raw, &shape) != nil {
						t.Fatalf("unmarshal inclusion: %v", err)
					}
					fixture.Expected.OK = shape.Expected.OK
				} else {
					proof := InclusionProof{
						LeafIndex: fixture.LeafIndex,
						TreeSize:  fixture.TreeSize,
						AuditPath: fixture.AuditPath,
					}
					actual = VerifyInclusionProof(proof, fixture.LeafHashHex, fixture.RootHashHex)
				}
				if actual != fixture.Expected.OK {
					t.Fatalf(
						"%s: expected ok=%v, got ok=%v",
						name, fixture.Expected.OK, actual,
					)
				}
				return
			}

			t.Fatalf("%s: unknown fixture shape (no 'receipt', 'receiptText', 'ed25519' or 'leafHashHex')", name)
		})
	}
}
