// Command differential judges every case in cases.jsonl with the Go
// verifiers in packages/verifiable-receipts-go (wired in by go.mod's
// replace directive).
//
// Usage: go run . <public.pem> <cases.jsonl> <out.jsonl>
// Writes one {"id", "ok"} line per case; "threw" records a panic, which
// the verifiers must never raise.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"os"
	"strings"

	vaos "github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go"
)

type testCase struct {
	ID   int    `json:"id"`
	Kind string `json:"kind"`
	Raw  string `json:"raw"`
	// PEM is an Ed25519 edge case's own key, used instead of public.pem.
	PEM string `json:"pem,omitempty"`
}

type result struct {
	ID     int     `json:"id"`
	OK     bool    `json:"ok"`
	Reason *string `json:"reason"`
	Threw  string  `json:"threw,omitempty"`
}

// parseReason is the reason for a receipt that ParseReceipt refuses: the
// verifiers' own reason for a receipt nested too deep, or "parse failed".
func parseReason(err error) string {
	if msg := strings.TrimPrefix(err.Error(), "vaos: "); msg == "receipt nesting deeper than 64" {
		return msg
	}
	return "parse failed"
}

// proofJSON decodes the way a careful caller would: pointers so a missing
// or null field is refused rather than read as zero, and indexes kept raw
// so count can take 284.0 (the same number as 284) and refuse "284".
type proofJSON struct {
	LeafHashHex *string          `json:"leafHashHex"`
	LeafIndex   *json.RawMessage `json:"leafIndex"`
	TreeSize    *json.RawMessage `json:"treeSize"`
	AuditPath   *[]string        `json:"auditPath"`
	RootHashHex *string          `json:"rootHashHex"`
}

// count reads a JSON number token as an integer value that fits in an
// int, or fails (a string, bool or null token is not a number).
func count(raw *json.RawMessage) (int, bool) {
	if raw == nil || len(*raw) == 0 || ((*raw)[0] != '-' && ((*raw)[0] < '0' || (*raw)[0] > '9')) {
		return 0, false
	}
	n := json.Number(*raw)
	if v, err := n.Int64(); err == nil {
		return int(v), true
	}
	f, err := n.Float64()
	if err != nil || f != math.Trunc(f) || math.Abs(f) >= 1<<62 {
		return 0, false
	}
	return int(f), true
}

func judge(pub []byte, c testCase) (r result) {
	r.ID = c.ID
	defer func() {
		if p := recover(); p != nil {
			r.OK, r.Threw = false, fmt.Sprint(p)
		}
	}()
	if c.PEM != "" {
		// Parsed without LoadEd25519PublicKeyFromPEM, which refuses weak
		// keys, so that the verifier gives the reason, as in the other
		// runners.
		block, _ := pem.Decode([]byte(c.PEM))
		if block == nil {
			r.Threw = "key: no PEM block"
			return r
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		edKey, ok := key.(ed25519.PublicKey)
		if err != nil || !ok {
			r.Threw = fmt.Sprint("key: ", err)
			return r
		}
		pub = edKey
	}
	if c.Kind == "receipt" || c.Kind == "guardian" {
		receipt, err := vaos.ParseReceipt([]byte(c.Raw))
		if err != nil {
			reason := parseReason(err)
			r.Reason = &reason
			return r
		}
		verify := vaos.VerifyV2Receipt
		if c.Kind == "guardian" {
			verify = vaos.VerifyGuardianAttestation
		}
		v := verify(receipt, pub)
		r.OK = v.OK
		if !v.OK {
			r.Reason = &v.Reason
		}
		return r
	}
	var p proofJSON
	if json.Unmarshal([]byte(c.Raw), &p) != nil || p.LeafHashHex == nil || p.LeafIndex == nil ||
		p.TreeSize == nil || p.AuditPath == nil || p.RootHashHex == nil {
		return r
	}
	idx, okIdx := count(p.LeafIndex)
	size, okSize := count(p.TreeSize)
	if !okIdx || !okSize {
		return r
	}
	proof := vaos.InclusionProof{LeafIndex: idx, TreeSize: size, AuditPath: *p.AuditPath}
	r.OK = vaos.VerifyInclusionProof(proof, *p.LeafHashHex, *p.RootHashHex)
	return r
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: go run . <public.pem> <cases.jsonl> <out.jsonl>")
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
	in, err := os.Open(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	defer in.Close()
	out, err := os.Create(os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	w := bufio.NewWriter(out)
	enc := json.NewEncoder(w)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var c testCase
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			fmt.Fprintln(os.Stderr, "error: bad case line:", err)
			os.Exit(2)
		}
		if err := enc.Encode(judge(pub, c)); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if err := w.Flush(); err != nil || out.Close() != nil {
		fmt.Fprintln(os.Stderr, "error: writing results")
		os.Exit(2)
	}
}
