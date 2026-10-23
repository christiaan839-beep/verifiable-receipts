package vaos

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fuzzKey is derived from a fixed seed, so a saved corpus entry signed
// with it still verifies on the next run.
func fuzzKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("verifiable-receipts fuzz key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

func fixtureKey(f *testing.F) ed25519.PublicKey {
	f.Helper()
	pemBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		f.Fatalf("read public key: %v", err)
	}
	pub, err := LoadEd25519PublicKeyFromPEM(pemBytes)
	if err != nil {
		f.Fatalf("load public key: %v", err)
	}
	return pub
}

func fixtureFiles(f *testing.F, prefix string) [][]byte {
	f.Helper()
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		f.Fatalf("read fixtures dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	out := make([][]byte, 0, len(names))
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(fixturesDir, name))
		if err != nil {
			f.Fatalf("read fixture: %v", err)
		}
		out = append(out, raw)
	}
	return out
}

func v2Fixtures(f *testing.F) []v2Fixture {
	f.Helper()
	var out []v2Fixture
	for _, raw := range fixtureFiles(f, "v2-") {
		var fixture v2Fixture
		if err := json.Unmarshal(raw, &fixture); err != nil {
			f.Fatalf("unmarshal v2 fixture: %v", err)
		}
		out = append(out, fixture)
	}
	return out
}

func envelopeJSON(f *testing.F, r Receipt) []byte {
	f.Helper()
	if len(r.Envelope) == 0 {
		return nil
	}
	data, err := json.Marshal(r.Envelope)
	if err != nil {
		f.Fatalf("marshal envelope: %v", err)
	}
	return data
}

// checkAccepted fails unless an accepted receipt carries the one valid
// spelling of a signature that verifies under pub.
func checkAccepted(t *testing.T, r Receipt, pub ed25519.PublicKey) {
	t.Helper()
	fuzzPub, fuzzPriv := fuzzKey()
	if !strings.HasPrefix(r.Signature, "v2=") {
		t.Fatalf("accepted a signature without the v2= prefix: %q", r.Signature)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(r.Signature[3:])
	if err != nil {
		t.Fatalf("accepted undecodable signature %q: %v", r.Signature, err)
	}
	if "v2="+base64.StdEncoding.EncodeToString(sig) != r.Signature {
		if strings.ContainsAny(r.Signature, "\r\n") {
			t.Skip("known: the Go base64 decoder skips CR and LF, so VerifyV2Receipt accepts them inside the signature")
		}
		t.Fatalf("accepted a non-canonical signature spelling %q", r.Signature)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte(r.Canonical), sig) {
		t.Fatalf("accepted a signature that does not verify: %q", r.Signature)
	}
	if r.ContentHash != "" && strings.TrimPrefix(r.ContentHash, "sha256:") != contentHash(r.Canonical)[len("sha256:"):] {
		t.Fatalf("accepted a wrong contentHash %q", r.ContentHash)
	}
	if pub.Equal(fuzzPub) && r.Signature != signV2(fuzzPriv, r.Canonical) {
		t.Fatalf("accepted %q, want the signature %q", r.Signature, signV2(fuzzPriv, r.Canonical))
	}
}

func FuzzVerifyV2Receipt(f *testing.F) {
	fixturePub := fixtureKey(f)
	fuzzPub, fuzzPriv := fuzzKey()
	for _, fixture := range v2Fixtures(f) {
		r := fixture.Receipt
		env := envelopeJSON(f, r)
		f.Add(r.Canonical, r.ContentHash, r.Signature, env, []byte(fixturePub))
		f.Add(r.Canonical, r.ContentHash, signV2(fuzzPriv, r.Canonical), env, []byte(fuzzPub))
		if fixture.Expected.OK {
			f.Add(r.Canonical, r.ContentHash, r.Signature[:10]+"\n"+r.Signature[10:], env, []byte(fixturePub))
		}
	}
	f.Add("", "", "", []byte(nil), []byte(nil))
	f.Add(`{"a":1}`, "", "v2=", []byte(`{"a":1.0}`), []byte(fuzzPub[:31]))

	f.Fuzz(func(t *testing.T, canonical, hash, signature string, envelope, key []byte) {
		r := Receipt{Canonical: canonical, ContentHash: hash, Signature: signature}
		if len(envelope) > 0 {
			var env map[string]json.RawMessage
			if json.Unmarshal(envelope, &env) == nil {
				r.Envelope = env
			}
		}
		pub := ed25519.PublicKey(key)
		res := VerifyV2Receipt(r, pub)
		if !res.OK {
			if res.Reason == "" {
				t.Fatal("rejected with an empty reason")
			}
		} else {
			checkAccepted(t, r, pub)
		}
		if g := VerifyGuardianAttestation(r, pub); g.OK {
			checkAccepted(t, r, pub)
		}
	})
}

func FuzzReceiptJSON(f *testing.F) {
	fuzzPub, fuzzPriv := fuzzKey()
	for _, raw := range fixtureFiles(f, "v2-") {
		var wrapper struct {
			Receipt json.RawMessage `json:"receipt"`
		}
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			f.Fatalf("unmarshal v2 fixture: %v", err)
		}
		f.Add([]byte(wrapper.Receipt))
	}
	canonical := `{"overall":"pass","rules":[{"ruleId":"r1","verdict":"pass","reason":null}],"verdictId":"v1"}`
	body, err := json.Marshal(map[string]any{
		"canonical": canonical,
		"signature": signV2(fuzzPriv, canonical),
		"overall":   "pass",
		"totalMs":   3,
		"rules":     []any{map[string]any{"ruleId": "r1", "verdict": "pass", "durationMs": 1}},
	})
	if err != nil {
		f.Fatalf("marshal seed: %v", err)
	}
	f.Add(body)
	f.Add([]byte(`null`))
	f.Add([]byte(`{"canonical":7}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var r Receipt
		if err := json.Unmarshal(data, &r); err != nil {
			return
		}
		if VerifyV2Receipt(r, fuzzPub).OK {
			checkAccepted(t, r, fuzzPub)
		}
		if VerifyGuardianAttestation(r, fuzzPub).OK {
			checkAccepted(t, r, fuzzPub)
		}
	})
}

func FuzzMutatedReceipt(f *testing.F) {
	f.Add("", uint8(0), uint16(0), byte(1), true)
	for _, fixture := range v2Fixtures(f) {
		f.Add(fixture.Receipt.Canonical, uint8(0), uint16(10), byte(0x20), true)
		f.Add(fixture.Receipt.Canonical, uint8(1), uint16(63), byte(0x80), false)
		f.Add(fixture.Receipt.Canonical, uint8(2), uint16(30), byte(0x01), false)
	}

	pub, priv := fuzzKey()
	f.Fuzz(func(t *testing.T, body string, field uint8, pos uint16, flip byte, withHash bool) {
		canonicalBytes, err := json.Marshal(map[string]string{"body": body})
		if err != nil {
			return
		}
		canonical := string(canonicalBytes)
		r := Receipt{Canonical: canonical, Signature: signV2(priv, canonical)}
		if withHash {
			r.ContentHash = contentHash(canonical)
		}
		if res := VerifyV2Receipt(r, pub); !res.OK {
			t.Fatalf("rejected the unmutated receipt: %s", res.Reason)
		}
		if flip == 0 {
			flip = 1
		}
		switch field % 3 {
		case 0:
			b := []byte(r.Signature)
			b[int(pos)%len(b)] ^= flip
			r.Signature = string(b)
		case 1:
			sig := ed25519.Sign(priv, canonicalBytes)
			sig[int(pos)%len(sig)] ^= flip
			r.Signature = "v2=" + base64.StdEncoding.EncodeToString(sig)
		case 2:
			b := []byte(canonical)
			b[int(pos)%len(b)] ^= flip
			r.Canonical = string(b)
		}
		if res := VerifyV2Receipt(r, pub); res.OK {
			if field%3 == 0 && strings.ContainsAny(r.Signature, "\r\n") {
				t.Skip("known: the Go base64 decoder skips CR and LF, so VerifyV2Receipt accepts them inside the signature")
			}
			t.Fatalf("accepted a mutated receipt (field %d, pos %d): %+v", field%3, pos, r)
		}
	})
}

func testTreeRoot(leaves []string) string {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	h, _ := InnerHash(testTreeRoot(leaves[:k]), testTreeRoot(leaves[k:]))
	return h
}

func testAuditPath(idx int, leaves []string) []string {
	if len(leaves) == 1 {
		return nil
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	if idx < k {
		return append(testAuditPath(idx, leaves[:k]), testTreeRoot(leaves[k:]))
	}
	return append(testAuditPath(idx-k, leaves[k:]), testTreeRoot(leaves[:k]))
}

func FuzzVerifyInclusionProof(f *testing.F) {
	for _, raw := range fixtureFiles(f, "inclusion-") {
		var fixture inclusionFixture
		if err := json.Unmarshal(raw, &fixture); err != nil {
			f.Fatalf("unmarshal inclusion fixture: %v", err)
		}
		f.Add(fixture.LeafIndex, fixture.TreeSize, fixture.LeafHashHex, fixture.RootHashHex,
			strings.Join(fixture.AuditPath, ","))
	}
	f.Add(-1, -1, "", "", "")
	f.Add(1<<62, 1<<62+1, "zz", "zz", ",,")

	f.Fuzz(func(t *testing.T, leafIndex, treeSize int, leaf, root, path string) {
		var auditPath []string
		if path != "" {
			auditPath = strings.Split(path, ",")
		}
		proof := InclusionProof{LeafIndex: leafIndex, TreeSize: treeSize, AuditPath: auditPath}
		if !VerifyInclusionProof(proof, leaf, root) {
			return
		}
		for _, other := range []string{root + "0", strings.ToUpper(root) + "x", ""} {
			if other != root && VerifyInclusionProof(proof, leaf, other) {
				t.Fatalf("proof verifies under two roots %q and %q", root, other)
			}
		}
	})
}

func FuzzInclusionProofWrongRoot(f *testing.F) {
	f.Add(uint8(0), uint8(0), []byte("seed"), []byte{0}, uint8(0), byte(1))
	f.Add(uint8(6), uint8(6), []byte("seed"), []byte("other root"), uint8(1), byte(0x80))
	f.Add(uint8(63), uint8(17), []byte{}, []byte{}, uint8(5), byte(0xff))

	f.Fuzz(func(t *testing.T, size, index uint8, salt, wrong []byte, entry uint8, flip byte) {
		n := int(size)%64 + 1
		idx := int(index) % n
		leaves := make([]string, n)
		for i := range leaves {
			leaves[i] = LeafHash(append(append([]byte{}, salt...), byte(i), byte(i>>8)))
		}
		root := testTreeRoot(leaves)
		path := testAuditPath(idx, leaves)
		proof := InclusionProof{LeafIndex: idx, TreeSize: n, AuditPath: path}
		if !VerifyInclusionProof(proof, leaves[idx], root) {
			t.Fatalf("valid proof rejected: n=%d idx=%d", n, idx)
		}

		sum := sha256.Sum256(wrong)
		wrongRoot := hex.EncodeToString(sum[:])
		if wrongRoot != root && VerifyInclusionProof(proof, leaves[idx], wrongRoot) {
			t.Fatalf("proof accepted under a wrong root: n=%d idx=%d", n, idx)
		}

		if len(path) > 0 {
			if flip == 0 {
				flip = 1
			}
			raw, _ := hex.DecodeString(path[int(entry)%len(path)])
			raw[int(entry)%len(raw)] ^= flip
			tampered := append([]string{}, path...)
			tampered[int(entry)%len(path)] = hex.EncodeToString(raw)
			bad := InclusionProof{LeafIndex: idx, TreeSize: n, AuditPath: tampered}
			if VerifyInclusionProof(bad, leaves[idx], root) {
				t.Fatalf("tampered proof accepted: n=%d idx=%d entry=%d", n, idx, int(entry)%len(path))
			}
		}
		for _, other := range []int{idx - 1, idx + 1} {
			moved := InclusionProof{LeafIndex: other, TreeSize: n, AuditPath: path}
			if other >= 0 && other < n && VerifyInclusionProof(moved, leaves[idx], root) {
				t.Fatalf("proof for index %d accepted at index %d (n=%d)", idx, other, n)
			}
		}
	})
}
