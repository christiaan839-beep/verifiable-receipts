package vaos

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Envelope consistency: every receipt field beside canonical,
// contentHash and signature must equal the same field in the signed
// canonical. Keys are generated per test; none is stored.

const envelopeCanonical = `{"agentSlug":"loan-underwriter","overall":"pass",` +
	`"rules":[{"ruleId":"r1","verdict":"pass","durationMs":2}],"n":1,` +
	`"big":9007199254740993}`

// signedReceiptJSON returns the JSON of a receipt that carries
// envelopeCanonical, its hash and signature, and the given extra fields.
func signedReceiptJSON(t *testing.T, priv ed25519.PrivateKey, canonical string, extra string) []byte {
	t.Helper()
	parts := []string{
		`"canonical":` + mustQuote(t, canonical),
		`"contentHash":"` + contentHash(canonical) + `"`,
		`"signature":"` + signV2(priv, canonical) + `"`,
	}
	if extra != "" {
		parts = append(parts, extra)
	}
	return []byte("{" + strings.Join(parts, ",") + "}")
}

func mustQuote(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	return string(b)
}

func verifyJSON(t *testing.T, pub ed25519.PublicKey, data []byte) VerifyResult {
	t.Helper()
	var r Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	return VerifyV2Receipt(r, pub)
}

func TestReceipt_UnmarshalJSONFillsEnvelope(t *testing.T) {
	var r Receipt
	data := []byte(`{"canonical":"{}","contentHash":"sha256:00","signature":"v2=AA==","overall":"pass","rules":[]}`)
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Canonical != "{}" || r.ContentHash != "sha256:00" || r.Signature != "v2=AA==" {
		t.Fatalf("known fields not filled: %+v", r)
	}
	if len(r.Envelope) != 2 || string(r.Envelope["overall"]) != `"pass"` || string(r.Envelope["rules"]) != `[]` {
		t.Fatalf("unexpected envelope: %v", r.Envelope)
	}
}

func TestReceipt_UnmarshalJSONRejectsBadShapes(t *testing.T) {
	for _, data := range []string{`null`, `[]`} {
		var r Receipt
		if err := json.Unmarshal([]byte(data), &r); err == nil {
			t.Fatalf("expected an error for %s", data)
		}
	}
}

// A canonical, signature or contentHash that is not a string parses, and
// the verifier rejects it with the reason the TypeScript and Python
// verifiers give, at the same step.
func TestReceipt_NonStringFieldsGetTheSharedReasons(t *testing.T) {
	pub, priv, _ := makeKeyPair(t)
	sig := signV2(priv, "{}")
	for data, reason := range map[string]string{
		`{"canonical":5,"signature":"` + sig + `"}`:                    "missing canonical projection",
		`{"canonical":"{}","signature":{}}`:                            "missing signature",
		`{"canonical":"{}","signature":"` + sig + `","contentHash":0}`: "contentHash must be a string",
		`{"canonical":"{}","signature":"v2=!","contentHash":0}`:        "signature base64 invalid",
	} {
		r, err := ParseReceipt([]byte(data))
		if err != nil {
			t.Fatalf("%s: %v", data, err)
		}
		if got := VerifyV2Receipt(r, pub); got.OK || got.Reason != reason {
			t.Fatalf("%s: got %+v, want %q", data, got, reason)
		}
	}
}

func TestEnvelope_AcceptsFieldsThatAgreeInAnyKeyOrder(t *testing.T) {
	pub, priv, _ := makeKeyPair(t)
	data := signedReceiptJSON(t, priv, envelopeCanonical,
		`"overall":"pass","rules":[{"durationMs":2,"verdict":"pass","ruleId":"r1"}],"n":1.0`)
	if result := verifyJSON(t, pub, data); !result.OK {
		t.Fatalf("expected OK, got %q", result.Reason)
	}
}

func TestEnvelope_RejectsAFieldThatDisagrees(t *testing.T) {
	pub, priv, _ := makeKeyPair(t)
	result := verifyJSON(t, pub, signedReceiptJSON(t, priv, envelopeCanonical, `"overall":"fail"`))
	if result.OK || result.Reason != `envelope field "overall" disagrees with the signed canonical` {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestEnvelope_RejectsANestedDifference(t *testing.T) {
	pub, priv, _ := makeKeyPair(t)
	result := verifyJSON(t, pub, signedReceiptJSON(t, priv, envelopeCanonical,
		`"rules":[{"ruleId":"r1","verdict":"block","durationMs":2}]`))
	if result.OK || !strings.Contains(result.Reason, `"rules" disagrees`) {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestEnvelope_RejectsAFieldAbsentFromTheCanonical(t *testing.T) {
	pub, priv, _ := makeKeyPair(t)
	result := verifyJSON(t, pub, signedReceiptJSON(t, priv, envelopeCanonical, `"approvedBy":"compliance"`))
	if result.OK || result.Reason != `envelope field "approvedBy" is not in the signed canonical` {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestEnvelope_ComparesNumbersByValue(t *testing.T) {
	pub, priv, _ := makeKeyPair(t)
	cases := []struct {
		extra string
		ok    bool
	}{
		{`"n":1e0`, true},
		{`"n":10e-1`, true},
		{`"n":2`, false},
		{`"n":true`, false},
		{`"n":"1"`, false},
		// A number of magnitude 2^53 or more matches nothing, not even
		// itself: a double cannot tell 2^53 from 2^53 + 1.
		{`"big":9007199254740992`, false},
		{`"big":9007199254740993`, false},
	}
	for _, c := range cases {
		result := verifyJSON(t, pub, signedReceiptJSON(t, priv, envelopeCanonical, c.extra))
		if result.OK != c.ok {
			t.Fatalf("%s: expected ok=%v, got %+v", c.extra, c.ok, result)
		}
	}
}

func TestEnvelope_RejectsASignedCanonicalThatIsNotAnObject(t *testing.T) {
	pub, priv, _ := makeKeyPair(t)
	canonical := `["not","an","object"]`
	r := Receipt{Canonical: canonical, Signature: signV2(priv, canonical)}
	if result := VerifyV2Receipt(r, pub); result.OK || result.Reason != "canonical is not a JSON object" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestEnvelope_RejectsASignedCanonicalThatIsNotJSON(t *testing.T) {
	pub, priv, _ := makeKeyPair(t)
	for _, canonical := range []string{"not json", `{"x":NaN}`, `{"x":1} trailing`, `{} {}`} {
		r := Receipt{Canonical: canonical, Signature: signV2(priv, canonical)}
		if result := VerifyV2Receipt(r, pub); result.OK || result.Reason != "canonical is not valid JSON" {
			t.Fatalf("%q: unexpected result: %+v", canonical, result)
		}
	}
}

func TestVerifyV2Receipt_DoesNotPanicOnAShortKey(t *testing.T) {
	_, priv, _ := makeKeyPair(t)
	canonical := `{"x":1}`
	r := Receipt{Canonical: canonical, Signature: signV2(priv, canonical)}
	if VerifyV2Receipt(r, ed25519.PublicKey{1, 2, 3}).OK {
		t.Fatal("expected a short key to fail")
	}
}

// The envelope runGuardian (TypeScript) returns: rules in evaluation
// order with the unsigned durationMs and evidence, plus totalMs. The
// canonical sorts the rules by ruleId and keeps ruleId, verdict, reason.
const guardianCanonical = `{"v":1,"type":"guardian-verdict","verdictId":"g_1","runId":"r1",` +
	`"agentSlug":"a","tokenId":"t","overall":"warn","rules":[` +
	`{"ruleId":"hipaa-no-mrn","verdict":"warn","reason":"MRN found"},` +
	`{"ruleId":"hipaa-no-raw-ssn","verdict":"pass","reason":null}],` +
	`"issuedAt":"2026-10-16T00:00:00.000Z"}`

func guardianJSON(t *testing.T, priv ed25519.PrivateKey, rules, overall, totalMs string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(guardianCanonical))
	return []byte(`{"verdictId":"g_1","overall":` + overall + `,"rules":` + rules +
		`,"totalMs":` + totalMs + `,"issuedAt":"2026-10-16T00:00:00.000Z",` +
		`"canonical":` + mustQuote(t, guardianCanonical) +
		`,"contentHash":"` + hex.EncodeToString(sum[:]) +
		`","signature":"` + signV2(priv, guardianCanonical) + `"}`)
}

const guardianRulesJSON = `[{"ruleId":"hipaa-no-raw-ssn","verdict":"pass","durationMs":0},` +
	`{"ruleId":"hipaa-no-mrn","verdict":"warn","reason":"MRN found","evidence":{"offset":4},"durationMs":1}]`

func verifyGuardianJSON(t *testing.T, pub ed25519.PublicKey, data []byte) VerifyResult {
	t.Helper()
	var r Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("unmarshal attestation: %v", err)
	}
	return VerifyGuardianAttestation(r, pub)
}

func TestVerifyGuardianAttestation_AcceptsARunGuardianEnvelope(t *testing.T) {
	pub, priv, _ := makeKeyPair(t)
	data := guardianJSON(t, priv, guardianRulesJSON, `"warn"`, "1")
	if result := verifyGuardianJSON(t, pub, data); !result.OK {
		t.Fatalf("expected OK, got %q", result.Reason)
	}
	// The generic check sees totalMs and the rules' extra fields.
	if verifyJSON(t, pub, data).OK {
		t.Fatal("expected VerifyV2Receipt to reject the unsigned Guardian fields")
	}
}

func TestVerifyGuardianAttestation_IgnoresTheUnsignedTimings(t *testing.T) {
	pub, priv, _ := makeKeyPair(t)
	rules := strings.Replace(guardianRulesJSON, `"durationMs":0`, `"durationMs":999`, 1)
	if result := verifyGuardianJSON(t, pub, guardianJSON(t, priv, rules, `"warn"`, "999")); !result.OK {
		t.Fatalf("expected OK, got %q", result.Reason)
	}
}

func TestVerifyGuardianAttestation_RejectsChangedContent(t *testing.T) {
	pub, priv, _ := makeKeyPair(t)
	cases := map[string][]byte{
		"changed verdict": guardianJSON(t, priv,
			strings.Replace(guardianRulesJSON, `"verdict":"warn"`, `"verdict":"pass"`, 1), `"warn"`, "1"),
		"dropped rule": guardianJSON(t, priv,
			`[{"ruleId":"hipaa-no-raw-ssn","verdict":"pass","durationMs":0}]`, `"warn"`, "1"),
		"changed overall": guardianJSON(t, priv, guardianRulesJSON, `"pass"`, "1"),
	}
	for name, data := range cases {
		if result := verifyGuardianJSON(t, pub, data); result.OK {
			t.Fatalf("%s: expected a rejection", name)
		}
	}
}
