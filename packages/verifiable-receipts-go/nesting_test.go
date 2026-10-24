package vaos

import (
	"encoding/json"
	"strings"
	"testing"
)

// VAOS 2.0 section 7.2: a receipt or a canonical nested deeper than 64 is
// rejected with a verdict; nothing deeper is decoded or compared.

func nestedText(levels int) string {
	return strings.Repeat("[", levels) + strings.Repeat("]", levels)
}

// deepReceipt is a receipt signed over canonical, with the field d set to
// the raw JSON value field (no field when it is empty).
func deepReceipt(t *testing.T, canonical, field string) (Receipt, VerifyResult) {
	t.Helper()
	pub, priv, _ := makeKeyPair(t)
	r := Receipt{Canonical: canonical, Signature: signV2(priv, canonical)}
	if field != "" {
		r.Envelope = map[string]json.RawMessage{"d": json.RawMessage(field)}
	}
	return r, VerifyV2Receipt(r, pub)
}

func TestNesting_AcceptsExactly64Deep(t *testing.T) {
	// The canonical's object and the receipt object are one level each;
	// the field d adds 63 more to each.
	if _, got := deepReceipt(t, `{"d":`+nestedText(63)+`}`, nestedText(63)); !got.OK {
		t.Fatalf("expected ok at depth 64, got %+v", got)
	}
}

func TestNesting_RejectsAReceipt65DeepFirst(t *testing.T) {
	_, got := deepReceipt(t, `{"a":1}`, nestedText(64))
	if got.OK || got.Reason != "receipt nesting deeper than 64" {
		t.Fatalf("got %+v", got)
	}
}

func TestNesting_RejectsACanonical65DeepValidJSONOrNot(t *testing.T) {
	for _, canonical := range []string{
		`{"d":` + nestedText(64) + `}`,
		`{"d":` + strings.Repeat("[", 64),
		`x` + strings.Repeat("{", 65),
	} {
		_, got := deepReceipt(t, canonical, "")
		if got.OK || got.Reason != "canonical nesting deeper than 64" {
			t.Fatalf("%.8s: got %+v", canonical, got)
		}
	}
}

func TestNesting_DoesNotCountBracketsInsideStrings(t *testing.T) {
	canonical := `{"s":"` + strings.Repeat("[", 100) + `\\\"` + strings.Repeat("{", 100) + `"}`
	if _, got := deepReceipt(t, canonical, ""); !got.OK {
		t.Fatalf("got %+v", got)
	}
}

func TestNesting_ReturnsAVerdictAtDepth5000And20000(t *testing.T) {
	for _, depth := range []int{5000, 20000} {
		canonical := `{"d":` + nestedText(depth) + `}`
		r, got := deepReceipt(t, canonical, nestedText(depth))
		if got.OK || got.Reason != "receipt nesting deeper than 64" {
			t.Fatalf("depth %d, deep field: got %+v", depth, got)
		}
		pub, priv, _ := makeKeyPair(t)
		r.Signature = signV2(priv, canonical)
		r.Envelope = map[string]json.RawMessage{
			"rules": json.RawMessage(`[{"ruleId":"r","verdict":"pass","reason":` + nestedText(depth) + `}]`),
		}
		if got := VerifyGuardianAttestation(r, pub); got.OK || got.Reason != "receipt nesting deeper than 64" {
			t.Fatalf("depth %d, Guardian: got %+v", depth, got)
		}
		r.Envelope = nil
		if got := VerifyV2Receipt(r, pub); got.OK || got.Reason != "canonical nesting deeper than 64" {
			t.Fatalf("depth %d, deep canonical: got %+v", depth, got)
		}
	}
}
