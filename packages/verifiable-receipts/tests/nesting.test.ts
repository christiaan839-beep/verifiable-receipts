/**
 * The library's recursive paths and the nesting limit of VAOS 2.0 section 7.2:
 * the verifiers return a verdict on any depth, and the canonical JSON writer
 * refuses to write what a verifier would reject, rather than overflow the
 * stack.
 */
import { describe, it, expect } from "vitest";
import { canonicalJson } from "../src/canonical-json.js";
import { verifyGuardianAttestation, type GuardianAttestation } from "../src/guardian.js";
import { verifyManifest, type BundleManifest } from "../src/bundle.js";

/** A value `levels` arrays deep, built without recursion. */
function nested(levels: number): unknown {
  let value: unknown = [];
  for (let i = 1; i < levels; i++) value = [value];
  return value;
}

const attestation = (reason: unknown): GuardianAttestation =>
  ({
    verdictId: "v",
    overall: "pass",
    rules: [{ ruleId: "r", verdict: "pass", reason, durationMs: 0 }],
    totalMs: 0,
    issuedAt: "2026-10-24T00:00:00.000Z",
    canonical: '{"runId":"run","agentSlug":"agent"}',
    contentHash: "",
    signature: "",
  }) as unknown as GuardianAttestation;

const manifest = (receipts: unknown): BundleManifest =>
  ({
    v: 1,
    type: "verifiable-receipt-bundle",
    generatedAt: "2026-10-24T00:00:00.000Z",
    receiptCount: 1,
    bundleDigest: "",
    receipts,
    manifestHash: "",
    signature: "",
  }) as unknown as BundleManifest;

describe("nesting depth", () => {
  it("canonicalJson writes a value 64 deep and refuses one 65 deep", () => {
    expect(canonicalJson({ d: nested(63) })).toBe(`{"d":${"[".repeat(63)}${"]".repeat(63)}}`);
    expect(() => canonicalJson({ d: nested(64) })).toThrow("canonical JSON: nesting deeper than 64");
  });

  for (const depth of [5_000, 20_000]) {
    it(`returns a verdict, not a stack overflow, at depth ${depth}`, () => {
      expect(() => canonicalJson(nested(depth))).toThrow("canonical JSON: nesting deeper than 64");
      expect(verifyGuardianAttestation(attestation(nested(depth)), () => true)).toEqual({
        ok: false,
        reason: "nesting-too-deep",
      });
      expect(verifyManifest(manifest([nested(depth)]), () => true)).toEqual({
        ok: false,
        reason: "nesting-too-deep",
      });
    });
  }

  it("leaves shallow input to the other checks", () => {
    expect(verifyGuardianAttestation(attestation(nested(10)), () => true).reason).toBe("canonical-mismatch");
    expect(verifyManifest(manifest([nested(10)]), () => true).ok).toBe(false);
    expect(verifyManifest(manifest([nested(10)]), () => true)).not.toEqual({
      ok: false,
      reason: "nesting-too-deep",
    });
  });
});
