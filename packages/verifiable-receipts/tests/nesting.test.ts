/**
 * The library's recursive paths and the nesting limit of VAOS 2.0 section 7.2:
 * the verifiers return a verdict on any depth, and the canonical JSON writer
 * refuses to write what a verifier would reject, rather than overflow the
 * stack.
 */
import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { canonicalJson } from "../src/canonical-json.js";
import {
  runGuardian,
  verifyGuardianAttestation,
  type GuardianAttestation,
  type GuardianRule,
} from "../src/guardian.js";
import { buildSignedBundle, verifyManifest, type BundleManifest } from "../src/bundle.js";
import { nestsDeeperThan, textNestsDeeperThan } from "../src/nesting.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signV2 = (canonical: string) =>
  `v2=${nodeSign(null, Buffer.from(canonical), privateKey).toString("base64")}`;
const verifyV2 = (canonical: string, signature: string) =>
  signature.startsWith("v2=") &&
  nodeVerify(null, Buffer.from(canonical), publicKey, Buffer.from(signature.slice(3), "base64"));

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

  it("counts a value 64 deep as within the limit, and 65 as beyond it", () => {
    expect(nestsDeeperThan(nested(64))).toBe(false);
    expect(nestsDeeperThan(nested(65))).toBe(true);
    expect(textNestsDeeperThan("[".repeat(64) + "]".repeat(64))).toBe(false);
    expect(textNestsDeeperThan("[".repeat(65))).toBe(true);
    // An escaped backslash, then an escaped quote, inside a string.
    const escapes = "\\\\\\\"";
    expect(textNestsDeeperThan(`["${"[".repeat(100)}${escapes}${"{".repeat(100)}"]`)).toBe(false);
  });

  it("leaves shallow input to the other checks", () => {
    expect(verifyGuardianAttestation(attestation(nested(10)), () => true).reason).toBe("canonical-mismatch");
    expect(verifyManifest(manifest([nested(10)]), () => true).ok).toBe(false);
    expect(verifyManifest(manifest([nested(10)]), () => true)).not.toEqual({
      ok: false,
      reason: "nesting-too-deep",
    });
  });
});

const ctx = { runId: "run", agentSlug: "agent", tokenId: "tok", input: {}, output: {} };
const rule = (evidence?: unknown): GuardianRule => ({
  id: "r",
  description: "a rule",
  evaluate: async () =>
    evidence === undefined
      ? { verdict: "pass" }
      : { verdict: "pass", evidence: evidence as Record<string, unknown> },
});

describe("verifyGuardianAttestation — nesting depth", () => {
  it("accepts a canonical 64 deep and rejects one 65 deep (a signed runId 63 and 64 deep)", async () => {
    const at = await runGuardian([rule()], { ...ctx, runId: nested(63) as string }, signV2);
    expect(verifyGuardianAttestation(at, verifyV2)).toEqual({ ok: true });
    const over = await runGuardian([rule()], { ...ctx, runId: nested(64) as string }, signV2);
    expect(verifyGuardianAttestation(over, verifyV2)).toEqual({ ok: false, reason: "nesting-too-deep" });
  });

  it("accepts an attestation 64 deep and rejects one 65 deep (unsigned evidence)", async () => {
    // attestation, rules and the rule are three levels; the evidence adds the rest.
    const at = await runGuardian([rule(nested(61))], ctx, signV2);
    expect(verifyGuardianAttestation(at, verifyV2)).toEqual({ ok: true });
    const over = await runGuardian([rule(nested(62))], ctx, signV2);
    expect(verifyGuardianAttestation(over, verifyV2)).toEqual({ ok: false, reason: "nesting-too-deep" });
  });

  it("returns a verdict on an unsigned canonical 20,000 deep, or one that is not a string (canonical-mismatch)", () => {
    const deep = { ...attestation(null), canonical: `{"runId":${"[".repeat(20_000)}${"]".repeat(20_000)}}` };
    expect(verifyGuardianAttestation(deep, () => true)).toEqual({ ok: false, reason: "nesting-too-deep" });
    const notText = { ...attestation(null), canonical: 7 } as unknown as GuardianAttestation;
    expect(verifyGuardianAttestation(notText, () => true)).toEqual({ ok: false, reason: "canonical-mismatch" });
  });
});

describe("verifyManifest — nesting depth", () => {
  const rows = [
    {
      id: "r1",
      agentName: "agent",
      modelUsed: "model",
      durationMs: 5,
      createdAt: "2026-01-01T00:00:00.000Z",
      signature: "v2=x",
      canonical: "{}",
    },
  ];

  it("accepts a manifest 64 deep and rejects one 65 deep (an unsigned extra field)", () => {
    const { manifest: signed } = buildSignedBundle(rows, signV2);
    const at = { ...signed, extra: nested(63) } as BundleManifest;
    expect(verifyManifest(at, verifyV2)).toEqual({ ok: true });
    const over = { ...signed, extra: nested(64) } as BundleManifest;
    expect(verifyManifest(over, verifyV2)).toEqual({ ok: false, reason: "nesting-too-deep" });
  });
});
