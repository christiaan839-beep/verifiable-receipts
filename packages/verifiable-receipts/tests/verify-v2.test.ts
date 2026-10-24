/**
 * The conformance v2 verifier's envelope rule for large numbers: JSON.parse
 * reads 2^53 + 1 as 2^53, so a number of magnitude 2^53 or more in a
 * repeated field matches nothing, here and in the Python and Go verifiers.
 * And its nesting limit: a receipt or canonical nested deeper than 64 is
 * rejected with a verdict, never a thrown stack overflow.
 */
import { describe, it, expect } from "vitest";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { verifyV2Receipt } from "../conformance/verify-v2.mjs";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");

function receipt(canonical: string, extra: Record<string, unknown>): Record<string, unknown> {
  return {
    ...extra,
    canonical,
    contentHash: "sha256:" + createHash("sha256").update(canonical).digest("hex"),
    signature: "v2=" + sign(null, Buffer.from(canonical, "utf8"), privateKey).toString("base64"),
  };
}

describe("verifyV2Receipt — numbers in repeated fields", () => {
  it("compares numbers below 2^53 by value", () => {
    const canonical = `{"overall":"pass","n":9007199254740991}`;
    expect(verifyV2Receipt(receipt(canonical, { n: 9007199254740991 }), publicKey).ok).toBe(true);
    expect(verifyV2Receipt(receipt(`{"n":1}`, { n: 1.0 }), publicKey).ok).toBe(true);
  });

  it("rejects a number of magnitude 2^53 or more, even one that matches", () => {
    for (const text of ["9007199254740992", "9007199254740993", "-9007199254740992", "1e300"]) {
      const canonical = `{"overall":"pass","big":${text}}`;
      const result = verifyV2Receipt(receipt(canonical, { big: JSON.parse(text) }), publicKey);
      expect(result.ok, text).toBe(false);
      expect(result.reason).toContain('"big" disagrees');
    }
  });
});

/** A value `levels` arrays deep, built without recursion. */
function nested(levels: number): unknown {
  let value: unknown = [];
  for (let i = 1; i < levels; i++) value = [value];
  return value;
}

/** The JSON text of nested(levels), built without JSON.stringify. */
const nestedText = (levels: number) => "[".repeat(levels) + "]".repeat(levels);

describe("verifyV2Receipt — nesting depth", () => {
  it("accepts a receipt and a canonical nested exactly 64 deep", () => {
    // The canonical's object is one level, its field 63 more; the receipt
    // object is one level, its copy of the field 63 more.
    const canonical = `{"d":${nestedText(63)}}`;
    expect(verifyV2Receipt(receipt(canonical, { d: nested(63) }), publicKey)).toEqual({ ok: true });
  });

  it("rejects a receipt nested 65 deep before checking anything else", () => {
    const result = verifyV2Receipt({ ...receipt(`{"a":1}`, {}), d: nested(64) }, publicKey);
    expect(result).toEqual({ ok: false, reason: "receipt nesting deeper than 64" });
  });

  it("rejects a canonical nested 65 deep, valid JSON or not", () => {
    for (const canonical of [`{"d":${nestedText(64)}}`, `{"d":${"[".repeat(64)}`, `x${"{".repeat(65)}`]) {
      const result = verifyV2Receipt(receipt(canonical, {}), publicKey);
      expect(result, canonical.slice(0, 8)).toEqual({ ok: false, reason: "canonical nesting deeper than 64" });
    }
  });

  it("does not count brackets inside strings", () => {
    // The string holds an escaped backslash, then an escaped quote.
    const escapes = "\\\\\\\"";
    const canonical = `{"s":"${"[".repeat(100)}${escapes}${"{".repeat(100)}"}`;
    expect(JSON.parse(canonical).s).toContain('\\"{');
    expect(verifyV2Receipt(receipt(canonical, {}), publicKey)).toEqual({ ok: true });
  });

  for (const depth of [5_000, 20_000]) {
    it(`returns a verdict, not a stack overflow, at depth ${depth}`, () => {
      const canonical = `{"d":${nestedText(depth)}}`;
      expect(verifyV2Receipt(receipt(canonical, { d: nested(depth) }), publicKey)).toEqual({
        ok: false,
        reason: "receipt nesting deeper than 64",
      });
      expect(verifyV2Receipt(receipt(canonical, {}), publicKey)).toEqual({
        ok: false,
        reason: "canonical nesting deeper than 64",
      });
    });
  }
});
