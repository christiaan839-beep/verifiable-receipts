/**
 * The conformance v2 verifier's envelope rule for large numbers: JSON.parse
 * reads 2^53 + 1 as 2^53, so a number of magnitude 2^53 or more in a
 * repeated field matches nothing, here and in the Python and Go verifiers.
 * And its nesting limit: a receipt or canonical nested deeper than 64 is
 * rejected with a verdict, never a thrown stack overflow.
 */
import { describe, it, expect } from "vitest";
import { createHash, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import {
  jsonEqual,
  nestsTooDeep,
  textNestsTooDeep,
  verifyV2Receipt,
} from "../conformance/verify-v2.mjs";

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

  it("bounds jsonEqual, nestsTooDeep and textNestsTooDeep at 64", () => {
    expect(jsonEqual(nested(64), nested(64))).toBe(true);
    expect(jsonEqual(nested(65), nested(65))).toBe(false);
    expect(jsonEqual(nested(20_000), nested(20_000))).toBe(false);
    // Objects too: {"k":{"k":...}} `levels` deep.
    const objects = (levels: number) => {
      let value: unknown = {};
      for (let i = 1; i < levels; i++) value = { k: value };
      return value;
    };
    expect(jsonEqual(objects(64), objects(64))).toBe(true);
    expect(jsonEqual(objects(65), objects(65))).toBe(false);
    expect(nestsTooDeep(nested(64))).toBe(false);
    expect(nestsTooDeep(nested(65))).toBe(true);
    expect(textNestsTooDeep(nestedText(64))).toBe(false);
    expect(textNestsTooDeep(nestedText(65))).toBe(true);
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


// VAOS 2.0 section 7.3: weak public keys. Little-endian y, sign bit clear.
const P = 2n ** 255n - 19n;
const keyFromY = (y: bigint) => Buffer.from(y.toString(16).padStart(64, "0"), "hex").reverse();
const keyObject = (raw: Buffer) =>
  createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") }, format: "jwk" });
// Under the identity key this signature verifies every message.
const universal = "v2=" + Buffer.concat([keyFromY(1n), Buffer.alloc(32)]).toString("base64");
const identitySignBit = Buffer.from(keyFromY(1n));
identitySignBit[31] |= 0x80;

describe("verifyV2Receipt — weak public keys", () => {
  for (const [name, raw, reason] of [
    ["identity", keyFromY(1n), "public key is a small-order point"],
    ["identity with the sign bit", identitySignBit, "public key is a small-order point"],
    ["y = p + 1", keyFromY(P + 1n), "public key is a small-order point"],
    ["y = p + 3", keyFromY(P + 3n), "public key is not a canonical encoding"],
  ] as const) {
    it(`refuses the ${name} key`, () => {
      const result = verifyV2Receipt({ canonical: `{"a":1}`, signature: universal }, keyObject(raw));
      expect(result).toEqual({ ok: false, reason });
    });
  }

  it("accepts a valid key", () => {
    expect(verifyV2Receipt(receipt(`{"a":1}`, {}), publicKey)).toEqual({ ok: true });
  });
});
