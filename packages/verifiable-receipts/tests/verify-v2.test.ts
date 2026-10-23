/**
 * The conformance v2 verifier's envelope rule for large numbers: JSON.parse
 * reads 2^53 + 1 as 2^53, so a number of magnitude 2^53 or more in a
 * repeated field matches nothing, here and in the Python and Go verifiers.
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
