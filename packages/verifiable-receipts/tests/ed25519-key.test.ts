/**
 * VAOS 2.0 section 7.3: loadEd25519PublicKey refuses a key that is a
 * point of small order or a non-canonical encoding.
 */
import { describe, it, expect } from "vitest";
import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { ed25519PublicKeyProblem, loadEd25519PublicKey } from "../src/ed25519-key.js";

const P = 2n ** 255n - 19n;
const keyFromY = (y: bigint) => Buffer.from(y.toString(16).padStart(64, "0"), "hex").reverse();
const pemOf = (raw: Buffer) =>
  createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") }, format: "jwk" })
    .export({ type: "spki", format: "pem" })
    .toString();

describe("loadEd25519PublicKey", () => {
  it("refuses the identity, y = p + 1 and y = p + 3 keys", () => {
    expect(() => loadEd25519PublicKey(pemOf(keyFromY(1n)))).toThrow("public key is a small-order point");
    expect(() => loadEd25519PublicKey(pemOf(keyFromY(P + 1n)))).toThrow("public key is a small-order point");
    expect(() => loadEd25519PublicKey(pemOf(keyFromY(P + 3n)))).toThrow(
      "public key is not a canonical encoding",
    );
  });

  it("refuses every key on the small-order blocklist, with or without the sign bit", () => {
    for (const hex of [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ]) {
      const raw = Buffer.from(hex, "hex");
      expect(ed25519PublicKeyProblem(raw)).toBe("public key is a small-order point");
      raw[31] |= 0x80;
      expect(ed25519PublicKeyProblem(raw)).toBe("public key is a small-order point");
    }
  });

  it("loads a valid key, and refuses a PEM that is not an Ed25519 key", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(loadEd25519PublicKey(pem).asymmetricKeyType).toBe("ed25519");
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
    expect(() => loadEd25519PublicKey(rsa.export({ type: "spki", format: "pem" }).toString())).toThrow(
      "not an Ed25519 public key",
    );
  });
});
