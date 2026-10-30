/**
 * VAOS 2.0 section 7.3, the strict profile: before the signature reaches
 * node:crypto, R must be a canonical encoding of a point of order L (not
 * of small order, the identity included, and in the prime-order
 * subgroup), S must be below L, and the key must be a point of order L.
 * Checked in the library (`verifyEd25519`, `ed25519SignatureProblem`,
 * `ed25519PublicKeyProblem`, `loadEd25519PublicKey`) and in the
 * conformance verifier (`verifyEd25519Strict`, `verifyV2Receipt`), with
 * the reasons of the Python and Go verifiers.
 */
import { describe, it, expect } from "vitest";
import { createHash, createPublicKey, verify as nodeVerify, type KeyObject } from "node:crypto";
import {
  BASE,
  IDENTITY,
  L,
  P,
  decode,
  encode,
  pointAdd,
  scalarMult,
  type Point,
} from "../src/edwards25519.js";
import {
  ed25519PublicKeyProblem,
  ed25519SignatureProblem,
  loadEd25519PublicKey,
  verifyEd25519,
} from "../src/ed25519-key.js";
import { verifyEd25519Strict, verifyV2Receipt } from "../conformance/verify-v2.mjs";

const GENERIC = "signature does not verify under the supplied public key";
const point = (h: string): Point => {
  const [p] = decode(Buffer.from(h, "hex"));
  if (p === null) throw new Error("bad point");
  return p;
};
const T8 = point("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
const T2 = point("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
const A_SCALAR = 0x1234567890abcdef1234567890abcdefn % L;
const R_SCALAR = 0xfedcba0987654321fedcba0987654321n % L;
const PUB = Buffer.from(encode(scalarMult(A_SCALAR, BASE)));
const MIXED_PUB = Buffer.from(encode(pointAdd(scalarMult(A_SCALAR, BASE), T8)));
const MSG = Buffer.from(`{"a":1}`);

const le32 = (n: bigint) => Buffer.from(n.toString(16).padStart(64, "0"), "hex").reverse();
const kOf = (r: Uint8Array, pub: Uint8Array, msg: Uint8Array) =>
  BigInt("0x" + Buffer.from(createHash("sha512").update(r).update(pub).update(msg).digest()).reverse().toString("hex")) % L;
const keyObject = (raw: Uint8Array): KeyObject =>
  createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw).toString("base64url") }, format: "jwk" });
const pemOf = (raw: Uint8Array) => keyObject(raw).export({ type: "spki", format: "pem" }).toString();
/** (R, S = r + k*a) for a chosen R. */
function sigWithR(rPoint: Point, msg: Uint8Array, pub: Uint8Array = PUB, r = 0n): Buffer {
  const rEnc = Buffer.from(encode(rPoint));
  return Buffer.concat([rEnc, le32((r + kOf(rEnc, pub, msg) * A_SCALAR) % L)]);
}
const receipt = (msg: Uint8Array, sig: Uint8Array) => ({
  canonical: Buffer.from(msg).toString("utf8"),
  signature: "v2=" + Buffer.from(sig).toString("base64"),
});

/** Every TypeScript entry point's reason for (pub, msg, sig), all equal. */
function reasons(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): (string | undefined)[] {
  return [
    verifyEd25519(pub, msg, sig).reason,
    verifyEd25519(keyObject(pub), msg, sig).reason,
    verifyEd25519Strict(pub, msg, sig).reason,
    verifyV2Receipt(receipt(msg, sig), keyObject(pub)).reason,
  ];
}

describe("strict Ed25519", () => {
  it("accepts an honest signature", () => {
    const sig = sigWithR(scalarMult(R_SCALAR, BASE), MSG, PUB, R_SCALAR);
    expect(reasons(PUB, MSG, sig)).toEqual([undefined, undefined, undefined, undefined]);
    expect(verifyEd25519(PUB, MSG, sig).ok).toBe(true);
    expect(verifyV2Receipt(receipt(MSG, sig), keyObject(PUB)).ok).toBe(true);
  });

  for (const [name, rPoint, r, reason] of [
    ["the identity", IDENTITY, 0n, "signature R is a small-order point"],
    ["a point of order 2", T2, 0n, "signature R is a small-order point"],
    ["a point of order 8", T8, 0n, "signature R is a small-order point"],
    ["a mixed-order point", pointAdd(scalarMult(R_SCALAR, BASE), T8), R_SCALAR, "signature R is not in the prime-order subgroup"],
  ] as const) {
    it(`rejects R = ${name}`, () => {
      const sig = sigWithR(rPoint, MSG, PUB, r);
      expect(ed25519SignatureProblem(sig)).toBe(reason);
      expect(reasons(PUB, MSG, sig)).toEqual([reason, reason, reason, reason]);
    });
  }

  it("rejects R = identity, S = k*a, which the cofactorless check alone may accept", () => {
    const sig = sigWithR(IDENTITY, MSG);
    // Node 22 answers true here, Node 24.22 (OpenSSL 3.5.9) false; the
    // strict profile answers the same on both.
    expect(typeof nodeVerify(null, MSG, keyObject(PUB), sig)).toBe("boolean");
    expect(reasons(PUB, MSG, sig)).toEqual(Array(4).fill("signature R is a small-order point"));
  });

  it("rejects R that is not a canonical encoding or not on the curve", () => {
    const rEnc = le32(P + 1n);
    const noncanonical = Buffer.concat([rEnc, le32((kOf(rEnc, PUB, MSG) * A_SCALAR) % L)]);
    expect(reasons(PUB, MSG, noncanonical)).toEqual(Array(4).fill("signature R is not a canonical encoding"));
    const signBit = Buffer.from(encode(IDENTITY));
    signBit[31] |= 0x80;
    expect(ed25519SignatureProblem(Buffer.concat([signBit, Buffer.alloc(32)]))).toBe(
      "signature R is not a canonical encoding",
    );
    const offCurve = Buffer.concat([le32(2n), le32(R_SCALAR)]);
    expect(reasons(PUB, MSG, offCurve)).toEqual(Array(4).fill("signature R is not a point on the curve"));
  });

  it("rejects S of L or more, and a signature that is not 64 bytes, with the usual reason", () => {
    const sig = sigWithR(scalarMult(R_SCALAR, BASE), MSG, PUB, R_SCALAR);
    const s = BigInt("0x" + Buffer.from(sig.subarray(32)).reverse().toString("hex"));
    for (const bad of [s + L, L, 2n ** 256n - 1n]) {
      const tampered = Buffer.concat([sig.subarray(0, 32), le32(bad)]);
      expect(ed25519SignatureProblem(tampered)).toBe(GENERIC);
      expect(reasons(PUB, MSG, tampered)).toEqual(Array(4).fill(GENERIC));
    }
    expect(ed25519SignatureProblem(sig)).toBeNull();
    for (const n of [0, 63, 65]) {
      expect(ed25519SignatureProblem(Buffer.alloc(n))).toBe(GENERIC);
      expect(verifyEd25519(PUB, MSG, Buffer.alloc(n)).reason).toBe(GENERIC);
      expect(verifyEd25519Strict(PUB, MSG, Buffer.alloc(n)).reason).toBe(GENERIC);
    }
  });

  it("rejects mixed-order R where the cofactorless equation holds (the key first)", () => {
    for (let nonce = 0; nonce < 400; nonce++) {
      const msg = Buffer.from(`{"n":${nonce}}`);
      for (let t = 1n; t < 8n; t++) {
        const rEnc = Buffer.from(encode(pointAdd(scalarMult(R_SCALAR, BASE), scalarMult(t, T8))));
        const k = kOf(rEnc, MIXED_PUB, msg);
        if ((t + k) % 8n !== 0n) continue;
        const sig = Buffer.concat([rEnc, le32((R_SCALAR + k * A_SCALAR) % L)]);
        expect(nodeVerify(null, msg, keyObject(MIXED_PUB), sig)).toBe(true);
        expect(reasons(MIXED_PUB, msg, sig)).toEqual(Array(4).fill("public key is not in the prime-order subgroup"));
        expect(ed25519SignatureProblem(sig)).toBe("signature R is not in the prime-order subgroup");
        return;
      }
    }
    throw new Error("no message found");
  });

  it("refuses keys of mixed order or off the curve, when loaded and when used", () => {
    const t2Mixed = Buffer.from(encode(pointAdd(scalarMult(A_SCALAR, BASE), T2)));
    for (const [raw, reason] of [
      [MIXED_PUB, "public key is not in the prime-order subgroup"],
      [t2Mixed, "public key is not in the prime-order subgroup"],
      [le32(2n), "public key is not a point on the curve"],
    ] as const) {
      expect(ed25519PublicKeyProblem(raw)).toBe(reason);
      expect(() => loadEd25519PublicKey(pemOf(raw))).toThrow(reason);
      const sig = sigWithR(scalarMult(R_SCALAR, BASE), MSG, raw, R_SCALAR);
      expect(reasons(raw, MSG, sig)).toEqual([reason, reason, reason, reason]);
    }
  });

  it("keeps the existing key reasons", () => {
    expect(ed25519PublicKeyProblem(le32(1n))).toBe("public key is a small-order point");
    expect(ed25519PublicKeyProblem(le32(P + 1n))).toBe("public key is a small-order point");
    expect(ed25519PublicKeyProblem(le32(P + 3n))).toBe("public key is not a canonical encoding");
    expect(ed25519PublicKeyProblem(encode(T8))).toBe("public key is a small-order point");
    expect(ed25519PublicKeyProblem(PUB)).toBeNull();
    expect(ed25519PublicKeyProblem(PUB.subarray(0, 31))).toBe("public key is not 32 bytes");
    expect(verifyEd25519(PUB.subarray(0, 31), MSG, Buffer.alloc(64)).reason).toBe("public key is not 32 bytes");
    expect(verifyEd25519Strict(PUB.subarray(0, 31), MSG, Buffer.alloc(64)).reason).toBe("public key is not 32 bytes");
  });
});
