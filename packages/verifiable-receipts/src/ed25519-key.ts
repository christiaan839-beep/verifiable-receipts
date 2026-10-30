/**
 * Ed25519 under the strict profile of VAOS 2.0 section 7.3.
 *
 * A public key must be a canonical encoding of a point of order L: not a
 * point of small order (under which some signatures verify every
 * message), not of mixed order, not off the curve, not a non-canonical
 * encoding. A signature's R must be the same, and its S below L. These
 * are checked before node:crypto sees the signature: on what passes them,
 * every correct Ed25519 verifier, cofactored or cofactorless, gives the
 * same verdict. Node.js 24.22.1 (OpenSSL 3.5.9) and 26.10.0 (OpenSSL
 * 3.5.8) refuse R = identity, which Node.js 22.23.2 accepts; these
 * checks refuse it on every line.
 */
import { KeyObject, createPublicKey, verify as nodeVerify } from "node:crypto";
import { L, pointProblem } from "./edwards25519.js";

/**
 * The encodings of the points of small order, with the sign bit cleared:
 * the libsodium blocklist ("Taming the many EdDSAs", Chalkias et al.). The
 * last two are the non-canonical encodings y = p and y = p + 1.
 */
const SMALL_ORDER_KEYS = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]);

const P = 2n ** 255n - 19n;

/** The reason a signature that fails is rejected with, here and in Python and Go. */
const DOES_NOT_VERIFY = "signature does not verify under the supplied public key";

/** Answers of ed25519PublicKeyProblem, by key; a key's answer never changes. */
const keyProblems = new Map<string, string | null>();
const KEY_CACHE_SIZE = 256;

/**
 * Why a raw 32-byte Ed25519 public key is refused (VAOS 2.0 section 7.3),
 * or null. In order: "public key is not 32 bytes"; "public key is a
 * small-order point" (the blocklist, sign bit cleared); "public key is
 * not a canonical encoding" (y of p or more); "public key is not a point
 * on the curve"; "public key is a small-order point"; "public key is not
 * in the prime-order subgroup" (mixed order). The same reasons as the
 * Python and Go verifiers. Answers are cached per key.
 *
 * @public
 */
export function ed25519PublicKeyProblem(raw: Uint8Array): string | null {
  if (raw.length !== 32) return "public key is not 32 bytes";
  const hex = Buffer.from(raw).toString("hex");
  const cached = keyProblems.get(hex);
  if (cached !== undefined) return cached;
  const cleared = Buffer.from(raw);
  cleared[31] = (cleared[31] ?? 0) & 0x7f;
  let problem: string | null;
  if (SMALL_ORDER_KEYS.has(cleared.toString("hex"))) {
    problem = "public key is a small-order point";
  } else if (BigInt("0x" + Buffer.from(cleared).reverse().toString("hex")) >= P) {
    problem = "public key is not a canonical encoding";
  } else {
    const p = pointProblem(raw);
    problem = p === null ? null : `public key is ${p}`;
  }
  if (keyProblems.size >= KEY_CACHE_SIZE) keyProblems.clear();
  keyProblems.set(hex, problem);
  return problem;
}

/**
 * Why a 64-byte Ed25519 signature is rejected before the signature check
 * (VAOS 2.0 section 7.3), or null: its R (first 32 bytes) must be a
 * canonical encoding of a point on the curve that is not of small order
 * (the identity included) and is in the prime-order subgroup ("signature
 * R is not a canonical encoding", "... is not a point on the curve",
 * "... is a small-order point", "... is not in the prime-order
 * subgroup"); and its S (last 32, little-endian) must be below L. A wrong
 * length or an S of L or more has the reason a failed check has. R is
 * never cached.
 *
 * @public
 */
export function ed25519SignatureProblem(signature: Uint8Array): string | null {
  if (signature.length !== 64) return DOES_NOT_VERIFY;
  const problem = pointProblem(signature.subarray(0, 32));
  if (problem !== null) return `signature R is ${problem}`;
  const s = BigInt("0x" + Buffer.from(signature.subarray(32)).reverse().toString("hex"));
  if (s >= L) return DOES_NOT_VERIFY;
  return null;
}

function rawOf(key: KeyObject): Uint8Array | null {
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") return null;
  const x = key.export({ format: "jwk" }).x;
  return typeof x === "string" ? Buffer.from(x, "base64url") : null;
}

/**
 * Verify an Ed25519 signature under the strict profile of VAOS 2.0
 * section 7.3: the key (`ed25519PublicKeyProblem`), then R and S
 * (`ed25519SignatureProblem`), then node:crypto's cofactorless check over
 * R and A as given. `publicKey` is a KeyObject or the raw 32 bytes.
 * Never throws: an argument that is not a Uint8Array (or, for the key,
 * a KeyObject) fails with the last reason below; the reason on failure is one of the reasons above or
 * "signature does not verify under the supplied public key".
 *
 * @public
 */
export function verifyEd25519(
  publicKey: KeyObject | Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): { ok: boolean; reason?: string } {
  if (!(message instanceof Uint8Array) || !(signature instanceof Uint8Array)) {
    return { ok: false, reason: DOES_NOT_VERIFY };
  }
  let key: KeyObject;
  let raw: Uint8Array | null;
  try {
    if (publicKey instanceof Uint8Array) {
      raw = publicKey;
      const problem = ed25519PublicKeyProblem(raw);
      if (problem) return { ok: false, reason: problem };
      key = createPublicKey({
        key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw).toString("base64url") },
        format: "jwk",
      });
    } else {
      if (!(publicKey instanceof KeyObject)) return { ok: false, reason: DOES_NOT_VERIFY };
      key = publicKey;
      raw = rawOf(key);
    }
  } catch {
    return { ok: false, reason: DOES_NOT_VERIFY };
  }
  if (raw === null) return { ok: false, reason: DOES_NOT_VERIFY };
  const problem = ed25519PublicKeyProblem(raw) ?? ed25519SignatureProblem(signature);
  if (problem) return { ok: false, reason: problem };
  let ok: boolean;
  try {
    ok = nodeVerify(null, message, key, signature);
  } catch {
    ok = false;
  }
  return ok ? { ok: true } : { ok: false, reason: DOES_NOT_VERIFY };
}

/**
 * Load an Ed25519 public key from PEM (SPKI), the format VAOS 2.0 section
 * 6.3 publishes it in. Throws when the PEM is not an Ed25519 public key, or
 * when `ed25519PublicKeyProblem` refuses the key.
 *
 * @public
 */
export function loadEd25519PublicKey(pem: string | Buffer): KeyObject {
  const key = createPublicKey({ key: pem, format: "pem" });
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("PEM is not an Ed25519 public key");
  }
  const x = key.export({ format: "jwk" }).x;
  const problem = ed25519PublicKeyProblem(Buffer.from(x ?? "", "base64url"));
  if (problem) throw new Error(problem);
  return key;
}
