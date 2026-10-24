/**
 * Ed25519 public keys a verifier refuses (VAOS 2.0 section 7.3): points of
 * small order, under which some signatures verify every message, and
 * non-canonical encodings. Node's `crypto.verify` accepts both, so a key is
 * checked when it is loaded.
 */
import { createPublicKey, type KeyObject } from "node:crypto";

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

/**
 * Why a raw 32-byte Ed25519 public key is refused, or null: "public key is
 * a small-order point" or "public key is not a canonical encoding" (y of p
 * or more). The same reasons as the Python and Go verifiers.
 *
 * @public
 */
export function ed25519PublicKeyProblem(raw: Uint8Array): string | null {
  if (raw.length !== 32) return "public key is not 32 bytes";
  const cleared = Buffer.from(raw);
  cleared[31] &= 0x7f;
  if (SMALL_ORDER_KEYS.has(cleared.toString("hex"))) return "public key is a small-order point";
  const y = BigInt("0x" + Buffer.from(cleared).reverse().toString("hex"));
  if (y >= P) return "public key is not a canonical encoding";
  return null;
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
