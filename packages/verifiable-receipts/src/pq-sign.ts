/**
 * Dual signing: Ed25519 + ML-DSA-65 (NIST FIPS 204).
 *
 * Receipts may need to verify for many years. If Ed25519 is broken
 * (for example by a large quantum computer), a `v3=` receipt still
 * carries an ML-DSA-65 signature over the same bytes, and
 * `verifyDualSig` requires both halves to hold. ML-DSA-65 comes from
 * `@noble/post-quantum`, which its authors describe as self-audited,
 * not independently audited.
 *
 * Wire format:
 *   v2=<base64-ed25519>                  ← Ed25519-only
 *   v3=<base64-ed25519>.<base64-mldsa65> ← dual-signed (this module)
 *
 * Pure module — no Node-specific I/O beyond `Buffer`. Caller supplies
 * the signing keys; we sign and verify.
 *
 * @packageDocumentation
 */

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

/** FIPS 204 ML-DSA-65 signature length in bytes. */
const ML_DSA65_SIGNATURE_BYTES = 3309;

/**
 * Decode standard base64 (RFC 4648 §4, padded). Returns null for any
 * other alphabet, missing padding or stray characters, which
 * `Buffer.from(s, "base64")` would silently skip.
 */
function decodeStrictBase64(s: string): Uint8Array | null {
  if (s.length === 0 || s.length % 4 !== 0) return null;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const bytes = Buffer.from(s, "base64");
  if (bytes.toString("base64") !== s) return null;
  return Uint8Array.from(bytes);
}

/** Result envelope for verifyDualSig(). */
export interface DualSigVerdict {
  ok: boolean;
  ed25519: boolean;
  mldsa65: boolean;
}

/**
 * Sign a canonical byte string with ML-DSA-65.
 * Returns base64-encoded signature.
 */
export function signMlDsa65(canonical: string, secretKey: Uint8Array): string {
  const sig = ml_dsa65.sign(
    Uint8Array.from(Buffer.from(canonical, "utf8")),
    secretKey,
  );
  return Buffer.from(sig).toString("base64");
}

/**
 * Verify a base64 ML-DSA-65 signature against canonical bytes.
 * Returns false on non-canonical base64, a signature that is not 3309
 * bytes, a mismatch, or a library throw. Never throws on adversarial
 * input.
 */
export function verifyMlDsa65(
  canonical: string,
  signatureB64: string,
  publicKey: Uint8Array,
): boolean {
  const sigBytes = decodeStrictBase64(signatureB64);
  if (!sigBytes || sigBytes.length !== ML_DSA65_SIGNATURE_BYTES) return false;
  try {
    return ml_dsa65.verify(
      sigBytes,
      Uint8Array.from(Buffer.from(canonical, "utf8")),
      publicKey,
    );
  } catch {
    return false;
  }
}

/**
 * Verify a dual-signature in the v3 wire format
 * (`v3=<ed25519-b64>.<mldsa65-b64>`). BOTH signatures must validate
 * for the verdict to be ok=true.
 *
 * `verifyEd25519` is a caller-supplied function so this module stays
 * pure (no Node:crypto coupling). Use any Ed25519 verifier — Node's
 * built-in `crypto.verify`, @noble/curves, libsodium, etc.
 */
export function verifyDualSig(
  canonical: string,
  wire: string,
  publicKeyMlDsa65: Uint8Array,
  verifyEd25519: (canonical: string, signature: string) => boolean,
): DualSigVerdict {
  if (!wire.startsWith("v3=")) {
    return { ok: false, ed25519: false, mldsa65: false };
  }
  const body = wire.slice(3);
  const parts = body.split(".");
  if (parts.length !== 2) {
    return { ok: false, ed25519: false, mldsa65: false };
  }
  const [edB64, mlB64] = parts;
  const edBytes = decodeStrictBase64(edB64);
  if (!edBytes || edBytes.length !== 64) {
    const ml = verifyMlDsa65(canonical, mlB64, publicKeyMlDsa65);
    return { ok: false, ed25519: false, mldsa65: ml };
  }
  const ed = verifyEd25519(canonical, `v2=${edB64}`);
  const ml = verifyMlDsa65(canonical, mlB64, publicKeyMlDsa65);
  return { ok: ed && ml, ed25519: ed, mldsa65: ml };
}

/** Format a v3 wire signature from raw base64 components. */
export function formatV3Wire(ed25519B64: string, mldsa65B64: string): string {
  return `v3=${ed25519B64}.${mldsa65B64}`;
}

/**
 * Generate a fresh ML-DSA-65 keypair. Returns base64-encoded keys
 * suitable for env-var storage.
 */
export function generateMlDsa65Keypair(): {
  secretKeyB64: string;
  publicKeyB64: string;
} {
  const { secretKey, publicKey } = ml_dsa65.keygen();
  return {
    secretKeyB64: Buffer.from(secretKey).toString("base64"),
    publicKeyB64: Buffer.from(publicKey).toString("base64"),
  };
}
