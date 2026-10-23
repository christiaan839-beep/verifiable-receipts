/**
 * The JavaScript v2 verifier of the conformance corpus, with node:crypto.
 *
 * Used by conformance.test.ts (the TypeScript harness) and by
 * roundtrip/verify.mjs. It lives here, not in src/, so the harness
 * checks the wire format itself rather than a library shortcut. It
 * makes the same checks, in the same order and with the same reasons,
 * as verify_v2_receipt (Python) and VerifyV2Receipt (Go):
 *
 *   1. `canonical` and `signature` are non-empty strings.
 *   2. `signature` is "v2=<base64>" with standard base64.
 *   3. `contentHash`, when present and not null, is a string; when
 *      non-empty, it equals the hex SHA-256 of `canonical`'s UTF-8
 *      bytes ("sha256:" prefix optional). (Go's Receipt.UnmarshalJSON
 *      rejects a non-string contentHash the same way.)
 *   4. The Ed25519 signature verifies over `canonical`'s UTF-8 bytes,
 *      exactly as given.
 *   5. `canonical` parses as a JSON object.
 *   6. Every other top-level field of the receipt equals the same field
 *      of that object (deep JSON-value equality); a field that
 *      disagrees, or that the canonical lacks, is rejected.
 *
 * JavaScript reads every JSON number as an IEEE 754 double, so integers
 * beyond 2^53 that differ only past that precision compare equal here,
 * where the Python and Go verifiers compare them exactly.
 */
import { createHash, verify as nodeVerify } from "node:crypto";

const ENVELOPE_ONLY = new Set(["canonical", "contentHash", "signature"]);

const STANDARD_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function isObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Deep JSON-value equality; object key order does not matter. */
export function jsonEqual(a, b) {
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((x, i) => jsonEqual(x, b[i]))
    );
  }
  if (isObject(a) || isObject(b)) {
    if (!isObject(a) || !isObject(b)) return false;
    const ka = Object.keys(a);
    if (ka.length !== Object.keys(b).length) return false;
    return ka.every((k) => Object.hasOwn(b, k) && jsonEqual(a[k], b[k]));
  }
  return a === b; // null, booleans, numbers, strings
}

/**
 * @param {Record<string, unknown>} receipt
 * @param {import("node:crypto").KeyObject} publicKey  Ed25519 public key
 * @returns {{ ok: boolean, reason?: string }}
 */
export function verifyV2Receipt(receipt, publicKey) {
  if (!isObject(receipt)) return { ok: false, reason: "receipt must be an object" };
  const { canonical, signature, contentHash } = receipt;
  if (typeof canonical !== "string" || canonical === "") {
    return { ok: false, reason: "missing canonical projection" };
  }
  if (typeof signature !== "string" || signature === "") {
    return { ok: false, reason: "missing signature" };
  }
  if (!signature.startsWith("v2=")) {
    return { ok: false, reason: "signature is not v2 (expected 'v2=<base64>')" };
  }
  if (!STANDARD_BASE64.test(signature.slice(3))) {
    return { ok: false, reason: "signature base64 invalid" };
  }
  const sigBytes = Buffer.from(signature.slice(3), "base64");
  // Reject non-canonical spellings (non-zero padding bits).
  if (sigBytes.toString("base64") !== signature.slice(3)) {
    return { ok: false, reason: "signature base64 invalid: not canonical" };
  }
  const canonicalBytes = Buffer.from(canonical, "utf8");

  if (contentHash != null && typeof contentHash !== "string") {
    return { ok: false, reason: "contentHash must be a string" };
  }
  if (contentHash) {
    const actual = createHash("sha256").update(canonicalBytes).digest("hex");
    if (actual !== contentHash.replace(/^sha256:/, "")) {
      return { ok: false, reason: "contentHash mismatch with canonical bytes" };
    }
  }

  let verified = false;
  try {
    verified = nodeVerify(null, canonicalBytes, publicKey, sigBytes);
  } catch {
    verified = false;
  }
  if (!verified) {
    return {
      ok: false,
      reason: "signature does not verify under the supplied public key",
    };
  }

  // Only now parse the canonical: these bytes are authenticated.
  let signed;
  try {
    signed = JSON.parse(canonical);
  } catch {
    return { ok: false, reason: "canonical is not valid JSON" };
  }
  if (!isObject(signed)) {
    return { ok: false, reason: "canonical is not a JSON object" };
  }
  for (const key of Object.keys(receipt).sort()) {
    if (ENVELOPE_ONLY.has(key)) continue;
    if (!Object.hasOwn(signed, key)) {
      return {
        ok: false,
        reason: `envelope field "${key}" is not in the signed canonical`,
      };
    }
    if (!jsonEqual(receipt[key], signed[key])) {
      return {
        ok: false,
        reason: `envelope field "${key}" disagrees with the signed canonical`,
      };
    }
  }
  return { ok: true };
}
