/**
 * The JavaScript v2 verifier of the conformance corpus, with node:crypto.
 *
 * Used by conformance.test.ts (the TypeScript harness) and by
 * roundtrip/verify.mjs. It lives here, not in src/, so the harness
 * checks the wire format itself rather than a library shortcut. It
 * makes the same checks, in the same order and with the same reasons,
 * as verify_v2_receipt (Python) and VerifyV2Receipt (Go):
 *
 *   0. The receipt nests at most 64 deep (VAOS 2.0 §7.2): the receipt
 *      object is one level, and each array or object in it one more.
 *   1. `canonical` and `signature` are non-empty strings.
 *   2. `signature` is "v2=<base64>" with standard base64.
 *   3. `contentHash`, when present and not null, is a string equal to
 *      the hex SHA-256 of `canonical`'s UTF-8 bytes ("sha256:" prefix
 *      optional); an empty string is a mismatch, not an absent field.
 *      (Go's Receipt.UnmarshalJSON rejects a non-string contentHash the
 *      same way.)
 *   4. The public key is not a point of small order or a non-canonical
 *      encoding (VAOS 2.0 §7.3; checked right after step 2), and the
 *      Ed25519 signature verifies over `canonical`'s UTF-8 bytes,
 *      exactly as given.
 *   5. `canonical` nests at most 64 deep, counted on its text before it
 *      is parsed, and parses as a JSON object.
 *   6. Every other top-level field of the receipt equals the same field
 *      of that object (deep JSON-value equality); a field that
 *      disagrees, or that the canonical lacks, is rejected.
 *
 * JavaScript reads every JSON number as an IEEE 754 double, so it cannot
 * tell 2^53 from 2^53 + 1. In step 6 a number of magnitude 2^53 or more,
 * in the field or in the canonical's value, equals nothing, here and in
 * the Python and Go verifiers (VAOS 2.0 §7, step 6): all three reject
 * such a field rather than compare it differently.
 *
 * jsonEqual below recurses at most 64 deep, and the depth checks walk an
 * explicit stack, so no input can overflow the call stack.
 */
import { createHash, verify as nodeVerify } from "node:crypto";

const ENVELOPE_ONLY = new Set(["canonical", "contentHash", "signature"]);

const STANDARD_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function isObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

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

/**
 * Why the Ed25519 public key is refused (VAOS 2.0 §7.3), or null: a point
 * of small order, or a non-canonical encoding (y of p or more). A key that
 * is not Ed25519 is left to the signature check, which fails.
 */
function ed25519KeyProblem(publicKey) {
  let x;
  try {
    x = publicKey.export({ format: "jwk" }).x;
  } catch {
    return null;
  }
  if (typeof x !== "string") return null;
  const cleared = Buffer.from(x, "base64url");
  if (cleared.length !== 32) return null;
  cleared[31] &= 0x7f;
  if (SMALL_ORDER_KEYS.has(cleared.toString("hex"))) return "public key is a small-order point";
  const y = BigInt("0x" + Buffer.from(cleared).reverse().toString("hex"));
  if (y >= 2n ** 255n - 19n) return "public key is not a canonical encoding";
  return null;
}

/** The nesting limit of VAOS 2.0 §7.2. */
const MAX_NESTING = 64;

/**
 * Whether `value` nests deeper than MAX_NESTING: `value` is one level
 * when it is an array or object, and each array or object inside it one
 * more. Walks an explicit stack, so it cannot overflow the call stack.
 */
export function nestsTooDeep(value) {
  const stack = [[value, 1]];
  while (stack.length > 0) {
    const [v, level] = stack.pop();
    if (v === null || typeof v !== "object") continue;
    if (level > MAX_NESTING) return true;
    for (const child of Array.isArray(v) ? v : Object.values(v)) {
      if (child !== null && typeof child === "object") stack.push([child, level + 1]);
    }
  }
  return false;
}

/**
 * Whether JSON text opens more than MAX_NESTING arrays and objects at
 * once, read from the start, valid JSON or not: outside strings `[` and
 * `{` open one and `]` and `}` close one (when one is open); a string
 * runs from `"` to the next `"` not escaped by `\`.
 */
export function textNestsTooDeep(text) {
  let open = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === "\\") i++;
      else if (c === '"') inString = false;
    } else if (c === '"') {
      inString = true;
    } else if (c === "[" || c === "{") {
      if (++open > MAX_NESTING) return true;
    } else if ((c === "]" || c === "}") && open > 0) {
      open--;
    }
  }
  return false;
}

/**
 * Deep JSON-value equality; object key order does not matter. A number of
 * magnitude 2^53 or more equals nothing: JSON.parse reads 2^53 + 1 as
 * 2^53, so such a number in a repeated field is rejected in every
 * verifier rather than compared differently.
 *
 * Bounded at MAX_NESTING: `depth` is the level of `a` and `b` (1 at the
 * top), and arrays or objects deeper than MAX_NESTING equal nothing, so
 * no input, even from a caller other than verifyV2Receipt, recurses
 * deeper than that.
 */
export function jsonEqual(a, b, depth = 1) {
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      depth <= MAX_NESTING &&
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((x, i) => jsonEqual(x, b[i], depth + 1))
    );
  }
  if (isObject(a) || isObject(b)) {
    if (depth > MAX_NESTING || !isObject(a) || !isObject(b)) return false;
    const ka = Object.keys(a);
    if (ka.length !== Object.keys(b).length) return false;
    return ka.every((k) => Object.hasOwn(b, k) && jsonEqual(a[k], b[k], depth + 1));
  }
  if (typeof a === "number" && typeof b === "number") {
    return Math.abs(a) < 2 ** 53 && Math.abs(b) < 2 ** 53 && a === b;
  }
  return a === b; // null, booleans, strings
}

/**
 * Reads a receipt from JSON text, counting its depth on the text first
 * (VAOS 2.0 §7.2), so a duplicate key that JSON.parse discards still
 * counts. Throws an Error whose message is the reason, as Python's
 * parse_receipt and Go's ParseReceipt do: "receipt nesting deeper than
 * 64", "receipt is not valid JSON" or "receipt is not a JSON object".
 *
 * @param {string} text
 * @returns {Record<string, unknown>}
 */
export function parseReceipt(text) {
  if (textNestsTooDeep(text)) throw new Error("receipt nesting deeper than 64");
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("receipt is not valid JSON");
  }
  if (!isObject(value)) throw new Error("receipt is not a JSON object");
  return value;
}

/**
 * @param {Record<string, unknown>} receipt
 * @param {import("node:crypto").KeyObject} publicKey  Ed25519 public key
 * @returns {{ ok: boolean, reason?: string }}
 */
export function verifyV2Receipt(receipt, publicKey) {
  if (!isObject(receipt)) return { ok: false, reason: "receipt must be an object" };
  if (nestsTooDeep(receipt)) return { ok: false, reason: "receipt nesting deeper than 64" };
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
  const keyProblem = ed25519KeyProblem(publicKey);
  if (keyProblem) return { ok: false, reason: keyProblem };
  const canonicalBytes = Buffer.from(canonical, "utf8");

  if (contentHash != null && typeof contentHash !== "string") {
    return { ok: false, reason: "contentHash must be a string" };
  }
  if (contentHash != null) {
    const actual = createHash("sha256").update(canonicalBytes).digest("hex");
    if (actual !== contentHash.replace(/^sha256:/, "")) {
      return { ok: false, reason: "contentHash mismatch with canonical bytes" };
    }
  }

  let verified;
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
  if (textNestsTooDeep(canonical)) {
    return { ok: false, reason: "canonical nesting deeper than 64" };
  }
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
