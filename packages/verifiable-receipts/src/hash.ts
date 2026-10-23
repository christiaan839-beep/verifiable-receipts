/**
 * SHA-256 hex digests and the wire spelling of a hash, shared by the
 * modules of this package. Not exported from the package.
 */

import { createHash } from "node:crypto";

/** Lowercase hex SHA-256 of `input`; a string is hashed as its UTF-8 bytes. */
export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

/** A hash on the wire: 32 bytes, written as exactly 64 lowercase hex digits. */
export function isHashHex(x: unknown): x is string {
  return typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
}
