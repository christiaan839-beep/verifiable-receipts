/**
 * JSON with object keys sorted at every depth (UTF-16 code-unit order,
 * as `Array.prototype.sort` orders strings) and no whitespace: the
 * canonical projection of VAOS 2.0 §5, also used for bundle manifests.
 * Not exported from the package; `bin/sign.mjs` imports it from `dist/`.
 */
import { MAX_NESTING } from "./nesting.js";

/**
 * A copy of `value` whose objects have their keys in sorted order.
 *
 * Throws when `value` nests deeper than 64 (VAOS 2.0 section 7.2): every
 * verifier rejects such a receipt, so it is not written. `level` is the
 * depth of `value` itself, for the recursion.
 */
export function sortKeysDeep(value: unknown, level = 1): unknown {
  if (value === null || typeof value !== "object") return value;
  if (level > MAX_NESTING) {
    throw new Error(`canonical JSON: nesting deeper than ${MAX_NESTING}`);
  }
  if (Array.isArray(value)) return value.map((item) => sortKeysDeep(item, level + 1));
  // A null-prototype object keeps a "__proto__" key as an ordinary
  // field; on a plain object the assignment would set the prototype
  // and drop the key.
  const sorted = Object.create(null) as Record<string, unknown>;
  for (const key of Object.keys(value).sort()) {
    sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key], level + 1);
  }
  return sorted;
}

/** `JSON.stringify` of `sortKeysDeep(value)`; throws as `sortKeysDeep` does. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}
