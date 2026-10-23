/**
 * JSON with object keys sorted at every depth (UTF-16 code-unit order,
 * as `Array.prototype.sort` orders strings) and no whitespace: the
 * canonical projection of VAOS 2.0 §5, also used for bundle manifests.
 * Not exported from the package; `bin/sign.mjs` imports it from `dist/`.
 */

/** A copy of `value` whose objects have their keys in sorted order. */
export function sortKeysDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  // A null-prototype object keeps a "__proto__" key as an ordinary
  // field; on a plain object the assignment would set the prototype
  // and drop the key.
  const sorted = Object.create(null) as Record<string, unknown>;
  for (const key of Object.keys(value).sort()) {
    sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
  }
  return sorted;
}

/** `JSON.stringify` of `sortKeysDeep(value)`. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}
