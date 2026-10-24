/**
 * The nesting limit of VAOS 2.0 section 7.2: no receipt, canonical or other
 * signed JSON value nests deeper than 64. Not exported from the package.
 */

/** The deepest a signed JSON value may nest (VAOS 2.0 section 7.2). */
export const MAX_NESTING = 64;

/**
 * Whether `value` nests deeper than `limit`: an array or object is one
 * level, and each array or object inside it one more. Walks an explicit
 * stack, so no depth of input overflows the call stack.
 */
export function nestsDeeperThan(value: unknown, limit: number = MAX_NESTING): boolean {
  const stack: Array<[unknown, number]> = [[value, 1]];
  while (stack.length > 0) {
    const [v, level] = stack.pop() as [unknown, number];
    if (v === null || typeof v !== "object") continue;
    if (level > limit) return true;
    for (const child of Array.isArray(v) ? v : Object.values(v)) {
      if (child !== null && typeof child === "object") stack.push([child, level + 1]);
    }
  }
  return false;
}
