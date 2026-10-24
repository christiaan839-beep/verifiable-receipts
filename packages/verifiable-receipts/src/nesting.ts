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

/**
 * Whether JSON text opens more than `limit` arrays and objects at once,
 * read from the start, valid JSON or not (VAOS 2.0 section 7.2): outside
 * strings `[` and `{` open one and `]` and `}` close one (when one is
 * open); a string runs from `"` to the next `"`, and a `\` inside it
 * escapes the character after it. The same count as the conformance
 * verifier's `textNestsTooDeep`.
 */
export function textNestsDeeperThan(text: string, limit: number = MAX_NESTING): boolean {
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
      if (++open > limit) return true;
    } else if ((c === "]" || c === "}") && open > 0) {
      open--;
    }
  }
  return false;
}
