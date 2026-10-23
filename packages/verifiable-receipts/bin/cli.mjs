/**
 * Argument parsing, error exit and stdin reading shared by the three
 * CLIs in this directory.
 */

/** Print `error: <message>` to stderr and exit with `code` (2, usage error, by default). */
export function fail(message, code = 2) {
  process.stderr.write(`error: ${message}\n`);
  process.exit(code);
}

/**
 * Read `--name value`, `--name=value` and bare `--name` (as "true") into
 * an object keyed by name. Arguments that do not start with `--` are
 * skipped.
 */
export function parseArgs(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const name = arg.slice(2);
    const eq = name.indexOf("=");
    if (eq >= 0) {
      flags[name.slice(0, eq)] = name.slice(eq + 1);
    } else {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) {
        flags[name] = "true";
      } else {
        flags[name] = next;
        i++;
      }
    }
  }
  return flags;
}

/** All of stdin as one string. */
export async function readStdin() {
  let text = "";
  for await (const chunk of process.stdin) text += chunk;
  return text;
}
