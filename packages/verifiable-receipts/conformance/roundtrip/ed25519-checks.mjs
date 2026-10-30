/**
 * Runs the Ed25519 fixtures through the TypeScript pre-checks.
 *
 * Usage: node ed25519-checks.mjs <fixtures-dir>
 * For each fixtures/ed25519-*.json, in name order, prints one line:
 * "<name>\t<key reason>\t<signature reason>", with "none" for no
 * problem, from ed25519PublicKeyProblem and ed25519SignatureProblem. The
 * round trip checks that Python and Go print the same lines.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { ed25519PublicKeyProblem, ed25519SignatureProblem } from "../../dist/index.js";

const dir = process.argv[2];
if (!dir || process.argv.length !== 3) {
  process.stderr.write("usage: node ed25519-checks.mjs <fixtures-dir>\n");
  process.exit(2);
}
const names = readdirSync(dir)
  .filter((f) => f.startsWith("ed25519-") && f.endsWith(".json"))
  .sort();
for (const name of names) {
  const fixture = JSON.parse(readFileSync(join(dir, name), "utf8"));
  let raw;
  let sig;
  if (fixture.ed25519) {
    raw = Buffer.from(fixture.ed25519.publicKey, "hex");
    sig = Buffer.from(fixture.ed25519.signature, "hex");
  } else {
    const spki = Buffer.from(fixture.publicKeyPem.replace(/-----[^-]+-----|\s/g, ""), "base64");
    raw = spki.subarray(spki.length - 32); // SPKI: a 12-byte prefix, then the key
    sig = Buffer.from(fixture.receipt.signature.slice("v2=".length), "base64");
  }
  const key = ed25519PublicKeyProblem(raw) ?? "none";
  const signature = ed25519SignatureProblem(sig) ?? "none";
  console.log(`${name.slice(0, -".json".length)}\t${key}\t${signature}`);
}
