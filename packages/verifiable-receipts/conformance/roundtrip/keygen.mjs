/**
 * Writes a fresh Ed25519 key pair for one round-trip run:
 * <dir>/ed25519-private.pem (PKCS#8) and <dir>/ed25519-public.pem (SPKI).
 * The driver deletes <dir> when it finishes; no key is kept.
 *
 * Usage: node keygen.mjs <dir>
 */
import { generateKeyPairSync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2];
if (!dir) {
  process.stderr.write("usage: node keygen.mjs <dir>\n");
  process.exit(2);
}
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
writeFileSync(
  join(dir, "ed25519-private.pem"),
  privateKey.export({ type: "pkcs8", format: "pem" }),
  { mode: 0o600 },
);
writeFileSync(
  join(dir, "ed25519-public.pem"),
  publicKey.export({ type: "spki", format: "pem" }),
);
