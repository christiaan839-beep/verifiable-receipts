/**
 * Verifies a receipt or Guardian attestation with node:crypto.
 *
 * A receipt goes through the conformance corpus's v2 verifier
 * (../verify-v2.mjs); a Guardian attestation through the TypeScript
 * package's verifyGuardianAttestation, with node:crypto's Ed25519.
 *
 * Usage: node verify.mjs <ed25519-public.pem> <receipt|guardian> <file.json>
 * Prints "ok" and exits 0, or prints "rejected: <reason>" and exits 1.
 */
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { verifyV2Receipt } from "../verify-v2.mjs";
import { verifyGuardianAttestation } from "../../dist/index.js";

const [keyPath, kind, path] = process.argv.slice(2);
if (!keyPath || !path || (kind !== "receipt" && kind !== "guardian")) {
  process.stderr.write(
    "usage: node verify.mjs <ed25519-public.pem> <receipt|guardian> <file.json>\n",
  );
  process.exit(2);
}
const publicKey = createPublicKey(readFileSync(keyPath, "utf8"));
const receipt = JSON.parse(readFileSync(path, "utf8"));

const verdict =
  kind === "receipt"
    ? verifyV2Receipt(receipt, publicKey)
    : verifyGuardianAttestation(receipt, (canonical, signature) => {
        if (!signature.startsWith("v2=")) return false;
        return verify(
          null,
          Buffer.from(canonical, "utf8"),
          publicKey,
          Buffer.from(signature.slice(3), "base64"),
        );
      });

if (verdict.ok) {
  console.log("ok");
} else {
  console.log(`rejected: ${verdict.reason}`);
  process.exit(1);
}
