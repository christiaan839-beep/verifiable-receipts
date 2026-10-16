/**
 * Writes a Guardian attestation signed by the TypeScript runGuardian:
 * two rules, one passing and one warning with a reason and evidence, so
 * the attestation carries the fields its canonical does not sign
 * (totalMs, each rule's durationMs and evidence).
 *
 * Needs the built package: run `npm install` in packages/verifiable-receipts.
 *
 * Usage: node guardian.mjs <ed25519-private.pem> <out.json>
 */
import { createPrivateKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { runGuardian } from "../../dist/index.js";

const [keyPath, outPath] = process.argv.slice(2);
if (!keyPath || !outPath) {
  process.stderr.write("usage: node guardian.mjs <ed25519-private.pem> <out.json>\n");
  process.exit(2);
}
const key = createPrivateKey(readFileSync(keyPath, "utf8"));

const rules = [
  {
    id: "roundtrip-no-ssn",
    description: "Output holds no US Social Security number.",
    evaluate: async () => ({ verdict: "pass" }),
  },
  {
    id: "roundtrip-disclosure",
    description: "Output tells the reader an AI wrote it.",
    evaluate: async () => ({
      verdict: "warn",
      reason: "AI disclosure missing",
      evidence: { field: "output.text" },
    }),
  },
];

const attestation = await runGuardian(
  rules,
  {
    runId: "run_roundtrip_001",
    agentSlug: "loan-underwriter",
    tokenId: "tok_roundtrip",
    input: { prompt: "Résumé check" },
    output: { text: "Approved." },
  },
  (canonical) =>
    `v2=${sign(null, Buffer.from(canonical, "utf8"), key).toString("base64")}`,
);
writeFileSync(outPath, JSON.stringify(attestation, null, 2) + "\n");
