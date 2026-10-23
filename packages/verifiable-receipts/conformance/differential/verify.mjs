/**
 * Judges every case in cases.jsonl with the TypeScript verifiers: receipts
 * with the conformance v2 verifier (../verify-v2.mjs), inclusion proofs
 * with verifyInclusionProof from the built package.
 *
 * Usage: node verify.mjs <public.pem> <cases.jsonl> <out.jsonl>
 * Writes one {"id", "ok"} line per case; "threw" records an exception,
 * which the verifiers must never raise.
 */
import { createPublicKey } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { verifyV2Receipt } from "../verify-v2.mjs";
import { verifyInclusionProof } from "../../dist/transparency.js";

const [keyPath, casesPath, outPath] = process.argv.slice(2);
const publicKey = createPublicKey(readFileSync(keyPath, "utf8"));
const verdicts = [];
for (const line of readFileSync(casesPath, "utf8").split("\n")) {
  if (line === "") continue;
  const { id, kind, raw } = JSON.parse(line);
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    verdicts.push({ id, ok: false });
    continue;
  }
  try {
    const ok =
      kind === "receipt"
        ? verifyV2Receipt(value, publicKey).ok
        : verifyInclusionProof(value.leafHashHex, value.leafIndex, value.treeSize, value.auditPath, value.rootHashHex);
    verdicts.push({ id, ok });
  } catch (err) {
    verdicts.push({ id, ok: false, threw: String(err) });
  }
}
writeFileSync(outPath, verdicts.map((v) => JSON.stringify(v)).join("\n") + "\n");
