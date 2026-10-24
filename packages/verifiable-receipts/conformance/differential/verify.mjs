/**
 * Judges every case in cases.jsonl with the TypeScript verifiers: receipts
 * with the conformance v2 verifier (../verify-v2.mjs), Guardian
 * attestations with verifyGuardianAttestation and inclusion proofs with
 * verifyInclusionProof from the built package.
 *
 * Usage: node verify.mjs <public.pem> <cases.jsonl> <out.jsonl>
 * Writes one {"id", "ok", "reason"} line per case ("parse failed" when the
 * text does not parse); "threw" records an exception,
 * which the verifiers must never raise.
 */
import { createPublicKey, verify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { verifyV2Receipt } from "../verify-v2.mjs";
import { verifyInclusionProof } from "../../dist/transparency.js";
import { verifyGuardianAttestation } from "../../dist/guardian.js";

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
    verdicts.push({ id, ok: false, reason: "parse failed" });
    continue;
  }
  if (kind !== "inclusion" && (value === null || typeof value !== "object" || Array.isArray(value))) {
    // Go and Python read a receipt into an object type; anything else fails to parse.
    verdicts.push({ id, ok: false, reason: "parse failed" });
    continue;
  }
  try {
    if (kind === "receipt") {
      const { ok, reason } = verifyV2Receipt(value, publicKey);
      verdicts.push({ id, ok, reason: reason ?? null });
    } else if (kind === "guardian") {
      // The library verifier names its reasons differently ("nesting-too-deep"),
      // so compare.py compares only its verdict.
      const { ok, reason } = verifyGuardianAttestation(value, (canonical, signature) =>
        signature.startsWith("v2=") &&
        verify(null, Buffer.from(canonical, "utf8"), publicKey, Buffer.from(signature.slice(3), "base64")),
      );
      verdicts.push({ id, ok, reason: reason ?? null });
    } else {
      const ok = verifyInclusionProof(value.leafHashHex, value.leafIndex, value.treeSize, value.auditPath, value.rootHashHex);
      verdicts.push({ id, ok, reason: null });
    }
  } catch (err) {
    verdicts.push({ id, ok: false, threw: String(err) });
  }
}
writeFileSync(outPath, verdicts.map((v) => JSON.stringify(v)).join("\n") + "\n");
