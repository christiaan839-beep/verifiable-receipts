/**
 * Judges every case in cases.jsonl with the TypeScript verifiers: receipts
 * with the conformance v2 verifier (../verify-v2.mjs), Guardian
 * attestations with verifyGuardianAttestation and inclusion proofs with
 * verifyInclusionProof from the built package.
 *
 * Usage: node verify.mjs <public.pem> <cases.jsonl> <out.jsonl>
 * Writes one {"id", "ok", "reason"} line per case, in case order ("parse
 * failed" when the text does not parse); "threw" records an exception,
 * which the verifiers must never raise. Cases are read a line at a time
 * and verdicts written in batches, so memory does not grow with the
 * number of cases.
 */
import { createPublicKey } from "node:crypto";
import { closeSync, createReadStream, openSync, readFileSync, writeSync } from "node:fs";
import { createInterface } from "node:readline";
import { parseReceipt, verifyV2Receipt } from "../verify-v2.mjs";
import { verifyInclusionProof } from "../../dist/transparency.js";
import { verifyGuardianAttestation } from "../../dist/guardian.js";
import { verifyEd25519 } from "../../dist/ed25519-key.js";

const TOO_DEEP = "receipt nesting deeper than 64";
const BATCH = 1000; // verdicts per write

function judge({ id, kind, raw, pem }, runKey) {
  // An Ed25519 edge case carries its own key.
  let publicKey = runKey;
  if (pem !== undefined) {
    try {
      publicKey = createPublicKey(pem);
    } catch (err) {
      return { id, ok: false, threw: `key: ${String(err)}` };
    }
  }
  let value;
  try {
    // A receipt or attestation is read as Python's parse_receipt and Go's
    // ParseReceipt read it: its depth counted on the text first.
    value = kind === "inclusion" ? JSON.parse(raw) : parseReceipt(raw);
  } catch (err) {
    const reason = err instanceof Error && err.message === TOO_DEEP ? TOO_DEEP : "parse failed";
    return { id, ok: false, reason };
  }
  try {
    if (kind === "receipt") {
      const { ok, reason } = verifyV2Receipt(value, publicKey);
      return { id, ok, reason: reason ?? null };
    }
    if (kind === "guardian") {
      // The library verifier names its reasons differently ("nesting-too-deep"),
      // so compare.py compares only its verdict.
      const { ok, reason } = verifyGuardianAttestation(value, (canonical, signature) =>
        signature.startsWith("v2=") &&
        verifyEd25519(publicKey, Buffer.from(canonical, "utf8"), Buffer.from(signature.slice(3), "base64")).ok,
      );
      return { id, ok, reason: reason ?? null };
    }
    const ok = verifyInclusionProof(value.leafHashHex, value.leafIndex, value.treeSize, value.auditPath, value.rootHashHex);
    return { id, ok, reason: null };
  } catch (err) {
    return { id, ok: false, threw: String(err) };
  }
}

function writeAll(fd, text) {
  const bytes = Buffer.from(text, "utf8");
  for (let off = 0; off < bytes.length; ) off += writeSync(fd, bytes, off);
}

const [keyPath, casesPath, outPath] = process.argv.slice(2);
const publicKey = createPublicKey(readFileSync(keyPath, "utf8"));
const out = openSync(outPath, "w");
const lines = createInterface({ input: createReadStream(casesPath, "utf8"), crlfDelay: Infinity });
let batch = "";
let pending = 0;
for await (const line of lines) {
  if (line === "") continue;
  batch += JSON.stringify(judge(JSON.parse(line), publicKey)) + "\n";
  if (++pending === BATCH) {
    writeAll(out, batch);
    batch = "";
    pending = 0;
  }
}
writeAll(out, batch);
closeSync(out);
