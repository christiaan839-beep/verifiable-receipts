#!/usr/bin/env node
/**
 * verifiable-receipts sign CLI — bin/sign.mjs
 *
 * Sign a receipt (VAOS 2.0 `v2=` or VAOS 3.0 `v3=`) from a JSON
 * object. One-shot, no network calls.
 *
 * Usage:
 *
 *   # Sign a receipt body from a JSON file
 *   npx verifiable-receipts-sign \
 *     --input ./receipt-body.json \
 *     --key ./ed25519-private.pem \
 *     --out ./signed-receipt.json
 *
 *   # Or pipe via stdin
 *   cat receipt-body.json | npx verifiable-receipts-sign \
 *     --key ./ed25519-private.pem
 *
 *   # Dual-sign with Ed25519 and ML-DSA-65 (v3=)
 *   npx verifiable-receipts-sign \
 *     --input ./receipt-body.json \
 *     --key ./ed25519-private.pem \
 *     --mldsa-key ./mldsa65-secret.b64 \
 *     --out ./signed-receipt-v3.json
 *
 * Input shape: any JSON object. The CLI removes the `canonical`,
 * `contentHash` and `signature` fields if present, canonicalizes the
 * rest per VAOS §5, and signs.
 *
 * Output: the body's fields, plus
 *   - `canonical`: the exact string that was signed;
 *   - `contentHash`: `sha256:` + hex SHA-256 of its UTF-8 bytes;
 *   - `signature`: `v2=<base64-ed25519>` or
 *     `v3=<base64-ed25519>.<base64-mldsa65>`.
 * The Python and Go verifiers check a `v2=` receipt in this shape: the
 * signature over `canonical`, and every other field against it.
 *
 * Exit codes:
 *   0  Signed successfully
 *   2  Usage error (bad flags, missing file, malformed input)
 */

import { readFileSync, writeFileSync } from "node:fs";
import {
  createHash,
  createPrivateKey,
  sign as edSign,
} from "node:crypto";
import { canonicalJson } from "../dist/canonical-json.js";
import { formatV3Wire, signMlDsa65 } from "../dist/pq-sign.js";
import { fail, parseArgs, readStdin } from "./cli.mjs";

function printHelp() {
  process.stdout.write(
    [
      "verifiable-receipts-sign",
      "",
      "Sign a JSON object as a v2= or v3= receipt. No network calls.",
      "",
      "Usage:",
      "  verifiable-receipts-sign --input <path> --key <ed25519.pem> [flags]",
      "  cat body.json | verifiable-receipts-sign --key <ed25519.pem>",
      "",
      "Required:",
      "  --key <path>          Path to Ed25519 private key (PEM)",
      "",
      "Optional:",
      "  --input <path>        JSON receipt body (omit to read stdin)",
      "  --out <path>          Output file (omit to write to stdout)",
      "  --mldsa-key <path>    ML-DSA-65 secret key, base64-encoded, for v3 dual-sign",
      "  --json                Always emit a single line of JSON to stdout (no pretty-print)",
      "  --help                This message",
      "",
      "Exit codes:",
      "  0  Signed",
      "  2  Usage error",
      "",
      "VAOS canonical projection (deterministic input to the signer):",
      "  • Remove the `canonical`, `contentHash` and `signature` fields if present.",
      "  • Sort object keys lexicographically at every depth.",
      "  • JSON-stringify with no whitespace.",
      "  • Sign the UTF-8 bytes with Ed25519 per RFC 8032.",
      "  • Wire prefix: `v2=` (Ed25519) or `v3=` (Ed25519 + ML-DSA-65).",
      "",
      "Output: the body's fields plus `canonical` (the signed string),",
      "`contentHash` (sha256: + hex of it) and `signature`.",
      "",
    ].join("\n"),
  );
}

/** FIPS 204 ML-DSA-65 secret key length in bytes. */
const ML_DSA65_SECRET_KEY_BYTES = 4032;

// Fields the signer writes; a body's own copies are dropped first.
const SIGNER_FIELDS = ["canonical", "contentHash", "signature"];

function withoutSignerFields(receiptBody) {
  const copy = { ...receiptBody };
  for (const k of SIGNER_FIELDS) delete copy[k];
  return copy;
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === "help" || argv.includes("--help") || argv.includes("-h")) {
    printHelp();
    process.exit(0);
  }
  const flags = parseArgs(argv);
  if (!flags.key) fail("--key is required (Ed25519 PEM)");

  let rawInput;
  if (flags.input) {
    try {
      rawInput = readFileSync(flags.input, "utf8");
    } catch (err) {
      fail(`could not read --input: ${err.message}`);
    }
  } else if (!process.stdin.isTTY) {
    rawInput = await readStdin();
    if (!rawInput.trim()) fail("no input on stdin");
  } else {
    fail("--input <path> required (or pipe JSON via stdin)");
  }

  let body;
  try {
    body = JSON.parse(rawInput);
  } catch (err) {
    fail(`input is not valid JSON: ${err.message}`);
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    fail("input must be a JSON object");
  }

  let edPrivKey;
  try {
    const pem = readFileSync(flags.key, "utf8");
    edPrivKey = createPrivateKey({ key: pem, format: "pem" });
  } catch (err) {
    fail(`could not load --key: ${err.message}`);
  }

  let mldsaSecret = null;
  if (flags["mldsa-key"]) {
    try {
      const b64 = readFileSync(flags["mldsa-key"], "utf8").trim();
      mldsaSecret = Buffer.from(b64, "base64");
    } catch (err) {
      fail(`could not load --mldsa-key: ${err.message}`);
    }
    if (mldsaSecret.length !== ML_DSA65_SECRET_KEY_BYTES) {
      fail(
        `--mldsa-key must hold a ${ML_DSA65_SECRET_KEY_BYTES}-byte ML-DSA-65 secret key, got ${mldsaSecret.length} bytes`,
      );
    }
  }

  const fields = withoutSignerFields(body);
  let canonical;
  try {
    canonical = canonicalJson(fields);
  } catch (err) {
    fail(`could not canonicalize the receipt: ${err.message}`);
  }
  const canonicalBytes = Buffer.from(canonical, "utf8");
  const contentHash =
    "sha256:" + createHash("sha256").update(canonicalBytes).digest("hex");
  const edSigBytes = edSign(null, canonicalBytes, edPrivKey);
  const edB64 = edSigBytes.toString("base64");

  const wire = mldsaSecret
    ? formatV3Wire(edB64, signMlDsa65(canonical, mldsaSecret))
    : `v2=${edB64}`;

  const signedReceipt = { ...fields, canonical, contentHash, signature: wire };
  const out =
    flags.json === "true"
      ? JSON.stringify(signedReceipt)
      : JSON.stringify(signedReceipt, null, 2);

  if (flags.out) {
    writeFileSync(flags.out, out + "\n");
    process.stderr.write(
      `[sign] wrote ${signedReceipt.signature.slice(0, 24)}… to ${flags.out}\n`,
    );
  } else {
    process.stdout.write(out + "\n");
  }
  process.exit(0);
}

main().catch((err) => fail(err?.message ?? String(err)));
