#!/usr/bin/env node
/**
 * verifiable-receipts CLI — bin/verify.mjs
 *
 * Verifies a signed bundle manifest (MANIFEST.signed.json) against an
 * Ed25519 public key. No network calls. It checks the manifest hash
 * and signature; it does not open the ZIP or check each receipt.
 *
 * Usage:
 *
 *   # Verify a signed manifest JSON file
 *   npx verifiable-receipts verify \
 *     --manifest ./MANIFEST.signed.json \
 *     --pubkey ./ed25519-public.pem
 *
 *   # Same flow piped from stdin
 *   cat MANIFEST.signed.json | npx verifiable-receipts \
 *     verify --pubkey ./ed25519-public.pem
 *
 *   # Exit codes:
 *   #   0 — manifest is intact and signature verifies
 *   #   1 — verification failed (reason printed)
 *   #   2 — usage error (bad flags, missing file, malformed JSON)
 */

import { readFileSync } from "node:fs";
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { verifyManifest } from "../dist/index.js";

function fail(message, code = 2) {
  process.stderr.write(`error: ${message}\n`);
  process.exit(code);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (!tok.startsWith("--")) continue;
    const body = tok.slice(2);
    const eq = body.indexOf("=");
    if (eq >= 0) {
      out[body.slice(0, eq)] = body.slice(eq + 1);
    } else {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) {
        out[body] = "true";
      } else {
        out[body] = next;
        i++;
      }
    }
  }
  return out;
}

function printHelp() {
  process.stdout.write(
    [
      "verifiable-receipts verify",
      "",
      "Usage:",
      "  verifiable-receipts verify --manifest <path> --pubkey <path>",
      "  verifiable-receipts verify --pubkey <path>          # manifest read from stdin",
      "",
      "Flags:",
      "  --manifest <path>   Path to a MANIFEST.signed.json file",
      "  --pubkey <path>     Path to an Ed25519 public key (PEM)",
      "  --json              Emit a JSON envelope on success/failure",
      "",
      "Checks the manifest hash and an Ed25519 v2= signature. It does not",
      "open the ZIP or check each receipt, and it refuses v3= manifests.",
      "  --help              This message",
      "",
      "Exit codes:",
      "  0  Manifest is intact and signature verifies",
      "  1  Verification failed",
      "  2  Usage error",
      "",
    ].join("\n"),
  );
}

async function readStdin() {
  let data = "";
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    printHelp();
    process.exit(0);
  }
  if (cmd !== "verify") {
    fail(`unknown subcommand: ${cmd} (try 'verify' or 'help')`);
  }

  const flags = parseArgs(argv.slice(1));
  if (!flags.pubkey) fail("--pubkey is required");

  // Pubkey: support PEM only for now. Base64-encoded raw key support
  // can land in a follow-up; PEM is what /.well-known/sovereign-receipts/
  // already serves so it's the canonical input shape.
  let pemBytes;
  try {
    pemBytes = readFileSync(flags.pubkey, "utf8");
  } catch (err) {
    fail(`could not read --pubkey: ${err.message}`);
  }
  let pubKey;
  try {
    pubKey = createPublicKey({ key: pemBytes, format: "pem" });
  } catch (err) {
    fail(`--pubkey is not a valid PEM public key: ${err.message}`);
  }

  // Manifest: from --manifest flag or stdin.
  let raw;
  if (flags.manifest) {
    try {
      raw = readFileSync(flags.manifest, "utf8");
    } catch (err) {
      fail(`could not read --manifest: ${err.message}`);
    }
  } else if (!process.stdin.isTTY) {
    raw = await readStdin();
    if (!raw.trim()) fail("no manifest data on stdin");
  } else {
    fail("--manifest <path> required (or pipe manifest JSON via stdin)");
  }

  let manifest;
  try {
    manifest = JSON.parse(raw);
  } catch (err) {
    fail(`manifest JSON parse failed: ${err.message}`);
  }

  // verifyManifest() takes a `verify(canonical, signature) => bool`
  // callback. This CLI checks Ed25519 `v2=` signatures only. A `v3=`
  // manifest is refused rather than passed on its Ed25519 half alone,
  // which would drop the ML-DSA-65 check; verify those with
  // verifyDualSig() from the library.
  const sigStr = String(manifest?.signature ?? "");
  if (sigStr.startsWith("v3=")) {
    fail("v3= manifests are not supported by this CLI; verify them with verifyDualSig()");
  }
  const verifyFn = (canonical, signature) => {
    try {
      const s = String(signature ?? "");
      if (!s.startsWith("v2=")) return false;
      const sig = Buffer.from(s.slice(3), "base64");
      if (sig.toString("base64") !== s.slice(3)) return false;
      return nodeVerify(null, Buffer.from(canonical, "utf8"), pubKey, sig);
    } catch {
      return false;
    }
  };

  const result = verifyManifest(manifest, verifyFn);
  const emitJson = flags.json === "true";

  if (result.ok) {
    if (emitJson) {
      process.stdout.write(
        JSON.stringify({
          ok: true,
          receiptCount: manifest.receiptCount,
          bundleDigest: manifest.bundleDigest,
          manifestHash: manifest.manifestHash,
          generatedAt: manifest.generatedAt,
        }) + "\n",
      );
    } else {
      process.stdout.write(
        [
          "✓ MANIFEST VERIFIED",
          "",
          `  receipts:       ${manifest.receiptCount}`,
          `  bundle digest:  ${manifest.bundleDigest}`,
          `  manifest hash:  ${manifest.manifestHash}`,
          `  generated at:   ${manifest.generatedAt}`,
          "",
        ].join("\n"),
      );
    }
    process.exit(0);
  }

  // Verification failed — surface the reason cleanly.
  if (emitJson) {
    process.stdout.write(
      JSON.stringify({ ok: false, reason: result.reason }) + "\n",
    );
  } else {
    process.stdout.write(
      [
        "✗ MANIFEST VERIFICATION FAILED",
        "",
        `  reason: ${result.reason}`,
        "",
        "  hash-mismatch       The recomputed manifestHash differs from the stored value.",
        "                      Likely tampering or a transcription error.",
        "  signature-mismatch  The signature does not match the stored manifestHash under",
        "                      the supplied public key. Wrong key or forged signature.",
        "  wrong-type          File is not a verifiable-receipt-bundle manifest.",
        "  wrong-version       Manifest version is unsupported by this CLI.",
        "",
      ].join("\n"),
    );
  }
  process.exit(1);
}

main().catch((err) => fail(err?.message ?? String(err)));
