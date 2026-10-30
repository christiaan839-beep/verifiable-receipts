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
import { loadEd25519PublicKey, verifyEd25519, verifyManifest } from "../dist/index.js";
import { textNestsDeeperThan } from "../dist/nesting.js";
import { fail, parseArgs, readStdin } from "./cli.mjs";

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
      "  --help              This message",
      "",
      "Checks the manifest hash and an Ed25519 v2= signature. It does not",
      "open the ZIP or check each receipt, and it refuses v3= manifests.",
      "",
      "Exit codes:",
      "  0  Manifest is intact and signature verifies",
      "  1  Verification failed",
      "  2  Usage error",
      "",
    ].join("\n"),
  );
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

  // PEM, the format VAOS 2.0 §6.3 publishes the issuer key in.
  let pemBytes;
  try {
    pemBytes = readFileSync(flags.pubkey, "utf8");
  } catch (err) {
    fail(`could not read --pubkey: ${err.message}`);
  }
  let pubKey;
  try {
    pubKey = loadEd25519PublicKey(pemBytes);
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

  // Depth is counted on the text before it is parsed (VAOS 2.0 §7.2), so
  // a duplicate key that JSON.parse would discard still counts.
  const tooDeep = textNestsDeeperThan(raw);
  let manifest;
  try {
    manifest = tooDeep ? {} : JSON.parse(raw);
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
      // The strict profile of VAOS 2.0 section 7.3: R and S are checked
      // before node:crypto sees the signature.
      return verifyEd25519(pubKey, Buffer.from(canonical, "utf8"), sig).ok;
    } catch {
      return false;
    }
  };

  const verdict = tooDeep
    ? { ok: false, reason: "nesting-too-deep" }
    : verifyManifest(manifest, verifyFn);
  const emitJson = flags.json === "true";

  if (verdict.ok) {
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

  if (emitJson) {
    process.stdout.write(
      JSON.stringify({ ok: false, reason: verdict.reason }) + "\n",
    );
  } else {
    process.stdout.write(
      [
        "✗ MANIFEST VERIFICATION FAILED",
        "",
        `  reason: ${verdict.reason}`,
        "",
        "  hash-mismatch       The recomputed manifestHash differs from the stored value.",
        "                      Likely tampering or a transcription error.",
        "  signature-mismatch  The signature does not match the stored manifestHash under",
        "                      the supplied public key. Wrong key or forged signature.",
        "  wrong-type          File is not a verifiable-receipt-bundle manifest.",
        "  wrong-version       Manifest version is unsupported by this CLI.",
        "  nesting-too-deep    The manifest nests deeper than 64 (VAOS 2.0 §7.2).",
        "",
      ].join("\n"),
    );
  }
  process.exit(1);
}

main().catch((err) => fail(err?.message ?? String(err)));
