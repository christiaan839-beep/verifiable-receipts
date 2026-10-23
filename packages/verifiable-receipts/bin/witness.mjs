#!/usr/bin/env node
/**
 * verifiable-receipts witness CLI — bin/witness.mjs
 *
 * Polls a transparency log endpoint, checks the tree head it serves,
 * verifies consistency since the last witnessed STH, signs the
 * canonical bytes with the operator's Ed25519 key, and submits the
 * cosignature to /api/transparency/witness.
 *
 * Before it signs, the witness checks (docs/specs/transparency-log.md
 * sections 3.3, 3.6 and 5):
 *   - every field has its one valid spelling (v 1, a non-empty logId,
 *     a 64-lowercase-hex rootHash, an integer treeSize from 0 to
 *     2^53 - 1, a toISOString timestamp, a canonical v2=/v3= signature);
 *   - `canonical` is exactly canonicalizeSth() of those fields. The
 *     witness signs the canonical it rebuilt, so it cosigns only the
 *     head it checked;
 *   - the logId is the one in its state file;
 *   - a head at the size it last signed has the same root;
 *   - with --log-public-key, the log's v2= signature over the canonical.
 *
 * Usage:
 *
 *   # One-shot: check once and exit
 *   npx verifiable-receipts-witness \
 *     --url https://log.example \
 *     --key ./witness-ed25519.pem \
 *     --witness-id "example-witness" \
 *     --public-key-url https://eu-witness.example/key.pem \
 *     --log-public-key ./log-ed25519.pub.pem \
 *     --once
 *
 *   # Daemon: poll every N seconds (default: 3600)
 *   npx verifiable-receipts-witness \
 *     --url https://log.example \
 *     --key ./witness-ed25519.pem \
 *     --witness-id "example-witness" \
 *     --interval 3600
 *
 * State file at ~/.sovereign-witness/<sanitized-witness-id>.json:
 *   { logId, lastSize, lastRoot, lastTimestamp, lastSubmittedAt }
 * A state file without logId (written by an earlier version) still
 * loads; the logId is added the next time the state is saved. A state
 * file that exists but cannot be read or parsed, or whose fields are
 * malformed, is refused (exit 2) rather than treated as absent.
 *
 * Exit codes (--once mode):
 *   0  Witnessed successfully OR no change since last poll
 *   1  The log misbehaved: fork or rewrite, a canonical that does not
 *      match the fields, another logId, or a bad log signature.
 *      Operator MUST investigate
 *   2  Usage error (bad flags, network failure, malformed STH, a bad
 *      state file, a v3= STH with --log-public-key)
 */

import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
} from "node:fs";
import {
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import { canonicalizeSth, verifyConsistencyProof } from "../dist/transparency.js";
import { isHashHex } from "../dist/hash.js";
import { fail, parseArgs } from "./cli.mjs";

function printHelp() {
  process.stdout.write(
    [
      "verifiable-receipts-witness",
      "",
      "Polls a transparency log STH, verifies append-only consistency since",
      "the last witnessed STH, signs the canonical bytes, and submits the",
      "cosignature back. Run as a daemon (--interval) or one-shot (--once).",
      "",
      "Usage:",
      "  verifiable-receipts-witness --url <base> --key <pem> --witness-id <name> [flags]",
      "",
      "Required:",
      "  --url <base>          Transparency log base URL (e.g. https://log.example)",
      "  --key <path>          Path to your Ed25519 private key (PEM)",
      "  --witness-id <name>   Display name for your witness",
      "",
      "Optional:",
      "  --public-key-url <url>  URL where you publish your witness public key",
      "  --log-public-key <path> The log's Ed25519 public key (PEM). When given,",
      "                          the log's v2= STH signature must verify before",
      "                          the witness cosigns; a v3= STH is refused.",
      "                          Without it the log signature is not checked.",
      "  --interval <sec>        Daemon poll interval (default 3600)",
      "  --once                  Single check + exit (don't loop)",
      "  --state <path>          Override state file location",
      "  --json                  Emit JSON envelope per check",
      "  --help                  This message",
      "",
      "Exit codes (--once):",
      "  0  Witnessed OR no change",
      "  1  The log misbehaved: fork / rewrite, canonical not matching its",
      "     fields, another logId, bad log signature (do NOT auto-recover;",
      "     investigate)",
      "  2  Usage error, network failure, malformed STH, a bad state file,",
      "     or a v3= STH with --log-public-key",
      "",
    ].join("\n"),
  );
}

function safeFileName(s) {
  return s.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 100);
}

function defaultStatePath(witnessId) {
  const dir = join(homedir(), ".sovereign-witness");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return join(dir, safeFileName(witnessId) + ".json");
}

/** A state file that exists but cannot be trusted. */
class BadStateError extends Error {}

/** Why `state` is not a usable state file, or null when it is. */
function stateShapeError(state) {
  if (typeof state !== "object" || state === null || Array.isArray(state)) {
    return "not a JSON object";
  }
  if (!Number.isSafeInteger(state.lastSize) || state.lastSize < 0) {
    return "lastSize must be an integer from 0 to 2^53 - 1";
  }
  if (!isHashHex(state.lastRoot)) {
    return "lastRoot must be 64 lowercase hex digits";
  }
  // Absent in files written before logId was saved; those still load.
  if (
    state.logId !== undefined &&
    (typeof state.logId !== "string" || state.logId.length === 0)
  ) {
    return "logId, when present, must be a non-empty string";
  }
  return null;
}

/**
 * The saved state, or null when there is no state file (a first-time
 * witness). A file that exists but cannot be read, parsed or trusted
 * throws BadStateError: treating it as absent would let the log start
 * the witness over from any tree head it likes.
 */
function loadState(path) {
  if (!existsSync(path)) return null;
  let state;
  try {
    state = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new BadStateError(`cannot read or parse ${path}: ${err.message}`);
  }
  const problem = stateShapeError(state);
  if (problem) throw new BadStateError(`${path}: ${problem}`);
  return state;
}

function saveState(path, state) {
  writeFileSync(path, JSON.stringify(state, null, 2), { mode: 0o600 });
}

function loadPrivateKey(keyPath) {
  let pem;
  try {
    pem = readFileSync(keyPath, "utf8");
  } catch (err) {
    fail(`could not read --key: ${err.message}`);
  }
  try {
    return createPrivateKey({ key: pem, format: "pem" });
  } catch (err) {
    fail(`--key is not a valid PEM private key: ${err.message}`);
  }
}

function loadLogPublicKey(keyPath) {
  let pem;
  try {
    pem = readFileSync(keyPath, "utf8");
  } catch (err) {
    fail(`could not read --log-public-key: ${err.message}`);
  }
  let key;
  try {
    key = createPublicKey({ key: pem, format: "pem" });
  } catch (err) {
    fail(`--log-public-key is not a valid PEM public key: ${err.message}`);
  }
  if (key.asymmetricKeyType !== "ed25519") {
    fail("--log-public-key must be an Ed25519 public key");
  }
  return key;
}

async function fetchSth(baseUrl) {
  const res = await fetch(`${baseUrl}/api/transparency/sth`, {
    headers: { accept: "application/json" },
  });
  if (!res.ok) {
    throw new Error(`STH fetch failed: HTTP ${res.status}`);
  }
  return await res.json();
}

// One valid spelling per field (transparency-log.md sections 3.3 and
// 3.6; schemas/tree-head.schema.json and defs.schema.json).
// The only keys a tree head may carry (tree-head.schema.json,
// additionalProperties: false): the signature covers no others.
const STH_KEYS = new Set([
  "v",
  "logId",
  "treeSize",
  "rootHash",
  "timestamp",
  "signature",
  "canonical",
]);
const ISO_TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const V2_SIGNATURE = /^v2=[A-Za-z0-9+/]{85}[AQgw]==$/;
const V3_SIGNATURE = /^v3=[A-Za-z0-9+/]{85}[AQgw]==\.[A-Za-z0-9+/]{4412}$/;

/** Why `sth` is not a well-formed tree head, or null when it is. */
function sthShapeError(sth) {
  if (typeof sth !== "object" || sth === null || Array.isArray(sth)) {
    return "not a JSON object";
  }
  for (const key of Object.keys(sth)) {
    if (!STH_KEYS.has(key)) {
      return `unexpected field ${JSON.stringify(key)} (the signature does not cover it)`;
    }
  }
  if (sth.v !== 1) return "v must be 1";
  if (typeof sth.logId !== "string" || sth.logId.length === 0) {
    return "logId must be a non-empty string";
  }
  if (!isHashHex(sth.rootHash)) {
    return "rootHash must be 64 lowercase hex digits";
  }
  if (!Number.isSafeInteger(sth.treeSize) || sth.treeSize < 0) {
    return "treeSize must be an integer from 0 to 2^53 - 1";
  }
  if (
    typeof sth.timestamp !== "string" ||
    !ISO_TIMESTAMP.test(sth.timestamp) ||
    Number.isNaN(Date.parse(sth.timestamp)) ||
    new Date(sth.timestamp).toISOString() !== sth.timestamp
  ) {
    return "timestamp must be a date as toISOString writes it";
  }
  if (
    sth.signature !== undefined &&
    !(typeof sth.signature === "string" &&
      (V2_SIGNATURE.test(sth.signature) || V3_SIGNATURE.test(sth.signature)))
  ) {
    return "signature must be a canonical v2= or v3= signature";
  }
  if (typeof sth.canonical !== "string") return "canonical must be a string";
  return null;
}

/** Verify the log's v2= Ed25519 signature over `canonical`. */
function verifyLogSignature(canonical, signature, publicKey) {
  try {
    const sig = Buffer.from(signature.slice(3), "base64");
    if (sig.length !== 64) return false;
    return edVerify(null, Buffer.from(canonical, "utf8"), publicKey, sig);
  } catch {
    return false;
  }
}

async function fetchConsistencyProof(baseUrl, oldSize, newSize) {
  const url = `${baseUrl}/api/transparency/proof?kind=consistency&old=${oldSize}&new=${newSize}`;
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`consistency proof fetch failed: HTTP ${res.status}`);
  }
  const body = await res.json();
  if (!Array.isArray(body.proof)) {
    throw new Error("consistency proof response is malformed");
  }
  return body.proof;
}

async function submitCosignature(baseUrl, payload) {
  const res = await fetch(`${baseUrl}/api/transparency/witness`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const errBody = await res.text().catch(() => "");
    throw new Error(`cosignature submit failed: HTTP ${res.status} ${errBody}`);
  }
  return await res.json();
}

function signCanonical(canonical, privateKey) {
  const sig = edSign(null, Buffer.from(canonical, "utf8"), privateKey);
  return "v2=" + sig.toString("base64");
}

async function runOnce(opts) {
  const log = (line) => {
    if (opts.json !== "true") process.stdout.write(line + "\n");
  };
  const emit = (envelope) => {
    if (opts.json === "true") {
      process.stdout.write(JSON.stringify(envelope) + "\n");
    }
  };
  // Every refusal: no signature, no submission, one [witness] line, a
  // JSON verdict in --json mode, and a non-zero exit.
  const refuse = (verdict, exit, message, extra = {}) => {
    log(`[witness] ${message} — NOT cosigning`);
    emit({ verdict, ...extra, message });
    return { verdict, exit };
  };

  let state;
  try {
    state = loadState(opts.statePath);
  } catch (err) {
    if (!(err instanceof BadStateError)) throw err;
    return refuse(
      "bad-state",
      2,
      `BAD STATE FILE — ${err.message}; fix or move it aside (a missing file means first-time witness)`,
    );
  }

  const sth = await fetchSth(opts.url);
  const shapeError = sthShapeError(sth);
  if (shapeError) {
    return refuse("malformed-sth", 2, `MALFORMED STH: ${shapeError}`);
  }
  log(`[witness] fetched STH: logId=${sth.logId} size=${sth.treeSize} root=${sth.rootHash.slice(0, 16)}…`);

  // The canonical the witness signs is the one it rebuilds from the
  // fields it checks; the log's copy must be byte-identical to it.
  const canonical = canonicalizeSth({
    v: sth.v,
    logId: sth.logId,
    rootHash: sth.rootHash,
    timestamp: sth.timestamp,
    treeSize: sth.treeSize,
  });
  if (sth.canonical !== canonical) {
    return refuse(
      "canonical-mismatch",
      1,
      "STH canonical does not match its fields (logId, rootHash, timestamp, treeSize, v)",
    );
  }

  if (opts.logPublicKey) {
    if (sth.signature === undefined) {
      return refuse("bad-log-signature", 1, "STH has no log signature");
    }
    if (sth.signature.startsWith("v3=")) {
      return refuse(
        "unsupported-log-signature",
        2,
        "v3= STH signature: --log-public-key checks v2= (Ed25519) only, and checking the Ed25519 half alone would skip the ML-DSA-65 half",
      );
    }
    if (!verifyLogSignature(canonical, sth.signature, opts.logPublicKey)) {
      return refuse("bad-log-signature", 1, "log signature does not verify under --log-public-key");
    }
    log("[witness] log signature OK");
  } else {
    log("[witness] log signature NOT checked (no --log-public-key)");
  }

  if (state) {
    if (typeof state.logId === "string" && state.logId !== sth.logId) {
      return refuse(
        "log-id-mismatch",
        1,
        `STH is for logId ${JSON.stringify(sth.logId)}, but this state file is for ${JSON.stringify(state.logId)}`,
        { expectedLogId: state.logId, logId: sth.logId },
      );
    }
    if (typeof state.logId !== "string") {
      log(`[witness] state file has no logId; recording ${JSON.stringify(sth.logId)}`);
    }
    if (
      state.lastSize === sth.treeSize &&
      state.lastRoot === sth.rootHash
    ) {
      if (typeof state.logId !== "string") {
        saveState(opts.statePath, { logId: sth.logId, ...state });
      }
      log("[witness] no change since last poll — nothing to witness");
      emit({
        verdict: "no-change",
        treeSize: sth.treeSize,
        rootHash: sth.rootHash,
      });
      return { verdict: "no-change", exit: 0 };
    }
    if (state.lastSize > sth.treeSize) {
      return refuse("fork-detected", 1, "FORK DETECTED — tree size went BACKWARDS", {
        reason: "tree-size-decreased",
        oldSize: state.lastSize,
        newSize: sth.treeSize,
      });
    }
    if (state.lastSize === sth.treeSize) {
      return refuse(
        "fork-detected",
        1,
        `FORK DETECTED — a different root for tree size ${sth.treeSize}, which this witness already signed`,
        {
          reason: "same-size-different-root",
          treeSize: sth.treeSize,
          signedRoot: state.lastRoot,
          rootHash: sth.rootHash,
        },
      );
    }
    // Fetch + verify consistency proof from last → current.
    const proof = await fetchConsistencyProof(opts.url, state.lastSize, sth.treeSize);
    const ok = verifyConsistencyProof(
      state.lastSize,
      sth.treeSize,
      state.lastRoot,
      sth.rootHash,
      proof,
    );
    if (!ok) {
      return refuse("fork-detected", 1, "CONSISTENCY PROOF FAILED — log forked or rewrote", {
        reason: "consistency-proof-failed",
        oldSize: state.lastSize,
        newSize: sth.treeSize,
      });
    }
    log(`[witness] consistency proof OK (${state.lastSize} → ${sth.treeSize})`);
  } else {
    log("[witness] no prior state — first-time witness of this log");
  }

  // Sign the canonical rebuilt from the checked fields and submit.
  const signature = signCanonical(canonical, opts.privateKey);
  const submitBody = {
    witnessId: opts.witnessId,
    signature,
    sthCanonical: canonical,
    ...(opts.publicKeyUrl ? { publicKeyUrl: opts.publicKeyUrl } : {}),
  };
  const submission = await submitCosignature(opts.url, submitBody);
  log(
    `[witness] cosignature submitted — total witnesses on this STH: ${submission.witnessCount}`,
  );

  const newState = {
    logId: sth.logId,
    lastSize: sth.treeSize,
    lastRoot: sth.rootHash,
    lastTimestamp: sth.timestamp,
    lastSubmittedAt: new Date().toISOString(),
  };
  saveState(opts.statePath, newState);

  emit({
    verdict: "witnessed",
    treeSize: sth.treeSize,
    rootHash: sth.rootHash,
    totalWitnesses: submission.witnessCount,
  });
  return { verdict: "witnessed", exit: 0 };
}

async function runDaemon(opts) {
  const intervalSec = Math.max(60, Number(opts.interval ?? 3600));
  process.stdout.write(
    `[witness] daemon mode — polling ${opts.url} every ${intervalSec}s\n`,
  );
  while (true) {
    try {
      const r = await runOnce(opts);
      if (r.exit === 1) {
        process.stderr.write(
          `[witness] daemon halting: ${r.verdict} — operator action required\n`,
        );
        process.exit(1);
      }
    } catch (err) {
      process.stderr.write(
        `[witness] poll error (will retry in ${intervalSec}s): ${err.message}\n`,
      );
    }
    await new Promise((r) => setTimeout(r, intervalSec * 1000));
  }
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === "help" || argv.includes("--help") || argv.includes("-h")) {
    printHelp();
    process.exit(0);
  }
  const flags = parseArgs(argv);
  if (!flags.url) fail("--url is required");
  if (!flags.key) fail("--key is required");
  if (!flags["witness-id"]) fail("--witness-id is required");

  const opts = {
    url: flags.url.replace(/\/+$/, ""),
    witnessId: flags["witness-id"],
    publicKeyUrl: flags["public-key-url"],
    privateKey: loadPrivateKey(flags.key),
    logPublicKey: flags["log-public-key"]
      ? loadLogPublicKey(flags["log-public-key"])
      : undefined,
    statePath: flags.state ?? defaultStatePath(flags["witness-id"]),
    interval: flags.interval,
    json: flags.json,
  };

  if (flags.once === "true") {
    const r = await runOnce(opts);
    process.exit(r.exit);
  } else {
    await runDaemon(opts);
  }
}

main().catch((err) => fail(err?.message ?? String(err)));
