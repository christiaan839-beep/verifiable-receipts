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
 * or, while a cosignature is in flight,
 *   { logId, lastSize, lastRoot, lastTimestamp, pending: true }
 * The new head is saved (written to <path>.tmp, fsynced, renamed over
 * the file, directory fsynced) BEFORE the signature leaves the
 * process, so a log that keeps the cosignature but answers an error,
 * or a crash after the POST, can never get a second cosignature on
 * another root at that size. A pending head is resubmitted on the next
 * poll. A state file without logId (written by an earlier version)
 * still loads; the logId is added the next time the state is saved. A
 * state file that exists but cannot be read or parsed, or whose fields
 * are malformed, is refused (exit 2) rather than treated as absent.
 *
 * Exit codes (--once mode):
 *   0  Witnessed successfully OR no change since last poll
 *   1  The log misbehaved: fork or rewrite, a canonical that does not
 *      match the fields, another logId, or a bad log signature.
 *      Operator MUST investigate
 *   2  Usage error (bad flags, network failure or timeout, malformed
 *      STH, a bad state file or one that cannot be saved, a failed
 *      submission, a v3= STH with --log-public-key)
 *
 * Every request has a timeout (--timeout, default 30 s) and a 1 MiB
 * response-body limit (see MAX_BODY_BYTES).
 */

import {
  readFileSync,
  existsSync,
  mkdirSync,
  openSync,
  writeSync,
  fsyncSync,
  closeSync,
  renameSync,
  unlinkSync,
} from "node:fs";
import {
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import {
  canonicalizeSth,
  treeRoot,
  verifyConsistencyProof,
} from "../dist/transparency.js";
import { isHashHex } from "../dist/hash.js";
import { fail, parseArgs } from "./cli.mjs";

/** Root of the empty tree: SHA-256 of no bytes (RFC 6962 section 2.1). */
const EMPTY_ROOT = treeRoot([]);

/**
 * Control characters, and the JSON/JS line separators U+2028/U+2029.
 * A logId may not contain them: it is printed on [witness] lines.
 */
// eslint-disable-next-line no-control-regex -- matching them is the point
const UNSAFE_TEXT = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

/**
 * Default per-request timeout. The witness polls at most hourly and
 * makes three small requests a poll; 30 s is far above the latency of
 * a working log, and stops a log that stalls a response from holding
 * the witness (or a daemon poll) forever.
 */
const DEFAULT_TIMEOUT_SEC = 30;

/**
 * Largest response body read. The biggest legitimate body is small:
 * a v3= STH is under 5 KB plus its logId, and a consistency proof for
 * a tree of up to 2^53 - 1 leaves has at most about 2 * 53 entries of
 * 66 bytes (under 8 KB). 1 MiB leaves two orders of magnitude of
 * headroom and still bounds the memory a hostile log can make the
 * witness use.
 */
const MAX_BODY_BYTES = 1024 * 1024;

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
      "  --log-id <id>           The logId this witness serves. When given, a head",
      "                          for any other logId is refused, even on the",
      "                          first run (exit 1).",
      "  --timeout <sec>         Per-request timeout (default 30). Bodies over",
      "                          1 MiB are refused.",
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
      "  2  Usage error, network failure or timeout, malformed STH, a bad",
      "     state file or one that cannot be saved, a failed submission",
      "     (resubmitted next poll), or a v3= STH with --log-public-key",
      "",
      "Daemon mode writes a stderr line for every non-zero verdict: exit 1",
      "halts the daemon, anything else is retried at the next poll.",
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
  if (state.lastSize === 0 && state.lastRoot !== EMPTY_ROOT) {
    return "lastRoot of an empty tree must be SHA-256 of no bytes";
  }
  if (
    state.logId !== undefined &&
    (typeof state.logId !== "string" ||
      state.logId.length === 0 ||
      UNSAFE_TEXT.test(state.logId))
  ) {
    return "logId, when present, must be a non-empty string without control characters";
  }
  if (state.pending !== undefined && state.pending !== true) {
    return "pending, when present, must be true";
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

/**
 * Replace the state file atomically: write <path>.tmp, fsync it,
 * rename it over the file and fsync the directory, so a crash leaves
 * either the old state or the new one, never a torn file. Throws on
 * any failure.
 */
function saveState(path, state) {
  const tmp = path + ".tmp";
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, JSON.stringify(state, null, 2));
    fsyncSync(fd);
  } catch (err) {
    closeSync(fd);
    try {
      unlinkSync(tmp);
    } catch {
      // Best effort; the error that matters is rethrown below.
    }
    throw err;
  }
  closeSync(fd);
  renameSync(tmp, path);
  let dirFd;
  try {
    dirFd = openSync(dirname(path), "r");
    fsyncSync(dirFd);
  } catch {
    // Some platforms cannot fsync a directory; the rename is done.
  } finally {
    if (dirFd !== undefined) closeSync(dirFd);
  }
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

/** The body as text, refusing more than MAX_BODY_BYTES. */
async function readLimited(res, what) {
  const tooLarge = () =>
    new Error(`${what} response too large (over ${MAX_BODY_BYTES} bytes)`);
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    await res.body?.cancel().catch(() => {});
    throw tooLarge();
  }
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel().catch(() => {});
      throw tooLarge();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * fetch with a timeout over the whole exchange (headers and body) and
 * the body-size limit. Returns { status, ok, text }.
 */
async function request(url, init, what, timeoutSec) {
  try {
    const res = await fetch(url, {
      ...init,
      signal: AbortSignal.timeout(timeoutSec * 1000),
    });
    const text = await readLimited(res, what);
    return { status: res.status, ok: res.ok, text };
  } catch (err) {
    if (err?.name === "TimeoutError" || err?.cause?.name === "TimeoutError") {
      throw new Error(`${what} timed out after ${timeoutSec}s`, { cause: err });
    }
    throw err;
  }
}

function parseJson(text, what) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${what} response is not JSON`);
  }
}

async function fetchSth(opts) {
  const r = await request(
    `${opts.url}/api/transparency/sth`,
    { headers: { accept: "application/json" } },
    "STH fetch",
    opts.timeoutSec,
  );
  if (!r.ok) {
    throw new Error(`STH fetch failed: HTTP ${r.status}`);
  }
  return parseJson(r.text, "STH fetch");
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
  if (UNSAFE_TEXT.test(sth.logId)) {
    return "logId must not contain control characters or U+2028/U+2029";
  }
  if (!isHashHex(sth.rootHash)) {
    return "rootHash must be 64 lowercase hex digits";
  }
  if (!Number.isSafeInteger(sth.treeSize) || sth.treeSize < 0) {
    return "treeSize must be an integer from 0 to 2^53 - 1";
  }
  if (sth.treeSize === 0 && sth.rootHash !== EMPTY_ROOT) {
    return "rootHash of an empty tree must be SHA-256 of no bytes";
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

async function fetchConsistencyProof(opts, oldSize, newSize) {
  const url = `${opts.url}/api/transparency/proof?kind=consistency&old=${oldSize}&new=${newSize}`;
  const r = await request(
    url,
    { headers: { accept: "application/json" } },
    "consistency proof fetch",
    opts.timeoutSec,
  );
  if (!r.ok) {
    throw new Error(`consistency proof fetch failed: HTTP ${r.status}`);
  }
  const body = parseJson(r.text, "consistency proof fetch");
  if (!Array.isArray(body?.proof)) {
    throw new Error("consistency proof response is malformed");
  }
  return body.proof;
}

async function submitCosignature(opts, payload) {
  const r = await request(
    `${opts.url}/api/transparency/witness`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    },
    "cosignature submit",
    opts.timeoutSec,
  );
  if (!r.ok) {
    // The body is the log's text: quoted, and cut short.
    throw new Error(
      `cosignature submit failed: HTTP ${r.status} ${JSON.stringify(r.text.slice(0, 200))}`,
    );
  }
  return parseJson(r.text, "cosignature submit");
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

  const sth = await fetchSth(opts);
  const shapeError = sthShapeError(sth);
  if (shapeError) {
    return refuse("malformed-sth", 2, `MALFORMED STH: ${shapeError}`);
  }
  log(`[witness] fetched STH: logId=${JSON.stringify(sth.logId)} size=${sth.treeSize} root=${sth.rootHash.slice(0, 16)}…`);
  if (opts.expectedLogId !== undefined && sth.logId !== opts.expectedLogId) {
    return refuse(
      "log-id-mismatch",
      1,
      `STH is for logId ${JSON.stringify(sth.logId)}, but --log-id is ${JSON.stringify(opts.expectedLogId)}`,
      { expectedLogId: opts.expectedLogId, logId: sth.logId },
    );
  }

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

  let verdict = "witnessed";
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
    const sameHead =
      state.lastSize === sth.treeSize && state.lastRoot === sth.rootHash;
    if (sameHead && state.pending === true) {
      // The head was saved but its submission did not complete. Same
      // size, same root: signing it again cannot make a fork.
      log("[witness] last submission of this head did not complete — resubmitting");
      verdict = "resubmitted";
    } else if (sameHead) {
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
    } else if (state.lastSize > sth.treeSize) {
      return refuse("fork-detected", 1, "FORK DETECTED — tree size went BACKWARDS", {
        reason: "tree-size-decreased",
        oldSize: state.lastSize,
        newSize: sth.treeSize,
      });
    } else if (state.lastSize === sth.treeSize) {
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
    } else {
      // Fetch + verify consistency proof from last → current.
      const proof = await fetchConsistencyProof(opts, state.lastSize, sth.treeSize);
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
    }
  } else {
    log("[witness] no prior state — first-time witness of this log");
  }

  // Save the head BEFORE the signature leaves the process. From here
  // on this witness never signs another root at this size, whatever
  // happens to the submission.
  const head = {
    logId: sth.logId,
    lastSize: sth.treeSize,
    lastRoot: sth.rootHash,
    lastTimestamp: sth.timestamp,
  };
  try {
    saveState(opts.statePath, { ...head, pending: true });
  } catch (err) {
    return refuse(
      "state-save-failed",
      2,
      `could not save the state file before signing (${err.message})`,
    );
  }

  // Sign the canonical rebuilt from the checked fields and submit.
  const signature = signCanonical(canonical, opts.privateKey);
  const submitBody = {
    witnessId: opts.witnessId,
    signature,
    sthCanonical: canonical,
    ...(opts.publicKeyUrl ? { publicKeyUrl: opts.publicKeyUrl } : {}),
  };
  let submission;
  try {
    submission = await submitCosignature(opts, submitBody);
  } catch (err) {
    log(`[witness] ${err.message} — the head is saved; the next poll resubmits it`);
    emit({
      verdict: "submit-failed",
      treeSize: sth.treeSize,
      rootHash: sth.rootHash,
      message: err.message,
    });
    return { verdict: "submit-failed", exit: 2 };
  }
  log(
    `[witness] cosignature submitted — total witnesses on this STH: ${JSON.stringify(submission?.witnessCount ?? null)}`,
  );

  try {
    saveState(opts.statePath, { ...head, lastSubmittedAt: new Date().toISOString() });
  } catch (err) {
    // The head is already saved (pending): the next poll resubmits the
    // same head, which is harmless.
    process.stderr.write(
      `[witness] warning: cosignature submitted but the state file could not be updated (${err.message})\n`,
    );
  }

  emit({
    verdict,
    treeSize: sth.treeSize,
    rootHash: sth.rootHash,
    totalWitnesses: submission?.witnessCount ?? null,
  });
  return { verdict, exit: 0 };
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
          `[witness] ${r.verdict} (exit 1) — daemon halting, operator action required\n`,
        );
        process.exit(1);
      }
      if (r.exit !== 0) {
        process.stderr.write(
          `[witness] ${r.verdict} (exit ${r.exit}) — will retry in ${intervalSec}s\n`,
        );
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
  const expectedLogId = flags["log-id"];
  if (
    expectedLogId !== undefined &&
    (expectedLogId === "true" || expectedLogId.length === 0 || UNSAFE_TEXT.test(expectedLogId))
  ) {
    fail("--log-id needs a logId without control characters");
  }
  const timeoutSec =
    flags.timeout === undefined ? DEFAULT_TIMEOUT_SEC : Number(flags.timeout);
  if (!Number.isFinite(timeoutSec) || timeoutSec <= 0) {
    fail("--timeout must be a positive number of seconds");
  }

  const opts = {
    url: flags.url.replace(/\/+$/, ""),
    witnessId: flags["witness-id"],
    publicKeyUrl: flags["public-key-url"],
    privateKey: loadPrivateKey(flags.key),
    logPublicKey: flags["log-public-key"]
      ? loadLogPublicKey(flags["log-public-key"])
      : undefined,
    statePath: flags.state ?? defaultStatePath(flags["witness-id"]),
    expectedLogId,
    timeoutSec,
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
