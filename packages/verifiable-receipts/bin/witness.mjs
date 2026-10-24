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
 * The new head is saved (written to a uniquely named temporary file,
 * fsynced, renamed over the file, directory fsynced) BEFORE the
 * signature leaves the process, so a log that keeps the cosignature
 * but answers an error, or a crash after the POST, can never get a
 * second cosignature on another root at that size. A pending head is
 * resubmitted on the next poll exactly as saved (same canonical, same
 * signature), even if the log has since re-dated it. Each poll holds
 * <state>.lock (on the state file's real path) as a lease from before
 * the state is read to after it is written, renewing its mtime every
 * LEASE_RENEW_MS; a second process on the same state file is refused
 * (state-locked) until the lease runs out (LEASE_MS). Its pid and
 * hostname are for messages only. A stale lock is broken under
 * <state>.lock.break; --break-lock is the explicit override. A
 * process whose lock was taken over does not sign (lock-lost).
 * SIGTERM and SIGINT release the lock (exit 143, 130). A head dated earlier than the saved one is
 * refused (receipts-log API.md: the timestamp "never decreases"). A
 * state file without logId (written by an earlier version)
 * still loads; the logId is added the next time the state is saved. A
 * state file that exists but cannot be read or parsed, or whose fields
 * are malformed, is refused (exit 2) rather than treated as absent.
 *
 * Exit codes (--once mode):
 *   0  Witnessed successfully OR no change since last poll
 *   1  The log misbehaved: fork or rewrite, a canonical that does not
 *      match the fields, another logId, a bad log signature, or a
 *      timestamp earlier than the saved one. Operator MUST investigate
 *   2  Usage error (bad flags, a fetch that failed, timed out, was
 *      redirected or was too large, malformed STH, a bad state file or
 *      one that cannot be saved, a state file locked by another
 *      process or in a directory it cannot write, a failed submission,
 *      a v3= STH with --log-public-key)
 *
 * Every request has a timeout (--timeout, 1 to 3600 s, default 30), a
 * 1 MiB response-body limit (see MAX_BODY_BYTES) and never follows a
 * redirect. With --json, a poll prints exactly one JSON verdict line on
 * stdout. Every [witness] line escapes control characters,
 * U+2028/U+2029 and the bidirectional controls, and strings from the
 * log are printed quoted.
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
  linkSync,
  lstatSync,
  realpathSync,
  utimesSync,
  statSync,
} from "node:fs";
import {
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import { basename, dirname, join } from "node:path";
import { homedir, hostname } from "node:os";
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
 * Control characters, the line separators U+2028/U+2029, and the
 * bidirectional controls (U+200E, U+200F, U+202A-U+202E,
 * U+2066-U+2069) that can make a line read differently from its
 * bytes. A logId may not contain them: it is printed on [witness]
 * lines.
 */
// eslint-disable-next-line no-control-regex -- matching them is the point
const UNSAFE_TEXT = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2028\u2029\u2066-\u2069]/;

/**
 * JSON.stringify, then \uXXXX for what it leaves raw but a viewer may
 * break a line on or reorder: the C1 controls (U+0080-U+009F, NEL
 * among them), U+2028/U+2029 and the bidirectional controls.
 */
function safeJson(value) {
  return JSON.stringify(value).replace(
    /[\u0080-\u009f\u200e\u200f\u202a-\u202e\u2028\u2029\u2066-\u2069]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}

/** A string for a [witness] line: quoted and escaped by safeJson. */
function quote(s) {
  return safeJson(String(s));
}

/**
 * One output line with every character UNSAFE_TEXT matches written as
 * \uXXXX, so nothing inside it (an error message, a file's bytes) can
 * end the line, start a forged one or reorder it.
 */
function escapeLine(text) {
  return text.replace(new RegExp(UNSAFE_TEXT.source, "g"), (c) =>
    "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}

/** A [witness] line on stderr, escaped. */
function warn(line) {
  process.stderr.write(escapeLine(line) + "\n");
}

/**
 * Default per-request timeout (--timeout takes 1 to 3600 seconds).
 * The witness polls at most hourly and
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
      "  --timeout <sec>         Per-request timeout, 1 to 3600 (default 30).",
      "                          Bodies over 1 MiB and redirects are refused.",
      "  --log-public-key <path> The log's Ed25519 public key (PEM). When given,",
      "                          the log's v2= STH signature must verify before",
      "                          the witness cosigns; a v3= STH is refused.",
      "                          Without it the log signature is not checked.",
      "  --interval <sec>        Daemon poll interval, 60 or more (default 3600)",
      "  --once                  Single check + exit (don't loop)",
      "  --state <path>          Override state file location (symlinks are",
      "                          resolved; the lock is <real path>.lock)",
      "  --break-lock            Remove the state file's lock (and its .break)",
      "                          whatever holds it, say so on stderr, and go",
      "                          on. If another witness is still running on",
      "                          this state file, two witnesses can sign: use",
      "                          it only when you are sure none is.",
      "  --json                  Emit JSON envelope per check",
      "  --help                  This message",
      "",
      "Exit codes (--once):",
      "  0  Witnessed OR no change",
      "  1  The log misbehaved: fork / rewrite, canonical not matching its",
      "     fields, another logId, bad log signature, a timestamp earlier",
      "     than the saved one (do NOT auto-recover; investigate)",
      "  2  Usage error, a fetch that failed, timed out, was redirected or",
      "     was too large, malformed STH, a bad state file or one that",
      "     cannot be saved, a state file locked by another witness",
      "     process (state-locked) or in a directory it cannot write",
      "     (state-unwritable), a failed submission (resubmitted next poll, as",
      "     saved), or a v3= STH with --log-public-key",
      "",
      "Each poll holds <state>.lock as a lease: the holder touches its",
      "mtime every 5 s. A lock is stale only when its mtime is older than",
      "LEASE_MS = 3 x --timeout + 30 s (120 s by default): a poll makes at",
      "most three requests, each bounded by --timeout, plus local work.",
      "Its pid and hostname are shown, never trusted. A stale lock is",
      "broken under <state>.lock.break; a held one is refused",
      "(state-locked) with the time its lease runs out, so a restarted",
      "witness recovers by itself. SIGTERM and SIGINT release the lock",
      "and exit 143 and 130.",
      "With --json each poll prints one JSON verdict line on stdout; the",
      "daemon banner goes to stderr.",
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
  if (state.lastTimestamp !== undefined && !isIsoTimestamp(state.lastTimestamp)) {
    return "lastTimestamp, when present, must be a date as toISOString writes it";
  }
  if (state.pending !== undefined && state.pending !== true) {
    return "pending, when present, must be true";
  }
  if (
    state.pending === true &&
    (typeof state.logId !== "string" || state.lastTimestamp === undefined)
  ) {
    return "a pending head needs its logId and lastTimestamp";
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
 * Replace the state file atomically: write a new uniquely named
 * temporary file, fsync it, rename it over the file and fsync the
 * directory, so a crash leaves either the old state or the new one,
 * never a torn file. Throws on any failure, so a failed save means no
 * signature. On macOS fsync is not F_FULLFSYNC: it reaches the drive,
 * not necessarily its platters.
 */
function saveState(path, state) {
  const tmp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const fd = openSync(tmp, "wx", 0o600);
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
  try {
    renameSync(tmp, path);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      // Best effort; the error that matters is rethrown below.
    }
    throw err;
  }
  let dirFd;
  try {
    dirFd = openSync(dirname(path), "r");
    fsyncSync(dirFd);
  } catch (err) {
    // Only the errors of a platform that cannot fsync a directory.
    if (!["EINVAL", "EISDIR", "EPERM", "ENOTSUP"].includes(err?.code)) throw err;
  } finally {
    if (dirFd !== undefined) closeSync(dirFd);
  }
}

const HOST = hostname();

/**
 * How often a held lock's lease is renewed: its mtime is touched by an
 * unref'd timer. VR_WITNESS_LEASE_RENEW_MS may only shorten it (50 to
 * 5000 ms; the tests use it): renewing more often is never less safe.
 */
const LEASE_RENEW_MS = (() => {
  const v = Number(process.env.VR_WITNESS_LEASE_RENEW_MS);
  return Number.isFinite(v) && v >= 50 && v <= 5000 ? v : 5000;
})();

/**
 * LEASE_MS: a lock is stale only when its mtime is older than this,
 * whatever pid, host or nonce it names (pids and hostnames repeat
 * across containers and pid namespaces, so they prove nothing). A poll
 * makes at most three requests (STH, consistency proof, cosignature),
 * each bounded end to end by --timeout, plus local work (a signature,
 * a few fsyncs) measured in milliseconds; 30 s more covers a slow disk.
 * So even a poll whose renewal timer never ran (an event loop blocked
 * throughout) ends inside its lease, and a renewed lease (every 5 s)
 * is never close to running out. With the default 30 s timeout it is
 * 120 s. A holder's own leaseMs, if longer, is honoured.
 */
function leaseMsFor(timeoutMs) {
  return 3 * timeoutMs + 30_000;
}
const MAX_LEASE_MS = leaseMsFor(3600 * 1000);

/** The lock this process holds, { path, nonce, timer }, or null. */
let heldLock = null;

const secs = (ms) => `${Math.max(0, Math.round(ms / 1000))}s`;

/** linkSync errors that mean "this file system has no hard links". */
const NO_HARD_LINKS = new Set(["EPERM", "ENOTSUP", "ENOSYS", "EXDEV", "EOPNOTSUPP"]);

/**
 * Create `path` holding `record`, atomically: write a temporary file,
 * fsync it, then hard-link it into place, so the file is never seen
 * empty or half written. Throws EEXIST when `path` exists. On a file
 * system without hard links it falls back to openSync(path, "wx") and
 * a write: still exclusive, but a reader can then see the file empty
 * for a moment (it is refused as unreadable until its lease runs out).
 */
function createWhole(path, record) {
  const text = JSON.stringify(record);
  const tmp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const fd = openSync(tmp, "wx", 0o600);
  let linked = false;
  try {
    try {
      writeSync(fd, text);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      linkSync(tmp, path);
      linked = true;
    } catch (err) {
      if (!NO_HARD_LINKS.has(err?.code)) throw err;
    }
  } finally {
    try {
      unlinkSync(tmp);
    } catch {
      // Best effort: a leftover temporary file is harmless.
    }
  }
  if (linked) return;
  const fd2 = openSync(path, "wx", 0o600);
  try {
    writeSync(fd2, text);
    fsyncSync(fd2);
  } finally {
    closeSync(fd2);
  }
}

const UNWRITABLE = new Set(["EACCES", "EPERM", "EROFS"]);

/** Remove `path` only if it still holds `nonce`. */
function unlinkIfOurs(path, nonce) {
  let record;
  try {
    record = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    if (err?.code === "ENOENT") return "gone";
    return "unreadable";
  }
  if (record?.nonce !== nonce) return "not-ours";
  unlinkSync(path);
  return "removed";
}

/**
 * Take <lock>.break, the right to break a stale lock. Returns
 * { nonce } or { problem }. A .break older than leaseMs is taken over:
 * it is renamed aside, and kept aside only if it is still the bytes
 * judged stale; otherwise it is put back.
 */
function takeBreak(breakPath, leaseMs) {
  const nonce = randomUUID();
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      createWhole(breakPath, { pid: process.pid, hostname: HOST, startedAt: new Date().toISOString(), nonce });
      return { nonce };
    } catch (err) {
      if (err?.code !== "EEXIST") return { problem: `cannot create ${breakPath} (${err.message})` };
    }
    let st;
    let raw;
    try {
      st = statSync(breakPath);
      raw = readFileSync(breakPath, "utf8");
    } catch (err) {
      if (err?.code === "ENOENT") continue;
      return { problem: `${breakPath} exists and cannot be read (${err.message})` };
    }
    const age = Date.now() - st.mtimeMs;
    if (age <= leaseMs) {
      return { problem: `another process is breaking it (${breakPath} was made ${secs(age)} ago)` };
    }
    const aside = `${breakPath}.${process.pid}.${randomUUID()}.stale`;
    try {
      renameSync(breakPath, aside);
    } catch (err) {
      if (err?.code === "ENOENT") continue;
      return { problem: `cannot move the stale ${breakPath} aside (${err.message})` };
    }
    let moved = null;
    try {
      moved = readFileSync(aside, "utf8");
    } catch {
      // Treated as changed.
    }
    if (moved !== raw) {
      // Not the one judged stale: put it back unless another took its place.
      try {
        linkSync(aside, breakPath);
      } catch (err) {
        if (NO_HARD_LINKS.has(err?.code) && !existsSync(breakPath)) renameSync(aside, breakPath);
      }
      try {
        unlinkSync(aside);
      } catch {
        // Already renamed back.
      }
      return { problem: `another process is breaking it (${breakPath} changed)` };
    }
    unlinkSync(aside);
    warn(`[witness] took over a stale ${breakPath} (made ${secs(age)} ago)`);
  }
  return { problem: `${breakPath} is contended` };
}

/** Touch the held lock's mtime every LEASE_RENEW_MS while it is ours. */
function startRenewal(held) {
  held.timer = setInterval(() => {
    try {
      const record = JSON.parse(readFileSync(held.path, "utf8"));
      if (record?.nonce !== held.nonce) {
        clearInterval(held.timer);
        warn(`[witness] warning: ${held.path} is no longer this process's lock; not renewing it`);
        return;
      }
      const now = new Date();
      utimesSync(held.path, now, now);
    } catch (err) {
      if (!held.warned) {
        held.warned = true;
        warn(`[witness] warning: could not renew the lease on ${held.path} (${err.message})`);
      }
    }
  }, LEASE_RENEW_MS);
  held.timer.unref();
}

/** True while the lock file still holds this process's nonce. */
function lockStillOurs() {
  if (!heldLock) return false;
  try {
    return JSON.parse(readFileSync(heldLock.path, "utf8"))?.nonce === heldLock.nonce;
  } catch {
    return false;
  }
}

/**
 * Take <statePath>.lock for one poll: a lease. The lock holds
 * { pid, hostname, startedAt, nonce, leaseMs }, but those are only
 * for messages and for the nonce-checked release; whether a lock is
 * held is decided by its mtime alone, renewed every LEASE_RENEW_MS
 * while held. Returns null when taken, or { verdict, message }:
 *   - a lock renewed within the lease is refused, whatever it names,
 *     with the time its lease runs out;
 *   - an expired lock is broken only while holding <lock>.break, and
 *     only if it still holds the bytes read;
 *   - with breakLock, the lock and <lock>.break are removed first,
 *     whatever holds them, said loudly on stderr.
 * Every refusal says how to recover.
 */
function acquireLock(lockPath, breakLock, leaseMs) {
  const breakPath = lockPath + ".break";
  const locked = (why, retryAt) => {
    const both = existsSync(breakPath);
    const files = both ? `${lockPath} and ${breakPath}` : lockPath;
    const when = retryAt ? `retry after ${retryAt}, when its lease runs out, or, ` : "";
    return {
      verdict: "state-locked",
      message: `${why}${both ? ` (${lockPath} and ${breakPath} both exist)` : ""}; ${when}if you are sure no other witness is running on this state file, rerun with --break-lock (or delete ${files})`,
    };
  };
  if (breakLock) {
    warn(
      `[witness] BREAKING LOCK ${lockPath} (--break-lock): removing it whatever holds it. If another witness is still running on this state file, two witnesses can sign.`,
    );
    for (const p of [lockPath, breakPath]) {
      try {
        unlinkSync(p);
      } catch (err) {
        if (err?.code !== "ENOENT") return locked(`cannot remove ${p} (${err.message})`);
      }
    }
  }
  const nonce = randomUUID();
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      createWhole(lockPath, {
        pid: process.pid,
        hostname: HOST,
        startedAt: new Date().toISOString(),
        nonce,
        leaseMs,
      });
      heldLock = { path: lockPath, nonce, timer: null };
      startRenewal(heldLock);
      return null;
    } catch (err) {
      if (UNWRITABLE.has(err?.code)) {
        return {
          verdict: "state-unwritable",
          message: `cannot create ${lockPath} (${err.message}); make the state file's directory writable by this user, or pass --state <path> in a writable directory`,
        };
      }
      if (err?.code !== "EEXIST") return locked(`cannot create ${lockPath} (${err.message})`);
    }
    let st;
    let raw;
    try {
      st = statSync(lockPath);
      raw = readFileSync(lockPath, "utf8");
    } catch (err) {
      if (err?.code === "ENOENT") continue;
      return locked(`${lockPath} exists and cannot be read (${err.message})`);
    }
    let holder = null;
    try {
      holder = JSON.parse(raw);
    } catch {
      // Unreadable: held until its lease runs out, like any other.
    }
    const recorded = Number(holder?.leaseMs);
    const lease = Math.max(
      leaseMs,
      Number.isFinite(recorded) && recorded > 0 ? Math.min(recorded, MAX_LEASE_MS) : 0,
    );
    const age = Date.now() - st.mtimeMs;
    const who =
      holder && typeof holder === "object"
        ? `held by pid ${quote(holder.pid)} on host ${quote(holder.hostname)} since ${quote(holder.startedAt)}`
        : "exists and cannot be read (it is not a lock record)";
    if (age <= lease) {
      return locked(
        `${lockPath} ${who}, last renewed ${secs(age)} ago`,
        new Date(st.mtimeMs + lease + 1000).toISOString(),
      );
    }
    // The lease ran out. Break it only while holding <lock>.break.
    const brk = takeBreak(breakPath, leaseMs);
    if (brk.problem) return locked(`${lockPath} is stale, but ${brk.problem}`);
    try {
      let now = null;
      try {
        now = readFileSync(lockPath, "utf8");
      } catch (err) {
        if (err?.code !== "ENOENT") throw err;
      }
      if (now === raw) {
        unlinkSync(lockPath);
        warn(`[witness] removed stale lock ${lockPath} (${who}; lease ran out: last renewed ${secs(age)} ago)`);
      }
    } catch (err) {
      return locked(`cannot remove stale ${lockPath} (${err.message})`);
    } finally {
      try {
        unlinkIfOurs(breakPath, brk.nonce);
      } catch {
        // A leftover <lock>.break ages out after the lease.
      }
    }
  }
  return locked(`${lockPath} is contended`);
}

/** Stop renewing, and remove the lock if it still holds our nonce. */
function releaseLock() {
  const held = heldLock;
  heldLock = null;
  if (!held) return;
  if (held.timer) clearInterval(held.timer);
  try {
    if (unlinkIfOurs(held.path, held.nonce) === "not-ours") {
      warn(`[witness] warning: ${held.path} is no longer this process's lock; left in place`);
    }
  } catch (err) {
    warn(`[witness] warning: could not remove ${held.path} (${err.message})`);
  }
}

/**
 * The real path of the state file (its directory's real path plus its
 * name, when the file does not exist yet), so a symlink and its target
 * share one lock and the rename replaces the target, not the link.
 */
function resolveStatePath(path) {
  try {
    return realpathSync(path);
  } catch (err) {
    if (err?.code !== "ENOENT") fail(`cannot resolve --state ${path} (${err.message})`);
  }
  let link = false;
  try {
    link = lstatSync(path).isSymbolicLink();
  } catch {
    // Nothing at the path: a first run.
  }
  if (link) fail(`--state ${path} is a symbolic link to nothing`);
  try {
    return join(realpathSync(dirname(path)), basename(path));
  } catch (err) {
    return fail(`cannot resolve the directory of --state ${path} (${err.message})`);
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
async function request(url, init, what, timeoutMs) {
  try {
    const res = await fetch(url, {
      ...init,
      // A redirect could send the request, or the signature, elsewhere.
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await readLimited(res, what);
    return { status: res.status, ok: res.ok, text };
  } catch (err) {
    if (err?.name === "TimeoutError" || err?.cause?.name === "TimeoutError") {
      throw new Error(`${what} timed out after ${timeoutMs / 1000}s`, { cause: err });
    }
    if (/redirect/i.test(String(err?.cause?.message ?? ""))) {
      throw new Error(`${what} got a redirect, which is never followed`, { cause: err });
    }
    const cause = err?.cause;
    const why = cause ? ` (${quote(cause.message ?? String(cause))})` : "";
    throw new Error(`${what}: ${err?.message ?? String(err)}${why}`, { cause: err });
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
    opts.timeoutMs,
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

/** A real date written exactly as Date.prototype.toISOString writes it. */
function isIsoTimestamp(t) {
  return (
    typeof t === "string" &&
    ISO_TIMESTAMP.test(t) &&
    !Number.isNaN(Date.parse(t)) &&
    new Date(t).toISOString() === t
  );
}
const V2_SIGNATURE = /^v2=[A-Za-z0-9+/]{85}[AQgw]==$/;
const V3_SIGNATURE = /^v3=[A-Za-z0-9+/]{85}[AQgw]==\.[A-Za-z0-9+/]{4412}$/;

/** Why `sth` is not a well-formed tree head, or null when it is. */
function sthShapeError(sth) {
  if (typeof sth !== "object" || sth === null || Array.isArray(sth)) {
    return "not a JSON object";
  }
  for (const key of Object.keys(sth)) {
    if (!STH_KEYS.has(key)) {
      return `unexpected field ${quote(key)} (the signature does not cover it)`;
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
  if (!isIsoTimestamp(sth.timestamp)) {
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
    opts.timeoutMs,
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
    opts.timeoutMs,
  );
  if (!r.ok) {
    // The body is the log's text: quoted, and cut short.
    throw new Error(
      `cosignature submit failed: HTTP ${r.status} ${quote(r.text.slice(0, 200))}`,
    );
  }
  return parseJson(r.text, "cosignature submit");
}

function signCanonical(canonical, privateKey) {
  const sig = edSign(null, Buffer.from(canonical, "utf8"), privateKey);
  return "v2=" + sig.toString("base64");
}

/**
 * One poll, holding <statePath>.lock from before the state is read
 * until after it is last written, so two witnesses on one state file
 * cannot each sign a different head of the same size.
 */
async function runOnce(opts) {
  const log = (line) => {
    if (opts.json !== "true") process.stdout.write(escapeLine(line) + "\n");
  };
  const emit = (envelope) => {
    if (opts.json === "true") process.stdout.write(safeJson(envelope) + "\n");
  };
  // Every refusal: no signature, no submission, one [witness] line, a
  // JSON verdict in --json mode, and a non-zero exit.
  const refuse = (verdict, exit, message, extra = {}) => {
    log(`[witness] ${message} — NOT cosigning`);
    emit({ verdict, ...extra, message });
    return { verdict, exit };
  };
  const io = { log, emit, refuse };

  const lockPath = opts.statePath + ".lock";
  const lockProblem = acquireLock(lockPath, opts.breakLock, opts.leaseMs);
  opts.breakLock = false; // only ever the first poll
  if (lockProblem) {
    const label = lockProblem.verdict === "state-unwritable" ? "STATE DIRECTORY NOT WRITABLE" : "STATE FILE LOCKED";
    return refuse(lockProblem.verdict, 2, `${label} — ${lockProblem.message}`);
  }
  try {
    return await runLocked(opts, io);
  } finally {
    releaseLock();
  }
}

async function runLocked(opts, { log, emit, refuse }) {
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

  let sth;
  try {
    sth = await fetchSth(opts);
  } catch (err) {
    return refuse("fetch-failed", 2, `${err.message}`);
  }
  const shapeError = sthShapeError(sth);
  if (shapeError) {
    return refuse("malformed-sth", 2, `MALFORMED STH: ${shapeError}`);
  }
  log(`[witness] fetched STH: logId=${quote(sth.logId)} size=${sth.treeSize} root=${sth.rootHash.slice(0, 16)}…`);
  if (opts.expectedLogId !== undefined && sth.logId !== opts.expectedLogId) {
    return refuse(
      "log-id-mismatch",
      1,
      `STH is for logId ${quote(sth.logId)}, but --log-id is ${quote(opts.expectedLogId)}`,
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
  let resubmit = null;
  if (state) {
    if (typeof state.logId === "string" && state.logId !== sth.logId) {
      return refuse(
        "log-id-mismatch",
        1,
        `STH is for logId ${quote(sth.logId)}, but this state file is for ${quote(state.logId)}`,
        { expectedLogId: state.logId, logId: sth.logId },
      );
    }
    if (typeof state.logId !== "string") {
      log(`[witness] state file has no logId; recording ${quote(sth.logId)}`);
    }
    // receipts-log API.md: the timestamp "never decreases".
    if (
      state.lastTimestamp !== undefined &&
      Date.parse(sth.timestamp) < Date.parse(state.lastTimestamp)
    ) {
      return refuse(
        "timestamp-decreased",
        1,
        `STH timestamp ${quote(sth.timestamp)} is earlier than the saved ${quote(state.lastTimestamp)}`,
        { timestamp: sth.timestamp, savedTimestamp: state.lastTimestamp },
      );
    }
    const sameHead =
      state.lastSize === sth.treeSize && state.lastRoot === sth.rootHash;
    if (sameHead && state.pending === true) {
      // The head was saved but its submission did not complete. Resubmit
      // the SAVED head, byte for byte: same bytes, same Ed25519
      // signature. A log that has re-dated this size and root gets no
      // signature on the new date while one is pending.
      resubmit = {
        logId: state.logId,
        lastSize: state.lastSize,
        lastRoot: state.lastRoot,
        lastTimestamp: state.lastTimestamp,
      };
      if (sth.timestamp !== state.lastTimestamp) {
        log(
          `[witness] the log re-signed this head with timestamp ${quote(sth.timestamp)}; resubmitting the saved head dated ${quote(state.lastTimestamp)}`,
        );
      } else {
        log("[witness] last submission of this head did not complete — resubmitting it");
      }
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
      let proof;
      try {
        proof = await fetchConsistencyProof(opts, state.lastSize, sth.treeSize);
      } catch (err) {
        return refuse("fetch-failed", 2, `${err.message}`);
      }
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
  // happens to the submission. A resubmission is of the head already
  // saved.
  const head = resubmit ?? {
    logId: sth.logId,
    lastSize: sth.treeSize,
    lastRoot: sth.rootHash,
    lastTimestamp: sth.timestamp,
  };
  // The lease may have run out (a stalled process) and another taken
  // the lock: then this process must not save or sign.
  const lockLost = () =>
    refuse(
      "lock-lost",
      2,
      `the lock on ${opts.statePath}.lock was taken over (its lease ran out, or --break-lock); check for another witness on this state file`,
    );
  if (!lockStillOurs()) return lockLost();
  if (!resubmit) {
    try {
      saveState(opts.statePath, { ...head, pending: true });
    } catch (err) {
      return refuse(
        "state-save-failed",
        2,
        `could not save the state file before signing (${err.message})`,
      );
    }
  }
  const toSign = canonicalizeSth({
    v: 1,
    logId: head.logId,
    rootHash: head.lastRoot,
    timestamp: head.lastTimestamp,
    treeSize: head.lastSize,
  });

  if (!lockStillOurs()) return lockLost();
  // Sign the canonical rebuilt from the checked (or saved) fields.
  const signature = signCanonical(toSign, opts.privateKey);
  const submitBody = {
    witnessId: opts.witnessId,
    signature,
    sthCanonical: toSign,
    ...(opts.publicKeyUrl ? { publicKeyUrl: opts.publicKeyUrl } : {}),
  };
  let submission;
  try {
    submission = await submitCosignature(opts, submitBody);
  } catch (err) {
    log(`[witness] ${err.message} — the head is saved; the next poll resubmits it`);
    emit({
      verdict: "submit-failed",
      treeSize: head.lastSize,
      rootHash: head.lastRoot,
      message: err.message,
    });
    return { verdict: "submit-failed", exit: 2 };
  }
  log(
    `[witness] cosignature submitted — total witnesses on this STH: ${quote(submission?.witnessCount ?? null)}`,
  );

  try {
    saveState(opts.statePath, { ...head, lastSubmittedAt: new Date().toISOString() });
  } catch (err) {
    // The head is already saved (pending): the next poll resubmits the
    // same head, which is harmless.
    warn(`[witness] warning: cosignature submitted but the state file could not be updated (${err.message})`);
  }

  emit({
    verdict,
    treeSize: head.lastSize,
    rootHash: head.lastRoot,
    totalWitnesses: submission?.witnessCount ?? null,
  });
  return { verdict, exit: 0 };
}

async function runDaemon(opts) {
  const intervalSec = opts.intervalSec;
  const banner = `[witness] daemon mode — polling ${opts.url} every ${intervalSec}s`;
  // --json keeps stdout to JSON lines.
  if (opts.json === "true") warn(banner);
  else process.stdout.write(escapeLine(banner) + "\n");
  while (true) {
    try {
      const r = await runOnce(opts);
      if (r.exit === 1) {
        warn(`[witness] ${r.verdict} (exit 1) — daemon halting, operator action required`);
        process.exit(1);
      }
      if (r.exit !== 0) {
        warn(`[witness] ${r.verdict} (exit ${r.exit}) — will retry in ${intervalSec}s`);
      }
    } catch (err) {
      const message = err?.message ?? String(err);
      warn(`[witness] poll error (will retry in ${intervalSec}s): ${quote(message)}`);
      if (opts.json === "true") {
        process.stdout.write(safeJson({ verdict: "error", message }) + "\n");
      }
    }
    await new Promise((r) => setTimeout(r, intervalSec * 1000));
  }
}

/** Set from the flags; main's catch uses it to keep --json output whole. */
let jsonMode = false;

function installSignalHandlers() {
  // A terminated poll releases its lock. (Node as PID 1 in a container
  // otherwise ignores SIGTERM until it is SIGKILLed.) The daemon's
  // sleep is a timer, so a signal ends it at once.
  for (const [signal, code] of [
    ["SIGTERM", 143],
    ["SIGINT", 130],
  ]) {
    process.on(signal, () => {
      releaseLock();
      warn(`[witness] ${signal}: lock released, exiting`);
      process.exit(code);
    });
  }
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === "help" || argv.includes("--help") || argv.includes("-h")) {
    printHelp();
    process.exit(0);
  }
  const flags = parseArgs(argv);
  jsonMode = flags.json === "true";
  installSignalHandlers();
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
  if (!Number.isFinite(timeoutSec) || timeoutSec < 1 || timeoutSec > 3600) {
    fail("--timeout must be a number of seconds from 1 to 3600");
  }
  const intervalSec =
    flags.interval === undefined ? 3600 : Number(flags.interval);
  if (!Number.isFinite(intervalSec) || intervalSec < 60) {
    fail("--interval must be a number of seconds, 60 or more");
  }

  const opts = {
    url: flags.url.replace(/\/+$/, ""),
    witnessId: flags["witness-id"],
    publicKeyUrl: flags["public-key-url"],
    privateKey: loadPrivateKey(flags.key),
    logPublicKey: flags["log-public-key"]
      ? loadLogPublicKey(flags["log-public-key"])
      : undefined,
    statePath: resolveStatePath(flags.state ?? defaultStatePath(flags["witness-id"])),
    breakLock: flags["break-lock"] === "true",
    expectedLogId,
    timeoutMs: Math.ceil(timeoutSec * 1000),
    leaseMs: leaseMsFor(Math.ceil(timeoutSec * 1000)),
    intervalSec,
    json: flags.json,
  };

  if (flags.once === "true") {
    const r = await runOnce(opts);
    process.exit(r.exit);
  } else {
    await runDaemon(opts);
  }
}

main().catch((err) => {
  const message = err?.message ?? String(err);
  // --json: one verdict line on stdout for this failure too.
  if (jsonMode) {
    process.stdout.write(safeJson({ verdict: "error", message }) + "\n");
  }
  fail(quote(message));
});
