/**
 * witness CLI integration tests.
 *
 * Spawns bin/witness.mjs as a subprocess against a tiny in-process
 * mock server (real HTTP, real Ed25519 signing). Covers:
 *   - --help prints usage and exits 0
 *   - missing required flags → exit 2
 *   - --once with a fresh state file → witnesses successfully
 *   - --once with same STH as last state → no-change, exit 0
 *   - --once after the log grew → consistency proof verified +
 *     fresh cosignature submitted
 *   - --once when the log forks → exit 1 with "fork-detected"
 *   - --json output shape matches the documented envelope
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import { generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { createServer, type Server, type ServerResponse } from "node:http";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  mkdirSync,
  chmodSync,
  statSync,
  readdirSync,
  symlinkSync,
  lstatSync,
  utimesSync,
  linkSync,
} from "node:fs";
import { tmpdir, hostname } from "node:os";
import { join } from "node:path";
import { TransparencyLog, InMemoryLogStore } from "../src/log-store.js";
import { canonicalizeSth, leafHash, treeRoot } from "../src/transparency.js";

const CLI = join(__dirname, "..", "bin", "witness.mjs");

let tmp: string;
let witnessKeyPath: string;
let statePath: string;
let server: Server;
let serverUrl: string;
let log: TransparencyLog;
let serverPrivKey: ReturnType<typeof generateKeyPairSync>["privateKey"];

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[]): CliResult {
  const r = spawnSync("node", [CLI, ...args], {
    encoding: "utf8",
    timeout: 4_000,
  });
  return {
    status: r.status,
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
  };
}

function signSth(sthCanonical: string): string {
  const sig = sign(null, Buffer.from(sthCanonical, "utf8"), serverPrivKey);
  return "v2=" + sig.toString("base64");
}

beforeAll(async () => {
  tmp = mkdtempSync(join(tmpdir(), "vr-witness-"));
  witnessKeyPath = join(tmp, "witness.pem");
  statePath = join(tmp, "state.json");

  // Witness keypair (used by the CLI to sign STHs)
  const witnessKp = generateKeyPairSync("ed25519");
  writeFileSync(
    witnessKeyPath,
    witnessKp.privateKey.export({ format: "pem", type: "pkcs8" }) as string,
  );

  // Server keypair (used by the mock server to sign its STH envelopes)
  const serverKp = generateKeyPairSync("ed25519");
  serverPrivKey = serverKp.privateKey;

  // Initialize the demo log + append three leaves
  log = new TransparencyLog("test-log", new InMemoryLogStore());
  log.append("leaf-0");
  log.append("leaf-1");
  log.append("leaf-2");

  // Stand up a minimal HTTP server that implements
  //   GET  /api/transparency/sth
  //   GET  /api/transparency/proof?kind=consistency&old=N&new=M
  //   POST /api/transparency/witness
  const submissions: Array<Record<string, unknown>> = [];
  // Expose `submissions` via a shared variable for assertions if needed.
  (globalThis as Record<string, unknown>).__witnessSubmissions = submissions;

  server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost`);
    if (req.method === "GET" && url.pathname === "/api/transparency/sth") {
      const sth = log.currentSth();
      const canonical = canonicalizeSth(sth);
      const signature = signSth(canonical);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ...sth, signature, canonical }));
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/transparency/proof") {
      const kind = url.searchParams.get("kind");
      if (kind === "consistency") {
        const oldSize = Number(url.searchParams.get("old"));
        const newSize = Number(url.searchParams.get("new"));
        const proof = log.proveConsistency(oldSize, newSize);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            kind: "consistency",
            logId: log.logId,
            oldSize,
            newSize,
            proof,
          }),
        );
        return;
      }
      res.writeHead(400);
      res.end();
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/transparency/witness") {
      let body = "";
      for await (const chunk of req) body += chunk;
      const parsed = JSON.parse(body) as Record<string, unknown>;
      submissions.push(parsed);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          ok: true,
          recorded: true,
          firstForThisSth: submissions.length === 1,
          witnessCount: submissions.length,
        }),
      );
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => {
    server.listen(0, () => resolve());
  });
  const addr = server.address();
  if (!addr || typeof addr === "string") {
    throw new Error("server has no address");
  }
  serverUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  rmSync(tmp, { recursive: true, force: true });
});

describe("witness CLI — argv parsing", () => {
  it("--help prints usage + exits 0", () => {
    const r = runCli(["--help"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/verifiable-receipts-witness/);
    expect(r.stdout).toMatch(/Exit codes/);
  });

  it("exits 2 when --url is missing", () => {
    const r = runCli([
      "--key",
      witnessKeyPath,
      "--witness-id",
      "Test",
      "--once",
    ]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--url/);
  });

  it("exits 2 when --key is missing", () => {
    const r = runCli(["--url", "http://x", "--witness-id", "Test", "--once"]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--key/);
  });

  it("exits 2 when --witness-id is missing", () => {
    const r = runCli(["--url", "http://x", "--key", witnessKeyPath, "--once"]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/witness-id/);
  });
});

// The flow tests below spawn the witness CLI with an asynchronous
// spawn and let it fetch from and post to the in-process HTTP server.
// (With spawnSync they cannot pass: it blocks this process's event
// loop, so the server never answers.)
describe("witness CLI — full witness flow (--once)", () => {
  it("first-time witness: signs + submits + writes state file", async () => {
    // Reset state for this test
    if (existsSync(statePath)) rmSync(statePath);

    const r = await runCliAsync([
      "--url",
      serverUrl,
      "--key",
      witnessKeyPath,
      "--witness-id",
      "Test Witness",
      "--state",
      statePath,
      "--once",
      "--json",
    ]);
    expect(r.status).toBe(0);
    const out = JSON.parse(r.stdout) as {
      verdict: string;
      treeSize: number;
      totalWitnesses: number;
    };
    expect(out.verdict).toBe("witnessed");
    expect(out.treeSize).toBe(3);
    expect(out.totalWitnesses).toBeGreaterThan(0);
    expect(existsSync(statePath)).toBe(true);
    const state = JSON.parse(readFileSync(statePath, "utf8")) as {
      lastSize: number;
      lastRoot: string;
    };
    expect(state.lastSize).toBe(3);
    expect(state.lastRoot.length).toBe(64);
  });

  it("second run with no log change: reports 'no-change' + exits 0", async () => {
    // state file already exists from previous test with lastSize=3
    const r = await runCliAsync([
      "--url",
      serverUrl,
      "--key",
      witnessKeyPath,
      "--witness-id",
      "Test Witness",
      "--state",
      statePath,
      "--once",
      "--json",
    ]);
    expect(r.status).toBe(0);
    const out = JSON.parse(r.stdout) as { verdict: string };
    expect(out.verdict).toBe("no-change");
  });

  it("after the log grows: re-witnesses with consistency proof", async () => {
    // Grow the log to size 7
    log.append("leaf-3");
    log.append("leaf-4");
    log.append("leaf-5");
    log.append("leaf-6");

    const r = await runCliAsync([
      "--url",
      serverUrl,
      "--key",
      witnessKeyPath,
      "--witness-id",
      "Test Witness",
      "--state",
      statePath,
      "--once",
      "--json",
    ]);
    expect(r.status).toBe(0);
    const out = JSON.parse(r.stdout) as {
      verdict: string;
      treeSize: number;
    };
    expect(out.verdict).toBe("witnessed");
    expect(out.treeSize).toBe(7);
  });
});

describe("witness CLI — fork detection", () => {
  it("when the state's lastSize > current treeSize, reports 'fork-detected' exit 1", async () => {
    // Write a state pointing to a tree-size that's BEYOND what the log has.
    // This simulates a forked / rewound log scenario.
    const forkedState = {
      lastSize: 999,
      lastRoot: "a".repeat(64),
      lastTimestamp: "2026-01-01T00:00:00.000Z",
      lastSubmittedAt: "2026-01-01T00:00:00.000Z",
    };
    const forkedPath = join(tmp, "forked-state.json");
    writeFileSync(forkedPath, JSON.stringify(forkedState));

    const r = await runCliAsync([
      "--url",
      serverUrl,
      "--key",
      witnessKeyPath,
      "--witness-id",
      "Fork Detector",
      "--state",
      forkedPath,
      "--once",
      "--json",
    ]);
    expect(r.status).toBe(1);
  });
});

// ── Checks before cosigning ───────────────────────────────────────────
//
// These tests run the CLI with an asynchronous spawn: spawnSync blocks
// this process's event loop, so the in-process mock log above could
// never answer the CLI's requests. Each test gets its own log server
// whose STH response it can rewrite, and records every request.

interface Req {
  method: string;
  path: string;
  body?: Record<string, unknown>;
}

function runCliAsync(
  args: string[],
  nodeArgs: string[] = [],
  env: Record<string, string> = {},
): Promise<CliResult> {
  return new Promise((resolve) => {
    const child = spawn("node", [...nodeArgs, CLI, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, ...env },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
    // Kill before vitest's 5 s test timeout, so a hung CLI shows up as
    // a failed assertion with its output rather than a bare timeout.
    const timer = setTimeout(() => child.kill("SIGKILL"), 4_000);
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr });
    });
  });
}

/**
 * Start the CLI in daemon mode (no --once). `waitFor` resolves when
 * stderr matches; `exited` resolves with the exit status.
 */
function startDaemon(args: string[]) {
  const child = spawn("node", [CLI, ...args], { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  let status: number | null | undefined;
  const waiters: Array<() => void> = [];
  const poke = () => waiters.splice(0).forEach((w) => w());
  child.stdout.on("data", (d: Buffer) => ((stdout += d.toString("utf8")), poke()));
  child.stderr.on("data", (d: Buffer) => ((stderr += d.toString("utf8")), poke()));
  const exited = new Promise<number | null>((resolve) =>
    child.on("close", (code) => ((status = code), poke(), resolve(code))),
  );
  const killer = setTimeout(() => child.kill("SIGKILL"), 4_000);
  child.on("close", () => clearTimeout(killer));
  const waitFor = (re: RegExp) =>
    new Promise<void>((resolve, reject) => {
      const check = () => {
        if (re.test(stderr)) resolve();
        else if (status !== undefined) reject(new Error(`exited ${status}; stderr: ${stderr}`));
        else waiters.push(check);
      };
      check();
    });
  return {
    child,
    exited,
    waitFor,
    running: () => status === undefined,
    output: () => ({ stdout, stderr }),
  };
}

const EMPTY_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

describe("witness CLI — checks before cosigning (--once)", () => {
  let dir: string;
  let witnessKey: string;
  let witnessPub: KeyObject;
  let logPubPath: string;
  let logPriv: KeyObject;
  let otherPriv: KeyObject;
  let tlog: TransparencyLog;
  let srv: Server;
  let base: string;
  let requests: Req[];
  // Rewrites the STH body the log serves; identity by default.
  let rewrite: (body: Record<string, unknown>) => Record<string, unknown>;
  // Status codes for the next POSTs (200 once the queue is empty). A
  // non-200 still records the body: a log that keeps the cosignature
  // and answers 500.
  let postStatus: number[];
  // Replaces the STH response entirely (oversized or stalled bodies).
  let sthHandler: ((res: ServerResponse) => void) | undefined;
  // Replace the proof and POST responses entirely.
  let proofHandler: ((res: ServerResponse, url: URL) => void) | undefined;
  let postHandler: ((res: ServerResponse) => void) | undefined;
  // A second host, to check that redirects are never followed.
  let other: Server;
  let otherBase: string;
  let otherHits = 0;
  let stateN = 0;

  const signWith = (key: KeyObject, text: string) =>
    "v2=" + sign(null, Buffer.from(text, "utf8"), key).toString("base64");

  // The STH the honest log would serve, before any rewrite.
  const honest = () => {
    const sth = tlog.currentSth();
    const canonical = canonicalizeSth(sth);
    return { ...sth, signature: signWith(logPriv, canonical), canonical };
  };

  const posts = () => requests.filter((r) => r.method === "POST");
  // The five signed fields of an STH body.
  const fieldsOf = (b: Record<string, unknown>) => ({
    v: b.v,
    logId: b.logId,
    rootHash: b.rootHash,
    timestamp: b.timestamp,
    treeSize: b.treeSize,
  });
  const freshState = () => join(dir, `state-${++stateN}.json`);
  const args = (state: string, extra: string[] = []) => [
    "--url", base, "--key", witnessKey, "--witness-id", "checks",
    "--state", state, "--once", "--json", ...extra,
  ];
  const verdictOf = (r: CliResult) =>
    JSON.parse(r.stdout.trim().split("\n").pop() ?? "{}") as Record<string, unknown>;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "vr-witness-checks-"));
    const wkp = generateKeyPairSync("ed25519");
    witnessKey = join(dir, "witness.pem");
    writeFileSync(witnessKey, wkp.privateKey.export({ format: "pem", type: "pkcs8" }) as string);
    witnessPub = wkp.publicKey;
    const lkp = generateKeyPairSync("ed25519");
    logPriv = lkp.privateKey;
    logPubPath = join(dir, "log.pub.pem");
    writeFileSync(logPubPath, lkp.publicKey.export({ format: "pem", type: "spki" }) as string);
    otherPriv = generateKeyPairSync("ed25519").privateKey;

    // A fixed clock, so the head the test expects is the one the log served.
    tlog = new TransparencyLog(
      "test-log",
      new InMemoryLogStore(),
      () => new Date("2026-10-24T08:00:00.000Z"),
    );
    tlog.append("leaf-0");
    tlog.append("leaf-1");
    tlog.append("leaf-2");

    srv = createServer((req, res) => {
      void (async () => {
        const url = new URL(req.url ?? "/", "http://localhost");
        const entry: Req = { method: req.method ?? "", path: url.pathname };
        requests.push(entry);
        if (req.method === "GET" && url.pathname === "/api/transparency/sth") {
          if (sthHandler) {
            sthHandler(res);
            return;
          }
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(rewrite(honest())));
          return;
        }
        if (req.method === "GET" && url.pathname === "/api/transparency/proof") {
          if (proofHandler) {
            proofHandler(res, url);
            return;
          }
          const proof = tlog.proveConsistency(
            Number(url.searchParams.get("old")),
            Number(url.searchParams.get("new")),
          );
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ kind: "consistency", proof }));
          return;
        }
        if (req.method === "POST" && url.pathname === "/api/transparency/witness") {
          let text = "";
          for await (const chunk of req) text += String(chunk);
          entry.body = JSON.parse(text) as Record<string, unknown>;
          if (postHandler) {
            postHandler(res);
            return;
          }
          const status = postStatus.shift() ?? 200;
          if (status !== 200) {
            res.writeHead(status, { "content-type": "text/plain" });
            res.end("stored it, but answering an error");
            return;
          }
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true, witnessCount: posts().length }));
          return;
        }
        res.writeHead(404);
        res.end();
      })();
    });
    await new Promise<void>((resolve) => srv.listen(0, "127.0.0.1", () => resolve()));
    const addr = srv.address();
    if (!addr || typeof addr === "string") throw new Error("server has no address");
    base = `http://127.0.0.1:${addr.port}`;

    other = createServer((_req, res) => {
      otherHits++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
    await new Promise<void>((resolve) => other.listen(0, "127.0.0.1", () => resolve()));
    const oaddr = other.address();
    if (!oaddr || typeof oaddr === "string") throw new Error("server has no address");
    otherBase = `http://127.0.0.1:${oaddr.port}`;
  });

  afterAll(async () => {
    other.closeAllConnections();
    await new Promise<void>((resolve) => other.close(() => resolve()));
    srv.closeAllConnections();
    await new Promise<void>((resolve) => srv.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  });

  beforeEach(() => {
    requests = [];
    rewrite = (b) => b;
    postStatus = [];
    sthHandler = undefined;
    proofHandler = undefined;
    postHandler = undefined;
    otherHits = 0;
  });

  it("happy path: cosigns the canonical rebuilt from the fields it checked", async () => {
    const state = freshState();
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(0);
    expect(verdictOf(r).verdict).toBe("witnessed");
    expect(posts()).toHaveLength(1);
    const body = posts()[0].body ?? {};
    const expected = canonicalizeSth(tlog.currentSth());
    expect(body.sthCanonical).toBe(expected);
    const sig = String(body.signature);
    expect(sig.startsWith("v2=")).toBe(true);
    expect(
      verify(null, Buffer.from(expected, "utf8"), witnessPub, Buffer.from(sig.slice(3), "base64")),
    ).toBe(true);
    const saved = JSON.parse(readFileSync(state, "utf8")) as Record<string, unknown>;
    expect(saved.logId).toBe("test-log");
    expect(saved.lastSize).toBe(3);
  });

  it("without --log-public-key, says the log signature was not checked", async () => {
    const r = await runCliAsync(args(freshState()).filter((a) => a !== "--json"));
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/\[witness\] log signature NOT checked/);
    expect(posts()).toHaveLength(1);
  });

  it.each([
    ["a different root", { rootHash: "b".repeat(64) }],
    ["a different size", { treeSize: 4 }],
    ["a different timestamp", { timestamp: "2020-01-01T00:00:00.000Z" }],
    ["a different logId", { logId: "other-log" }],
  ])("refuses a canonical naming %s than the fields", async (_name, change) => {
    rewrite = (b) => {
      const canonical = canonicalizeSth({ ...fieldsOf(b), ...change } as never);
      return { ...b, canonical, signature: signWith(logPriv, canonical) };
    };
    const r = await runCliAsync(args(freshState()));
    expect(r.status).toBe(1);
    expect(verdictOf(r).verdict).toBe("canonical-mismatch");
    expect(posts()).toHaveLength(0);
  });

  it("refuses a canonical with the same fields in another spelling", async () => {
    rewrite = (b) => {
      return { ...b, canonical: JSON.stringify(fieldsOf(b), null, 1) };
    };
    const r = await runCliAsync(args(freshState()));
    expect(r.status).toBe(1);
    expect(verdictOf(r).verdict).toBe("canonical-mismatch");
    expect(posts()).toHaveLength(0);
  });

  it.each([
    ["v is 2", { v: 2 }],
    ["v is the string 1", { v: "1" }],
    ["logId is empty", { logId: "" }],
    ["logId is a number", { logId: 7 }],
    ["rootHash is uppercase", { rootHash: "A".repeat(64) }],
    ["rootHash is 63 digits", { rootHash: "a".repeat(63) }],
    ["rootHash has a 0x prefix", { rootHash: "0x" + "a".repeat(64) }],
    ["treeSize is a fraction", { treeSize: 2.5 }],
    ["treeSize is negative", { treeSize: -1 }],
    ["treeSize is 2^53", { treeSize: 2 ** 53 }],
    ["treeSize is a string", { treeSize: "3" }],
    ["timestamp has no milliseconds", { timestamp: "2026-10-24T00:00:00Z" }],
    ["timestamp has an offset", { timestamp: "2026-10-24T02:00:00.000+02:00" }],
    ["timestamp is not a real date", { timestamp: "2026-02-30T00:00:00.000Z" }],
    ["timestamp is a number", { timestamp: 1761264000000 }],
    ["signature is not v2= or v3=", { signature: "v1=" + "A".repeat(86) + "==" }],
    ["signature is short", { signature: "v2=AAAA" }],
    ["signature has non-zero padding bits", { signature: "v2=" + "A".repeat(85) + "B==" }],
    ["it has a field the schema does not allow", { note: "not signed" }],
    ["it has a field named like a signed one", { treesize: 3 }],
    ["logId has a newline", { logId: "x\n[witness] log signature OK" }],
    ["logId has a carriage return", { logId: "x\r[witness] log signature OK" }],
    ["logId has U+2028", { logId: "x\u2028y" }],
    ["logId has U+2029", { logId: "x\u2029y" }],
    ["logId has a DEL", { logId: "x\u007fy" }],
    ["treeSize is 0 with a non-empty root", { treeSize: 0, rootHash: "a".repeat(64) }],
  ])("refuses a malformed STH: %s", async (_name, change) => {
    rewrite = (b) => {
      const changed: Record<string, unknown> = { ...b, ...change };
      // A canonical that matches the (malformed) fields, so only the
      // shape check can stop it.
      return { ...changed, canonical: canonicalizeSth(fieldsOf(changed) as never) };
    };
    const r = await runCliAsync(args(freshState()));
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("malformed-sth");
    expect(r.stdout + r.stderr).not.toMatch(/cosignature submitted/);
    expect(posts()).toHaveLength(0);
  });

  it("refuses a head from a different logId than the saved state", async () => {
    const state = freshState();
    const sth = tlog.currentSth();
    writeFileSync(
      state,
      JSON.stringify({ logId: "other-log", lastSize: sth.treeSize, lastRoot: sth.rootHash }),
    );
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(1);
    expect(verdictOf(r).verdict).toBe("log-id-mismatch");
    expect(posts()).toHaveLength(0);
  });

  it("reports the same size with a different root as a fork, without asking for a proof", async () => {
    const state = freshState();
    writeFileSync(
      state,
      JSON.stringify({ logId: "test-log", lastSize: 3, lastRoot: "a".repeat(64) }),
    );
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(1);
    const v = verdictOf(r);
    expect(v.verdict).toBe("fork-detected");
    expect(v.reason).toBe("same-size-different-root");
    expect(requests.filter((q) => q.path === "/api/transparency/proof")).toHaveLength(0);
    expect(posts()).toHaveLength(0);
  });

  it("with --log-public-key, refuses a head signed by another key", async () => {
    rewrite = (b) => ({ ...b, signature: signWith(otherPriv, String(b.canonical)) });
    const r = await runCliAsync(args(freshState(), ["--log-public-key", logPubPath]));
    expect(r.status).toBe(1);
    expect(verdictOf(r).verdict).toBe("bad-log-signature");
    expect(posts()).toHaveLength(0);
  });

  it("with --log-public-key, refuses a head with no signature", async () => {
    rewrite = (b) => {
      const rest = { ...b };
      delete rest.signature;
      return rest;
    };
    const r = await runCliAsync(args(freshState(), ["--log-public-key", logPubPath]));
    expect(r.status).toBe(1);
    expect(verdictOf(r).verdict).toBe("bad-log-signature");
    expect(posts()).toHaveLength(0);
  });

  it("with --log-public-key, refuses a v3= head instead of checking half of it", async () => {
    const v3 =
      "v3=" + Buffer.alloc(64, 1).toString("base64") + "." + Buffer.alloc(3309, 2).toString("base64");
    rewrite = (b) => ({ ...b, signature: v3 });
    const r = await runCliAsync(args(freshState(), ["--log-public-key", logPubPath]));
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("unsupported-log-signature");
    expect(posts()).toHaveLength(0);
  });

  it("with --log-public-key, cosigns a head the log signed", async () => {
    const r = await runCliAsync(
      args(freshState(), ["--log-public-key", logPubPath]).filter((a) => a !== "--json"),
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/\[witness\] log signature OK/);
    expect(r.stdout).not.toMatch(/NOT checked/);
    expect(posts()).toHaveLength(1);
  });

  it.each([
    ["is not JSON", "{ lastSize: 3"],
    ["is JSON null", "null"],
    ["is a JSON array", "[]"],
    ["has lastSize negative", JSON.stringify({ lastSize: -1, lastRoot: "a".repeat(64) })],
    ["has lastSize a fraction", JSON.stringify({ lastSize: 1.5, lastRoot: "a".repeat(64) })],
    ["has lastSize a string", JSON.stringify({ lastSize: "3", lastRoot: "a".repeat(64) })],
    ["has no lastSize", JSON.stringify({ lastRoot: "a".repeat(64) })],
    ["has lastRoot uppercase", JSON.stringify({ lastSize: 3, lastRoot: "A".repeat(64) })],
    ["has no lastRoot", JSON.stringify({ lastSize: 3 })],
    ["has logId empty", JSON.stringify({ logId: "", lastSize: 3, lastRoot: "a".repeat(64) })],
    ["has logId a number", JSON.stringify({ logId: 7, lastSize: 3, lastRoot: "a".repeat(64) })],
    ["has lastSize 0 with a non-empty root", JSON.stringify({ lastSize: 0, lastRoot: "a".repeat(64) })],
    ["has logId with a newline", JSON.stringify({ logId: "a\nb", lastSize: 3, lastRoot: "a".repeat(64) })],
  ])("fails closed on a state file that %s", async (_name, text) => {
    const state = freshState();
    writeFileSync(state, text);
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("bad-state");
    expect(posts()).toHaveLength(0);
    // The bad file is left as it was for the operator to inspect.
    expect(readFileSync(state, "utf8")).toBe(text);
  });

  it("fails closed on a state file that cannot be read", async () => {
    const state = freshState();
    mkdirSync(state); // a directory where the file should be
    const r = await runCliAsync(args(state).filter((a) => a !== "--json"));
    expect(r.status).toBe(2);
    expect(r.stdout).toMatch(/\[witness\] BAD STATE FILE/);
    expect(posts()).toHaveLength(0);
  });

  // ── Review round: state before signature, empty tree, flags, network ──

  const headWith = (b: Record<string, unknown>, change: Record<string, unknown>) => {
    const changed: Record<string, unknown> = { ...b, ...change };
    const canonical = canonicalizeSth(fieldsOf(changed) as never);
    return { ...changed, canonical, signature: signWith(logPriv, canonical) };
  };

  it("POST answers 500, then a conflicting head of the same size: fork, no second POST", async () => {
    const state = freshState();
    postStatus = [500];
    const first = await runCliAsync(args(state));
    expect(first.status).toBe(2);
    expect(verdictOf(first).verdict).toBe("submit-failed");
    expect(posts()).toHaveLength(1);
    const saved = JSON.parse(readFileSync(state, "utf8")) as Record<string, unknown>;
    expect(saved.lastSize).toBe(3);
    expect(saved.lastRoot).toBe(tlog.currentSth().rootHash);
    expect(saved.pending).toBe(true);

    // Same size, another root, and a "valid" proof from the log's view.
    rewrite = (b) => headWith(b, { rootHash: "d".repeat(64) });
    const second = await runCliAsync(args(state));
    expect(second.status).toBe(1);
    const v = verdictOf(second);
    expect(v.verdict).toBe("fork-detected");
    expect(v.reason).toBe("same-size-different-root");
    expect(posts()).toHaveLength(1);
  });

  it("POST answers 500, then the same head: resubmits once, then reports no change", async () => {
    const state = freshState();
    postStatus = [500];
    const first = await runCliAsync(args(state));
    expect(first.status).toBe(2);
    const second = await runCliAsync(args(state));
    expect(second.status).toBe(0);
    expect(verdictOf(second).verdict).toBe("resubmitted");
    expect(posts()).toHaveLength(2);
    // The log serves the same timestamp here (a fixed clock), so the
    // rebuilt canonical is the same. A log that changes the timestamp
    // is covered by the next test.
    expect(posts()[1].body).toEqual(posts()[0].body);
    const saved = JSON.parse(readFileSync(state, "utf8")) as Record<string, unknown>;
    expect(saved.pending).toBeUndefined();
    expect(typeof saved.lastSubmittedAt).toBe("string");
    const third = await runCliAsync(args(state));
    expect(third.status).toBe(0);
    expect(verdictOf(third).verdict).toBe("no-change");
    expect(posts()).toHaveLength(2);
  });

  it("a state directory it cannot write: no lock, no signature, no POST", async () => {
    const locked = join(dir, `locked-${++stateN}`);
    mkdirSync(locked);
    chmodSync(locked, 0o500);
    try {
      const r = await runCliAsync(args(join(locked, "state.json")));
      expect(r.status).toBe(2);
      // The lock file sits beside the state file, so taking it fails first.
      expect(verdictOf(r).verdict).toBe("state-unwritable");
      expect(String(verdictOf(r).message)).toMatch(/writable/);
      expect(requests.filter((q) => q.method === "GET")).toHaveLength(0);
      expect(posts()).toHaveLength(0);
    } finally {
      chmodSync(locked, 0o700);
    }
  });

  it("a state save that fails: no signature leaves, no POST", async () => {
    // Preloaded into the CLI: every renameSync fails, as a full disk or
    // an I/O error would.
    const preload = join(dir, "rename-fails.mjs");
    writeFileSync(
      preload,
      [
        'import fs from "node:fs";',
        'import { syncBuiltinESMExports } from "node:module";',
        "fs.renameSync = () => {",
        '  throw Object.assign(new Error("EIO: simulated rename failure"), { code: "EIO" });',
        "};",
        "syncBuiltinESMExports();",
      ].join("\n"),
    );
    const sub = join(dir, `save-fails-${++stateN}`);
    mkdirSync(sub);
    const state = join(sub, "state.json");
    const r = await runCliAsync(args(state), ["--import", preload]);
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("state-save-failed");
    expect(posts()).toHaveLength(0);
    // No state, no temporary file, no lock left behind.
    expect(readdirSync(sub)).toEqual([]);
  });

  it("saves the state by renaming a new file over it, leaving no temporary file", async () => {
    // A prior head at size 2, so the run replaces an existing file.
    const sub = join(dir, `atomic-${++stateN}`);
    mkdirSync(sub);
    const state = join(sub, "state.json");
    const root2 = treeRoot([leafHash("leaf-0"), leafHash("leaf-1")]);
    const original = JSON.stringify({ logId: "test-log", lastSize: 2, lastRoot: root2 });
    writeFileSync(state, original);
    // A second name for the original file keeps its inode allocated for
    // the whole run, so the file system cannot hand that inode number to
    // a new file (ext4 reuses a freed inode at once).
    const orig = state + ".orig";
    linkSync(state, orig);
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(0);
    expect(verdictOf(r).verdict).toBe("witnessed");
    // A rename puts another file at the path; the original is untouched.
    // Writing in place would change the original's bytes, seen through
    // the second name, and leave one inode behind both names.
    expect(statSync(state).ino).not.toBe(statSync(orig).ino);
    expect(readFileSync(orig, "utf8")).toBe(original);
    expect(readdirSync(sub).sort()).toEqual(["state.json", "state.json.orig"]);
  });

  it("prints the logId JSON-quoted, so it cannot forge a [witness] line", async () => {
    rewrite = (b) => headWith(b, { logId: "x [witness] log signature OK" });
    const r = await runCliAsync(args(freshState()).filter((a) => a !== "--json"));
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('logId="x [witness] log signature OK"');
    expect(r.stdout.split("\n").filter((l) => l.startsWith("[witness] log signature OK"))).toHaveLength(0);
  });

  it("refuses a consistency proof that does not fold, with prior state", async () => {
    const state = freshState();
    writeFileSync(state, JSON.stringify({ logId: "test-log", lastSize: 2, lastRoot: "a".repeat(64) }));
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(1);
    const v = verdictOf(r);
    expect(v.verdict).toBe("fork-detected");
    expect(v.reason).toBe("consistency-proof-failed");
    expect(posts()).toHaveLength(0);
  });

  it("cosigns an empty tree whose root is SHA-256 of nothing", async () => {
    rewrite = (b) => headWith(b, { treeSize: 0, rootHash: EMPTY_ROOT });
    const r = await runCliAsync(args(freshState()));
    expect(r.status).toBe(0);
    expect(verdictOf(r).verdict).toBe("witnessed");
    expect(posts()).toHaveLength(1);
  });

  it("goes on from a saved empty tree to a larger one", async () => {
    const state = freshState();
    writeFileSync(state, JSON.stringify({ logId: "test-log", lastSize: 0, lastRoot: EMPTY_ROOT }));
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(0);
    expect(verdictOf(r).verdict).toBe("witnessed");
    expect(posts()).toHaveLength(1);
  });

  it("--log-id refuses a head for another log, even on the first run", async () => {
    const r = await runCliAsync(args(freshState(), ["--log-id", "other-log"]));
    expect(r.status).toBe(1);
    expect(verdictOf(r).verdict).toBe("log-id-mismatch");
    expect(posts()).toHaveLength(0);
  });

  it("--log-id accepts a head for that log", async () => {
    const r = await runCliAsync(args(freshState(), ["--log-id", "test-log"]));
    expect(r.status).toBe(0);
    expect(verdictOf(r).verdict).toBe("witnessed");
  });

  it("refuses an oversized STH body without reading it all", async () => {
    sthHandler = (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      const chunk = " ".repeat(64 * 1024);
      for (let i = 0; i < 32; i++) res.write(chunk); // 2 MiB, chunked
      res.end("{}");
    };
    const r = await runCliAsync(args(freshState()));
    expect(r.status).toBe(2);
    expect(r.stdout.trim().split("\n")).toHaveLength(1);
    const v = verdictOf(r);
    expect(v.verdict).toBe("fetch-failed");
    expect(String(v.message)).toMatch(/too large/);
    expect(posts()).toHaveLength(0);
  });

  it("gives up on a stalled STH body after --timeout", async () => {
    sthHandler = (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write('{"v":1'); // and never finish
    };
    const started = Date.now();
    const r = await runCliAsync(args(freshState(), ["--timeout", "1"]));
    expect(r.status).toBe(2);
    expect(r.stdout.trim().split("\n")).toHaveLength(1);
    const v = verdictOf(r);
    expect(v.verdict).toBe("fetch-failed");
    expect(String(v.message)).toMatch(/timed out/);
    expect(Date.now() - started).toBeLessThan(3_500);
    expect(posts()).toHaveLength(0);
  });

  it("daemon: an exit-1 verdict halts it, with a stderr line", async () => {
    const state = freshState();
    writeFileSync(state, JSON.stringify({ logId: "test-log", lastSize: 3, lastRoot: "a".repeat(64) }));
    const d = startDaemon(args(state).filter((a) => a !== "--once"));
    expect(await d.exited).toBe(1);
    expect(d.output().stderr).toMatch(/\[witness\] fork-detected .*halting/);
    expect(posts()).toHaveLength(0);
  });

  it("daemon: an exit-2 verdict is reported on stderr and it keeps running", async () => {
    const state = freshState();
    writeFileSync(state, "not json");
    const d = startDaemon(args(state).filter((a) => a !== "--once"));
    try {
      await d.waitFor(/\[witness\] bad-state .*retry/);
      await new Promise((r) => setTimeout(r, 300));
      expect(d.running()).toBe(true);
      expect(posts()).toHaveLength(0);
    } finally {
      d.child.kill("SIGKILL");
      await d.exited;
    }
  });

  // ── Second review: one process per state file, the saved head ──

  const waitUntil = async (cond: () => boolean) => {
    const until = Date.now() + 3_000;
    while (!cond()) {
      if (Date.now() > until) throw new Error("condition not met");
      await new Promise((r) => setTimeout(r, 10));
    }
  };

  it("two runs on one state file: one signs, the other is refused as state-locked", async () => {
    const state = freshState();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held = 0;
    sthHandler = (res) => {
      held++;
      void gate.then(() => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(honest()));
      });
    };
    const a = runCliAsync(args(state));
    await waitUntil(() => held === 1);
    const b = await runCliAsync(args(state));
    release();
    const ra = await a;
    expect(b.status).toBe(2);
    expect(verdictOf(b).verdict).toBe("state-locked");
    expect(ra.status).toBe(0);
    expect(verdictOf(ra).verdict).toBe("witnessed");
    expect(posts()).toHaveLength(1);
    expect(existsSync(state + ".lock")).toBe(false);
  });

  it("recovers a lock whose lease has expired", async () => {
    const state = freshState();
    const dead = spawnSync("node", ["-e", ""]).pid;
    writeFileSync(state + ".lock", JSON.stringify({ pid: dead, startedAt: "2026-10-24T00:00:00.000Z" }));
    expireLease(state + ".lock");
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(0);
    expect(verdictOf(r).verdict).toBe("witnessed");
    expect(r.stderr).toMatch(/stale lock/);
    expect(posts()).toHaveLength(1);
    expect(existsSync(state + ".lock")).toBe(false);
  });

  it("refuses while a live process holds the lock, and leaves its lock alone", async () => {
    const state = freshState();
    const lock = JSON.stringify({ pid: process.pid, startedAt: "2026-10-24T00:00:00.000Z" });
    writeFileSync(state + ".lock", lock);
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("state-locked");
    expect(posts()).toHaveLength(0);
    expect(readFileSync(state + ".lock", "utf8")).toBe(lock);
  });

  it("refuses rather than steal a lock it cannot read", async () => {
    const state = freshState();
    writeFileSync(state + ".lock", "not json");
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("state-locked");
    expect(posts()).toHaveLength(0);
    expect(readFileSync(state + ".lock", "utf8")).toBe("not json");
  });

  it("POST answers 500, then the head with a new timestamp: resubmits the saved head byte for byte", async () => {
    const state = freshState();
    postStatus = [500];
    const first = await runCliAsync(args(state));
    expect(first.status).toBe(2);
    rewrite = (b) => headWith(b, { timestamp: "2026-10-24T09:00:00.000Z" });
    const second = await runCliAsync(args(state).filter((a) => a !== "--json"));
    expect(second.status).toBe(0);
    expect(second.stdout).toMatch(/re-signed/);
    expect(posts()).toHaveLength(2);
    expect(posts()[1].body).toEqual(posts()[0].body);
    const saved = JSON.parse(readFileSync(state, "utf8")) as Record<string, unknown>;
    expect(saved.lastTimestamp).toBe("2026-10-24T08:00:00.000Z");
    expect(saved.pending).toBeUndefined();
  });

  it("refuses a head dated before the one it last saved", async () => {
    const state = freshState();
    const first = await runCliAsync(args(state));
    expect(first.status).toBe(0);
    rewrite = (b) => headWith(b, { timestamp: "2001-01-01T00:00:00.000Z" });
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(1);
    expect(verdictOf(r).verdict).toBe("timestamp-decreased");
    expect(posts()).toHaveLength(1);
  });

  it("refuses a pending head re-dated earlier", async () => {
    const state = freshState();
    postStatus = [500];
    await runCliAsync(args(state));
    rewrite = (b) => headWith(b, { timestamp: "2001-01-01T00:00:00.000Z" });
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(1);
    expect(verdictOf(r).verdict).toBe("timestamp-decreased");
    expect(posts()).toHaveLength(1);
  });

  it("escapes NEL, U+2028 and U+2029 in a log's error body", async () => {
    postHandler = (res) => {
      res.writeHead(500, { "content-type": "text/plain" });
      res.end("a\u0085[witness] forged\u2028[witness] forged\u2029[witness] forged");
    };
    const text = await runCliAsync(args(freshState()).filter((a) => a !== "--json"));
    expect(text.status).toBe(2);
    const all = text.stdout + text.stderr;
    expect(all).not.toMatch(/[\u0085\u2028\u2029]/);
    expect(all).toContain("\\u0085");
    expect(all).toContain("\\u2028");
    const json = await runCliAsync(args(freshState()));
    expect(json.stdout).not.toMatch(/[\u0085\u2028\u2029]/);
    expect(json.stdout.trim().split("\n")).toHaveLength(1);
  });

  it("does not follow a redirect on the STH fetch", async () => {
    sthHandler = (res) => {
      res.writeHead(302, { location: `${otherBase}/api/transparency/sth` });
      res.end();
    };
    const r = await runCliAsync(args(freshState()));
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("fetch-failed");
    expect(otherHits).toBe(0);
    expect(posts()).toHaveLength(0);
  });

  it("does not follow a redirect on the cosignature POST", async () => {
    postHandler = (res) => {
      res.writeHead(307, { location: `${otherBase}/api/transparency/witness` });
      res.end();
    };
    const r = await runCliAsync(args(freshState()));
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("submit-failed");
    expect(otherHits).toBe(0);
  });

  it("--json: a failed proof fetch is one fetch-failed line", async () => {
    const state = freshState();
    const root2 = treeRoot([leafHash("leaf-0"), leafHash("leaf-1")]);
    writeFileSync(state, JSON.stringify({ logId: "test-log", lastSize: 2, lastRoot: root2 }));
    proofHandler = (res) => {
      res.writeHead(503);
      res.end();
    };
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(2);
    expect(r.stdout.trim().split("\n")).toHaveLength(1);
    expect(verdictOf(r).verdict).toBe("fetch-failed");
    expect(posts()).toHaveLength(0);
  });

  it("--json: a failed STH fetch is one fetch-failed line", async () => {
    sthHandler = (res) => {
      res.writeHead(500);
      res.end();
    };
    const r = await runCliAsync(args(freshState()));
    expect(r.status).toBe(2);
    expect(r.stdout.trim().split("\n")).toHaveLength(1);
    expect(verdictOf(r).verdict).toBe("fetch-failed");
  });

  it.each(["0", "3601", "abc", "-5"])("--timeout %s is a usage error", async (t) => {
    const r = await runCliAsync(args(freshState(), ["--timeout", t]));
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--timeout/);
    expect(requests).toHaveLength(0);
  });

  it("--timeout 1.0001 is accepted", async () => {
    const r = await runCliAsync(args(freshState(), ["--timeout", "1.0001"]));
    expect(r.status).toBe(0);
    expect(verdictOf(r).verdict).toBe("witnessed");
  });

  it.each(["abc", "30", "59.9"])("daemon --interval %s is a usage error", async (i) => {
    const r = await runCliAsync(
      args(freshState(), ["--interval", i]).filter((a) => a !== "--once"),
    );
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--interval/);
    expect(requests).toHaveLength(0);
  });

  // ── Round 4: lock recovery, signals, symlinks, escaping ──

  // A preload module run inside the CLI before it starts.
  const preload = (name: string, lines: string[]) => {
    const file = join(dir, `${name}-${++stateN}.mjs`);
    writeFileSync(file, lines.join("\n"));
    return ["--import", file];
  };
  // Backdate a file's mtime by an hour: past any lease.
  const expireLease = (file: string) => {
    const past = new Date(Date.now() - 3600e3);
    utimesSync(file, past, past);
  };
  const lockOf = (pid: number, host = hostname()) =>
    JSON.stringify({ pid, hostname: host, startedAt: "2026-10-24T00:00:00.000Z", nonce: "test" });
  // Holds the next STH responses until `release` is called.
  const gateSth = () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const seen = { n: 0 };
    sthHandler = (res) => {
      seen.n++;
      void gate.then(() => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(honest()));
      });
    };
    return { release, seen };
  };

  it("a fresh lock holding its own pid is refused, and says when to retry", async () => {
    const state = freshState();
    const pre = preload("own-pid-lock", [
      'import { writeFileSync } from "node:fs";',
      'import { hostname } from "node:os";',
      `writeFileSync(${JSON.stringify(state + ".lock")}, JSON.stringify({ pid: process.pid, hostname: hostname(), startedAt: "2026-10-24T00:00:00.000Z", nonce: "old" }));`,
    ]);
    const r = await runCliAsync(args(state), pre);
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("state-locked");
    expect(String(verdictOf(r).message)).toMatch(/retry after/);
    expect(posts()).toHaveLength(0);
  });

  it("a restarted witness recovers its own-pid lock once the lease runs out", async () => {
    const state = freshState();
    const lock = JSON.stringify(state + ".lock");
    const pre = preload("own-pid-expired", [
      'import { writeFileSync, utimesSync } from "node:fs";',
      'import { hostname } from "node:os";',
      `writeFileSync(${lock}, JSON.stringify({ pid: process.pid, hostname: hostname(), startedAt: "2026-10-24T00:00:00.000Z", nonce: "old" }));`,
      `utimesSync(${lock}, new Date(Date.now() - 3600e3), new Date(Date.now() - 3600e3));`,
    ]);
    const r = await runCliAsync(args(state), pre);
    expect(r.status).toBe(0);
    expect(verdictOf(r).verdict).toBe("witnessed");
    expect(r.stderr).toMatch(/stale lock/);
    expect(posts()).toHaveLength(1);
  });

  it("refuses a lock held by a live pid it may not signal (pid 1), and says how to recover", async () => {
    const state = freshState();
    writeFileSync(state + ".lock", lockOf(1));
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(2);
    const v = verdictOf(r);
    expect(v.verdict).toBe("state-locked");
    expect(String(v.message)).toMatch(/--break-lock/);
    expect(posts()).toHaveLength(0);
    expect(readFileSync(state + ".lock", "utf8")).toBe(lockOf(1));
  });

  it("refuses a fresh lock from another host, naming it, even with a dead pid", async () => {
    const state = freshState();
    const dead = spawnSync("node", ["-e", ""]).pid;
    writeFileSync(state + ".lock", lockOf(dead, "some-other-host"));
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(2);
    const v = verdictOf(r);
    expect(v.verdict).toBe("state-locked");
    expect(String(v.message)).toMatch(/some-other-host/);
    expect(String(v.message)).toMatch(/--break-lock/);
    expect(posts()).toHaveLength(0);
  });

  it("refuses an empty lock file as unreadable", async () => {
    const state = freshState();
    writeFileSync(state + ".lock", "");
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("state-locked");
    expect(String(verdictOf(r).message)).toMatch(/cannot be read/);
    expect(posts()).toHaveLength(0);
  });

  it("--break-lock removes a live-looking lock, says so loudly, and witnesses", async () => {
    const state = freshState();
    writeFileSync(state + ".lock", lockOf(process.pid));
    const r = await runCliAsync(args(state, ["--break-lock"]));
    expect(r.status).toBe(0);
    expect(verdictOf(r).verdict).toBe("witnessed");
    expect(r.stderr).toMatch(/BREAKING LOCK/);
    expect(posts()).toHaveLength(1);
    expect(existsSync(state + ".lock")).toBe(false);
  });

  it("SIGTERM mid-poll releases the lock and exits 143", async () => {
    const state = freshState();
    const g = gateSth();
    const d = startDaemon(args(state));
    try {
      await waitUntil(() => g.seen.n === 1);
      expect(existsSync(state + ".lock")).toBe(true);
      d.child.kill("SIGTERM");
      expect(await d.exited).toBe(143);
      expect(existsSync(state + ".lock")).toBe(false);
      expect(posts()).toHaveLength(0);
    } finally {
      g.release();
    }
  });

  it("SIGINT mid-poll releases the lock and exits 130", async () => {
    const state = freshState();
    const g = gateSth();
    const d = startDaemon(args(state));
    try {
      await waitUntil(() => g.seen.n === 1);
      d.child.kill("SIGINT");
      expect(await d.exited).toBe(130);
      expect(existsSync(state + ".lock")).toBe(false);
    } finally {
      g.release();
    }
  });

  it("SIGTERM during the daemon's sleep exits 143 at once", async () => {
    const state = freshState();
    const d = startDaemon(args(state).filter((a) => a !== "--once"));
    await waitUntil(() => posts().length === 1);
    await new Promise((r) => setTimeout(r, 100));
    expect(d.running()).toBe(true);
    d.child.kill("SIGTERM");
    expect(await d.exited).toBe(143);
    expect(existsSync(state + ".lock")).toBe(false);
  });

  it("two processes breaking one stale lock: exactly one signs", async () => {
    const state = freshState();
    const dead = spawnSync("node", ["-e", ""]).pid;
    writeFileSync(state + ".lock", lockOf(dead));
    expireLease(state + ".lock");
    // Slow every unlink of the lock, widening the check-then-unlink gap.
    const pre = preload("slow-unlink", [
      'import fs from "node:fs";',
      'import { syncBuiltinESMExports } from "node:module";',
      "const real = fs.unlinkSync;",
      "fs.unlinkSync = (p) => {",
      '  if (String(p).endsWith(".lock")) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 300);',
      "  return real(p);",
      "};",
      "syncBuiltinESMExports();",
    ]);
    const [a, b] = await Promise.all([runCliAsync(args(state), pre), runCliAsync(args(state), pre)]);
    expect([a.status, b.status].sort()).toEqual([0, 2]);
    expect(posts()).toHaveLength(1);
  });

  it("a symlinked state path and its target share one lock, and the symlink stays", async () => {
    const sub = join(dir, `symlink-${++stateN}`);
    mkdirSync(sub);
    const real = join(sub, "real.json");
    const link = join(sub, "link.json");
    const root2 = treeRoot([leafHash("leaf-0"), leafHash("leaf-1")]);
    writeFileSync(real, JSON.stringify({ logId: "test-log", lastSize: 2, lastRoot: root2 }));
    symlinkSync("real.json", link);
    const g = gateSth();
    const a = runCliAsync(args(link));
    await waitUntil(() => g.seen.n === 1);
    const b = await runCliAsync(args(real));
    g.release();
    const ra = await a;
    expect(ra.status).toBe(0);
    expect(b.status).toBe(2);
    expect(verdictOf(b).verdict).toBe("state-locked");
    expect(posts()).toHaveLength(1);
    expect(lstatSync(link).isSymbolicLink()).toBe(true);
    expect((JSON.parse(readFileSync(real, "utf8")) as { lastSize: number }).lastSize).toBe(3);
  });

  it("daemon --json: stdout is JSON lines only, the banner goes to stderr", async () => {
    const state = freshState();
    writeFileSync(state, "not json");
    const d = startDaemon(args(state).filter((a) => a !== "--once"));
    try {
      await d.waitFor(/bad-state .*retry/);
      await waitUntil(() => d.output().stdout.includes("\n"));
      const { stdout, stderr } = d.output();
      expect(stderr).toMatch(/daemon mode/);
      const lines = stdout.trim().split("\n");
      expect(lines.length).toBeGreaterThan(0);
      for (const l of lines) expect(() => JSON.parse(l) as unknown).not.toThrow();
    } finally {
      d.child.kill("SIGKILL");
      await d.exited;
    }
  });

  // An old-format state at the current head makes the witness save it
  // (to add the logId); a failing rename there is an unexpected throw.
  const throwingPoll = () => {
    const state = freshState();
    const sth = tlog.currentSth();
    writeFileSync(state, JSON.stringify({ lastSize: sth.treeSize, lastRoot: sth.rootHash }));
    const pre = preload("rename-throws", [
      'import fs from "node:fs";',
      'import { syncBuiltinESMExports } from "node:module";',
      'fs.renameSync = () => { throw Object.assign(new Error("EIO: simulated"), { code: "EIO" }); };',
      "syncBuiltinESMExports();",
    ]);
    return { state, pre };
  };

  it("daemon --json: a thrown poll error is a JSON line too", async () => {
    const { state, pre } = throwingPoll();
    const child = spawn("node", [...pre, CLI, ...args(state).filter((a) => a !== "--once")], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (x: Buffer) => (stdout += x.toString("utf8")));
    child.stderr.on("data", (x: Buffer) => (stderr += x.toString("utf8")));
    try {
      // stdout and stderr are separate pipes: wait for both.
      await waitUntil(() => /poll error/.test(stderr) && stdout.includes("\n"));
      const lines = stdout.trim().split("\n");
      expect(lines).toHaveLength(1);
      expect((JSON.parse(lines[0]) as { verdict: string }).verdict).toBe("error");
    } finally {
      child.kill("SIGKILL");
    }
  });

  it("--json=true: an unexpected error in --once is one JSON line", async () => {
    const { state, pre } = throwingPoll();
    const r = await runCliAsync(
      [...args(state).filter((a) => a !== "--json"), "--json=true"],
      pre,
    );
    expect(r.status).toBe(2);
    const lines = r.stdout.trim().split("\n");
    expect(lines).toHaveLength(1);
    expect((JSON.parse(lines[0]) as { verdict: string }).verdict).toBe("error");
  });

  it.each([
    ["U+200E", "\u200e"],
    ["U+200F", "\u200f"],
    ["U+202A", "\u202a"],
    ["U+202E", "\u202e"],
    ["U+2066", "\u2066"],
    ["U+2069", "\u2069"],
  ])("refuses a logId with the bidi control %s", async (_n, ch) => {
    rewrite = (b) => headWith(b, { logId: `x${ch}y` });
    const r = await runCliAsync(args(freshState()));
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("malformed-sth");
    expect(posts()).toHaveLength(0);
  });

  it("escapes bidi controls in a log's error body", async () => {
    postHandler = (res) => {
      res.writeHead(500, { "content-type": "text/plain" });
      res.end("a\u202e[witness] desrever\u2066b\u200fc");
    };
    const text = await runCliAsync(args(freshState()).filter((a) => a !== "--json"));
    const all = text.stdout + text.stderr;
    expect(all).not.toMatch(/[\u200e\u200f\u202a-\u202e\u2066-\u2069]/);
    expect(all).toContain("\\u202e");
    const json = await runCliAsync(args(freshState()));
    expect(json.stdout).not.toMatch(/[\u200e\u200f\u202a-\u202e\u2066-\u2069]/);
    expect(json.stdout).toContain("\\u202e");
  });

  it.each([
    ["ESC", "\u001b"],
    ["NEL", "\u0085"],
    ["U+2028", "\u2028"],
    ["U+2029", "\u2029"],
    ["U+202E", "\u202e"],
  ])("escapes a raw %s in text that is not quoted (a state file's bytes)", async (_n, ch) => {
    const state = freshState();
    // JSON.parse quotes the start of the bad text in its error message,
    // raw: the character goes first so it is always in that excerpt.
    writeFileSync(state, `${ch}[witness] forged`);
    const r = await runCliAsync(args(state).filter((a) => a !== "--json"));
    expect(r.status).toBe(2);
    const all = r.stdout + r.stderr;
    expect(all.includes(ch)).toBe(false);
    expect(all).toContain("\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
  });

  it("prints the log's error body quoted", async () => {
    postHandler = (res) => {
      res.writeHead(500, { "content-type": "text/plain" });
      res.end('he said "hi"');
    };
    const r = await runCliAsync(args(freshState()).filter((a) => a !== "--json"));
    expect(r.status).toBe(2);
    expect(r.stdout).toContain('"he said \\"hi\\""');
  });

  it("a directory fsync that fails with EIO: state-save-failed, no POST", async () => {
    const pre = preload("dir-fsync-eio", [
      'import fs from "node:fs";',
      'import { syncBuiltinESMExports } from "node:module";',
      "const open = fs.openSync;",
      "const fsync = fs.fsyncSync;",
      "const dirs = new Set();",
      "fs.openSync = (p, ...rest) => {",
      "  const fd = open(p, ...rest);",
      "  try { if (fs.statSync(p).isDirectory()) dirs.add(fd); } catch { /* not there */ }",
      "  return fd;",
      "};",
      "fs.fsyncSync = (fd) => {",
      '  if (dirs.has(fd)) throw Object.assign(new Error("EIO: simulated"), { code: "EIO" });',
      "  return fsync(fd);",
      "};",
      "syncBuiltinESMExports();",
    ]);
    const r = await runCliAsync(args(freshState()), pre);
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("state-save-failed");
    expect(posts()).toHaveLength(0);
  });

  it("does not write through a planted <state>.tmp", async () => {
    const sub = join(dir, `planted-${++stateN}`);
    mkdirSync(sub);
    const state = join(sub, "state.json");
    const victim = join(sub, "victim.txt");
    writeFileSync(victim, "untouched");
    symlinkSync("victim.txt", state + ".tmp");
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(0);
    expect(readFileSync(victim, "utf8")).toBe("untouched");
    expect(lstatSync(state).isFile()).toBe(true);
    expect(lstatSync(state + ".tmp").isSymbolicLink()).toBe(true);
  });

  it("a fetch that fails says why (the cause), quoted", async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", () => resolve()));
    const addr = closed.address();
    if (!addr || typeof addr === "string") throw new Error("no address");
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    const a = args(freshState());
    a[a.indexOf("--url") + 1] = `http://127.0.0.1:${addr.port}`;
    const r = await runCliAsync(a);
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("fetch-failed");
    expect(String(verdictOf(r).message)).toMatch(/ECONNREFUSED/);
  });

  // ── Round 5: the lock is a lease ──

  it("I-1: two witnesses with the same pid and hostname (separate pid namespaces): one signs", async () => {
    const state = freshState();
    const fakepid = preload("fakepid", [
      'import os from "node:os";',
      'import { syncBuiltinESMExports } from "node:module";',
      'Object.defineProperty(process, "pid", { value: 1, configurable: true });',
      'os.hostname = () => "shared-host";',
      "syncBuiltinESMExports();",
    ]);
    // Each STH request gets a different head of the same size.
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let n = 0;
    sthHandler = (res) => {
      const k = n++;
      void gate.then(() => {
        const body = k === 0 ? honest() : headWith(honest(), { rootHash: "e".repeat(64) });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
      });
    };
    const a = runCliAsync(args(state), fakepid);
    await waitUntil(() => n === 1);
    const b = runCliAsync(args(state), fakepid);
    await new Promise((r) => setTimeout(r, 400));
    release();
    const [ra, rb] = await Promise.all([a, b]);
    expect([ra.status, rb.status].sort()).toEqual([0, 2]);
    expect(posts()).toHaveLength(1);
  });

  it("refuses a fresh lock whatever its pid (a dead one here): pid liveness is not trusted", async () => {
    const state = freshState();
    const dead = spawnSync("node", ["-e", ""]).pid;
    writeFileSync(state + ".lock", lockOf(dead));
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(2);
    const v = verdictOf(r);
    expect(v.verdict).toBe("state-locked");
    expect(String(v.message)).toMatch(/last renewed/);
    expect(String(v.message)).toMatch(/retry after/);
    expect(posts()).toHaveLength(0);
  });

  it("renews the lease during a long poll, and a second process is refused meanwhile", async () => {
    const state = freshState();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held = 0;
    postHandler = (res) => {
      held++;
      void gate.then(() => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, witnessCount: 1 }));
      });
    };
    const env = { VR_WITNESS_LEASE_RENEW_MS: "100" };
    const a = runCliAsync(args(state), [], env);
    try {
      await waitUntil(() => held === 1);
      const m0 = statSync(state + ".lock").mtimeMs;
      await new Promise((r) => setTimeout(r, 450)); // > 2 x the renewal interval
      const m1 = statSync(state + ".lock").mtimeMs;
      expect(m1).toBeGreaterThan(m0);
      const b = await runCliAsync(args(state));
      expect(b.status).toBe(2);
      expect(verdictOf(b).verdict).toBe("state-locked");
    } finally {
      release();
    }
    const ra = await a;
    expect(ra.status).toBe(0);
    expect(posts()).toHaveLength(1);
  });

  it("takes over a stale <lock>.break", async () => {
    const state = freshState();
    writeFileSync(state + ".lock", lockOf(12345));
    expireLease(state + ".lock");
    writeFileSync(state + ".lock.break", lockOf(12345));
    expireLease(state + ".lock.break");
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(0);
    expect(verdictOf(r).verdict).toBe("witnessed");
    expect(r.stderr).toMatch(/stale .*\.break/);
    expect(posts()).toHaveLength(1);
    expect(existsSync(state + ".lock.break")).toBe(false);
  });

  it("a refusal names both <lock> and <lock>.break when both exist", async () => {
    const state = freshState();
    writeFileSync(state + ".lock", lockOf(12345));
    expireLease(state + ".lock");
    writeFileSync(state + ".lock.break", lockOf(12345)); // fresh: someone is breaking it
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(2);
    const m = String(verdictOf(r).message);
    expect(m).toContain(state + ".lock ");
    expect(m).toContain(state + ".lock.break");
    expect(posts()).toHaveLength(0);
  });

  it("does not break a lock that changed after it was judged stale (the exact-bytes re-check)", async () => {
    const state = freshState();
    const lock = state + ".lock";
    writeFileSync(lock, lockOf(12345));
    expireLease(lock);
    const fresh = JSON.stringify({ pid: 777, hostname: "h", startedAt: "2026-10-24T00:00:00.000Z", nonce: "theirs" });
    // Once the CLI has judged the lock stale and starts taking
    // <lock>.break, another process replaces the lock with a fresh one
    // (a new file, as a real process would write it).
    const pre = preload("lock-replaced", [
      'import fs from "node:fs";',
      'import { syncBuiltinESMExports } from "node:module";',
      "const open = fs.openSync;",
      "const write = fs.writeFileSync;",
      "const rename = fs.renameSync;",
      "let done = false;",
      "fs.openSync = (p, ...rest) => {",
      "  const s = String(p);",
      '  if (!done && s.includes(".lock.break.") && s.endsWith(".tmp")) {',
      "    done = true;",
      '    const lock = s.slice(0, s.indexOf(".lock.break.") + ".lock".length);',
      `    write(lock + ".other", ${JSON.stringify(fresh)});`,
      '    rename(lock + ".other", lock);',
      "  }",
      "  return open(p, ...rest);",
      "};",
      "syncBuiltinESMExports();",
    ]);
    const r = await runCliAsync(args(state), pre);
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("state-locked");
    expect(readFileSync(lock, "utf8")).toBe(fresh);
    expect(posts()).toHaveLength(0);
  });

  it("a lock taken over mid-poll: refuses to sign, and leaves the other lock in place", async () => {
    const state = freshState();
    const lock = state + ".lock";
    const g = gateSth();
    const a = runCliAsync(args(state));
    await waitUntil(() => g.seen.n === 1);
    const theirs = JSON.stringify({ pid: 777, hostname: "h", startedAt: "2026-10-24T00:00:00.000Z", nonce: "theirs" });
    writeFileSync(lock, theirs);
    g.release();
    const r = await a;
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("lock-lost");
    expect(posts()).toHaveLength(0);
    expect(readFileSync(lock, "utf8")).toBe(theirs);
  });

  it("a lock taken over between the pending save and the signature: no POST", async () => {
    const state = freshState();
    const theirs = JSON.stringify({ pid: 777, hostname: "h", startedAt: "2026-10-24T00:00:00.000Z", nonce: "theirs" });
    // Right after the state file is renamed into place, another process
    // takes the lock.
    const pre = preload("takeover-after-save", [
      'import fs from "node:fs";',
      'import { syncBuiltinESMExports } from "node:module";',
      "const rename = fs.renameSync;",
      "const write = fs.writeFileSync;",
      "fs.renameSync = (from, to) => {",
      "  rename(from, to);",
      `  if (String(to).endsWith(".json")) write(String(to) + ".lock", ${JSON.stringify(theirs)});`,
      "};",
      "syncBuiltinESMExports();",
    ]);
    const r = await runCliAsync(args(state), pre);
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("lock-lost");
    expect(posts()).toHaveLength(0);
    expect(readFileSync(state + ".lock", "utf8")).toBe(theirs);
  });

  it("without hard links (linkSync ENOTSUP) the lock still works: one signs", async () => {
    const state = freshState();
    const noLinks = preload("no-hard-links", [
      'import fs from "node:fs";',
      'import { syncBuiltinESMExports } from "node:module";',
      'fs.linkSync = () => { throw Object.assign(new Error("ENOTSUP: no hard links"), { code: "ENOTSUP" }); };',
      "syncBuiltinESMExports();",
    ]);
    const g = gateSth();
    const a = runCliAsync(args(state), noLinks);
    await waitUntil(() => g.seen.n === 1);
    const b = await runCliAsync(args(state), noLinks);
    g.release();
    const ra = await a;
    expect(ra.status).toBe(0);
    expect(verdictOf(ra).verdict).toBe("witnessed");
    expect(b.status).toBe(2);
    expect(verdictOf(b).verdict).toBe("state-locked");
    expect(posts()).toHaveLength(1);
    expect(existsSync(state + ".lock")).toBe(false);
  });

  it("--help documents the lease and that --break-lock can let two witnesses sign", () => {
    const r = runCli(["--help"]);
    expect(r.stdout).toMatch(/LEASE_MS/);
    expect(r.stdout).toMatch(/both sign|two witnesses can sign/i);
  });

  // ── Round 6: no save without the lock; the state never shrinks ──

  // Logs that grow the honest 3-leaf log, each with a later clock.
  const logAt = (extra: string[], iso: string) => {
    const l = new TransparencyLog("test-log", new InMemoryLogStore(), () => new Date(iso));
    for (const x of ["leaf-0", "leaf-1", "leaf-2", ...extra]) l.append(x);
    return l;
  };
  const headOf = (l: TransparencyLog) => {
    const sth = l.currentSth();
    const canonical = canonicalizeSth(sth);
    return { ...sth, signature: signWith(logPriv, canonical), canonical };
  };
  const send = (res: ServerResponse, body: unknown) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };
  // Serve the STH and proofs of whichever log `current()` returns.
  const serveLog = (current: () => TransparencyLog) => {
    sthHandler = (res) => send(res, headOf(current()));
    proofHandler = (res, url) =>
      send(res, {
        proof: current().proveConsistency(
          Number(url.searchParams.get("old")),
          Number(url.searchParams.get("new")),
        ),
      });
  };
  const atSize = (n: number) =>
    posts().filter((p) => (JSON.parse(String(p.body?.sthCanonical)) as { treeSize: number }).treeSize === n);
  const skewAhead = () =>
    preload("skew", [
      "const off = 3600e3; const _now = Date.now.bind(Date); const D = Date;",
      "globalThis.Date = class extends D { constructor(...a) { if (a.length === 0) super(_now() + off); else super(...a); } static now() { return _now() + off; } };",
    ]);
  const blockAfterPost = (ms: number) =>
    preload("block-after-post", [
      "const real = globalThis.fetch;",
      "globalThis.fetch = async (url, init) => {",
      "  const r = await real(url, init);",
      '  if (init?.method === "POST") {',
      "    const t = await r.text();",
      `    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ${ms});`,
      "    return new Response(t, { status: r.status, headers: r.headers });",
      "  }",
      "  return r;",
      "};",
    ]);
  const L4 = () => logAt(["leaf-3"], "2026-10-24T09:00:00.000Z");
  const L5 = () => logAt(["leaf-3", "leaf-4"], "2026-10-24T10:00:00.000Z");
  const EVIL5 = () => logAt(["leaf-3", "evil"], "2026-10-24T11:00:00.000Z");
  const seed3 = (state: string) =>
    writeFileSync(
      state,
      JSON.stringify({
        logId: "test-log",
        lastSize: 3,
        lastRoot: tlog.currentSth().rootHash,
        lastTimestamp: "2026-10-24T08:00:00.000Z",
      }),
    );

  it("I-6a: a holder blocked after its POST, whose lock is taken over, does not roll the state back", async () => {
    const state = freshState();
    seed3(state);
    const l4 = L4();
    const l5 = L5();
    const evil = EVIL5();
    let current = l4;
    serveLog(() => current);
    const a = runCliAsync(args(state), blockAfterPost(2000));
    await waitUntil(() => posts().length === 1);
    current = l5;
    // B's clock runs an hour ahead, so A's lease looks expired to it.
    const b = await runCliAsync(args(state), skewAhead());
    expect(b.status).toBe(0);
    await a;
    current = evil;
    const c = await runCliAsync(args(state));
    expect(verdictOf(c).verdict).toBe("fork-detected");
    expect(atSize(5)).toHaveLength(1);
  });

  it("I-6b: a slow POST while another, with a skewed clock, takes the lock: no rollback", async () => {
    const state = freshState();
    seed3(state);
    const l4 = L4();
    const l5 = L5();
    const evil = EVIL5();
    let current = l4;
    serveLog(() => current);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let k = 0;
    postHandler = (res) => {
      const ok = () => send(res, { ok: true, witnessCount: 1 });
      if (k++ === 0) void gate.then(ok);
      else ok();
    };
    const a = runCliAsync(args(state));
    await waitUntil(() => posts().length === 1);
    current = l5;
    const b = await runCliAsync(args(state), skewAhead());
    expect(b.status).toBe(0);
    release();
    await a;
    current = evil;
    const c = await runCliAsync(args(state));
    expect(verdictOf(c).verdict).toBe("fork-detected");
    expect(atSize(5)).toHaveLength(1);
  });

  it("I-6c: a legacy state without logId: the no-change save needs the lock too", async () => {
    const state = freshState();
    const l4 = L4();
    const l5 = L5();
    const evil = EVIL5();
    writeFileSync(state, JSON.stringify({ lastSize: 4, lastRoot: l4.currentSth().rootHash }));
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let current = l5;
    let k = 0;
    serveLog(() => current);
    const plain = sthHandler!;
    sthHandler = (res) => {
      if (k++ === 0) void gate.then(() => send(res, headOf(l4)));
      else plain(res);
    };
    const a = runCliAsync(args(state));
    await waitUntil(() => k === 1);
    const b = await runCliAsync(args(state), skewAhead());
    expect(b.status).toBe(0);
    release();
    const ra = await a;
    expect(verdictOf(ra).verdict).toBe("lock-lost");
    current = evil;
    const c = await runCliAsync(args(state));
    expect(verdictOf(c).verdict).toBe("fork-detected");
    expect(atSize(5)).toHaveLength(1);
  });

  // Right after the CLI opens its temporary state file, another process
  // writes the state file: the gap between the lock check and the rename.
  const stateWrittenDuringSave = (content: string) =>
    preload("state-written-during-save", [
      'import fs from "node:fs";',
      'import { syncBuiltinESMExports } from "node:module";',
      "const open = fs.openSync;",
      "const write = fs.writeFileSync;",
      "let done = false;",
      "fs.openSync = (p, ...rest) => {",
      "  const fd = open(p, ...rest);",
      "  const s = String(p);",
      '  if (!done && s.endsWith(".tmp") && !s.includes(".lock")) {',
      "    done = true;",
      `    write(s.replace(/\\.\\d+\\.[0-9a-f-]+\\.tmp$/, ""), ${JSON.stringify(content)});`,
      "  }",
      "  return fd;",
      "};",
      "syncBuiltinESMExports();",
    ]);

  it("saveState refuses to write a smaller lastSize over the file", async () => {
    const state = freshState();
    const bigger = JSON.stringify({ logId: "test-log", lastSize: 5, lastRoot: "b".repeat(64), lastTimestamp: "2026-10-24T10:00:00.000Z" });
    const r = await runCliAsync(args(state), stateWrittenDuringSave(bigger));
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("lock-lost");
    expect(posts()).toHaveLength(0);
    expect(readFileSync(state, "utf8")).toBe(bigger);
  });

  it("saveState refuses an equal size with a different root", async () => {
    const state = freshState();
    const other = JSON.stringify({ logId: "test-log", lastSize: 3, lastRoot: "b".repeat(64), lastTimestamp: "2026-10-24T08:00:00.000Z" });
    const r = await runCliAsync(args(state), stateWrittenDuringSave(other));
    expect(r.status).toBe(1);
    expect(verdictOf(r).verdict).toBe("fork-detected");
    expect(posts()).toHaveLength(0);
    expect(readFileSync(state, "utf8")).toBe(other);
  });

  it("honours a holder's recorded longer leaseMs", async () => {
    const state = freshState();
    // Renewed an hour ago, but its holder's lease is two hours.
    writeFileSync(
      state + ".lock",
      JSON.stringify({ pid: 777, hostname: "h", startedAt: "2026-10-24T00:00:00.000Z", nonce: "n", leaseMs: 7200e3 }),
    );
    expireLease(state + ".lock");
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("state-locked");
    expect(String(verdictOf(r).message)).toMatch(/retry after/);
    expect(posts()).toHaveLength(0);
  });

  it("a fresh <lock>.break refusal says when to retry", async () => {
    const state = freshState();
    writeFileSync(state + ".lock", lockOf(12345));
    expireLease(state + ".lock");
    writeFileSync(state + ".lock.break", lockOf(12345));
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(2);
    expect(String(verdictOf(r).message)).toMatch(/another process is breaking it.*retry after/);
  });

  it("lock taken over after the POST: witnessed with a note, the state left pending, their lock kept", async () => {
    const state = freshState();
    const theirs = JSON.stringify({ pid: 777, hostname: "h", startedAt: "2026-10-24T00:00:00.000Z", nonce: "theirs" });
    postHandler = (res) => {
      writeFileSync(state + ".lock", theirs);
      send(res, { ok: true, witnessCount: 1 });
    };
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(0);
    const v = verdictOf(r);
    expect(v.verdict).toBe("witnessed");
    expect(String(v.note)).toMatch(/lock was taken over/);
    expect((JSON.parse(readFileSync(state, "utf8")) as { pending?: boolean }).pending).toBe(true);
    expect(readFileSync(state + ".lock", "utf8")).toBe(theirs);
  });

  it("lock taken over while the STH is fetched: lock-lost, not a verdict from the state it loaded", async () => {
    const state = freshState();
    const sth = tlog.currentSth();
    writeFileSync(
      state,
      JSON.stringify({ logId: "test-log", lastSize: sth.treeSize, lastRoot: sth.rootHash, lastTimestamp: sth.timestamp }),
    );
    const theirs = JSON.stringify({ pid: 777, hostname: "h", startedAt: "2026-10-24T00:00:00.000Z", nonce: "theirs" });
    sthHandler = (res) => {
      writeFileSync(state + ".lock", theirs);
      send(res, honest());
    };
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(2);
    expect(verdictOf(r).verdict).toBe("lock-lost");
    expect(readFileSync(state + ".lock", "utf8")).toBe(theirs);
  });

  it("--help lists lock-lost and the clock-skew assumption", () => {
    const r = runCli(["--help"]);
    expect(r.stdout).toMatch(/lock-lost/);
    expect(r.stdout).toMatch(/clock skew/i);
  });

  it("loads a state file written before logId was saved, and adds the logId", async () => {
    const state = freshState();
    const sth = tlog.currentSth();
    writeFileSync(
      state,
      JSON.stringify({
        lastSize: sth.treeSize,
        lastRoot: sth.rootHash,
        lastTimestamp: sth.timestamp,
        lastSubmittedAt: "2026-01-01T00:00:00.000Z",
      }),
    );
    const r = await runCliAsync(args(state));
    expect(r.status).toBe(0);
    expect(verdictOf(r).verdict).toBe("no-change");
    expect(posts()).toHaveLength(0);
    const saved = JSON.parse(readFileSync(state, "utf8")) as Record<string, unknown>;
    expect(saved.logId).toBe("test-log");
    expect(saved.lastSize).toBe(sth.treeSize);
  });
});
