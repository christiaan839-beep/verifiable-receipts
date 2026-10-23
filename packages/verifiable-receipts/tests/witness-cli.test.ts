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
import { createServer, type Server } from "node:http";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TransparencyLog, InMemoryLogStore } from "../src/log-store.js";
import { canonicalizeSth } from "../src/transparency.js";

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
    timeout: 10_000,
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

function runCliAsync(args: string[]): Promise<CliResult> {
  return new Promise((resolve) => {
    const child = spawn("node", [CLI, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
    const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr });
    });
  });
}

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
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(rewrite(honest())));
          return;
        }
        if (req.method === "GET" && url.pathname === "/api/transparency/proof") {
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
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => srv.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  });

  beforeEach(() => {
    requests = [];
    rewrite = (b) => b;
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
