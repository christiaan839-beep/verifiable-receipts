/**
 * The differential run's TypeScript runner reads its cases a line at a
 * time: a cases file larger than its heap is judged in full, one verdict
 * per case, in case order. The nightly run's million cases are about
 * 3 GB of text, past the longest string V8 can make.
 *
 * Needs the package built (dist/), as the runner does.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const RUNNER = join(__dirname, "verify.mjs");
const PUBLIC_KEY = join(__dirname, "..", "public-key.pem");
// 48 MB of cases under a 16 MB heap: reading the file whole cannot fit.
const CASES = 24_000;
const HEAP_MB = 16;

let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "differential-streaming-"));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** About 2 KB of inclusion proof; its root is wrong, so it is rejected. */
function caseLine(id: number): string {
  const raw = JSON.stringify({
    leafHashHex: "00".repeat(32),
    leafIndex: 0,
    treeSize: 2 ** 30,
    auditPath: Array.from({ length: 30 }, () => "ab".repeat(32)),
    rootHashHex: "11".repeat(32),
  });
  return JSON.stringify({ id, kind: "inclusion", raw }) + "\n";
}

describe("differential verify.mjs", () => {
  it("judges a cases file larger than its heap, a line at a time", () => {
    const casesPath = join(dir, "cases.jsonl");
    const outPath = join(dir, "ts.jsonl");
    const fd = openSync(casesPath, "w");
    for (let start = 0; start < CASES; start += 1000) {
      let chunk = "";
      for (let id = start; id < start + 1000; id++) chunk += caseLine(id);
      writeSync(fd, chunk);
    }
    closeSync(fd);

    const run = spawnSync(
      process.execPath,
      [`--max-old-space-size=${HEAP_MB}`, RUNNER, PUBLIC_KEY, casesPath, outPath],
      { encoding: "utf8" },
    );
    expect(run.status, run.stderr).toBe(0);

    const verdicts = readFileSync(outPath, "utf8").trimEnd().split("\n").map((l) => JSON.parse(l));
    expect(verdicts).toHaveLength(CASES);
    verdicts.forEach((v, i) => expect(v).toEqual({ id: i, ok: false, reason: null }));
  }, 120_000);
});
