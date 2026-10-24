/**
 * Cross-language conformance harness — TypeScript verifier side.
 *
 * Reads the JSON fixtures from ./fixtures/ and runs each one through
 * the TypeScript reference implementation. Every fixture has an
 * `expected.ok` field; the harness asserts the verifier agrees.
 *
 * The Python harness at conformance.py and the Go harness at
 * conformance_test.go run the SAME fixtures and MUST produce
 * byte-identical pass/fail outcomes. This is what makes the
 * "three-language symmetric verifier" claim auditable: the corpus
 * is the contract.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createPublicKey } from "node:crypto";

import { verifyInclusionProof } from "../src/transparency.js";
// The harness's own v2 verifier, shared with roundtrip/verify.mjs.
import { verifyV2Receipt } from "./verify-v2.mjs";

const FIXTURES_DIR = join(__dirname, "fixtures");
const PUBLIC_KEY_PEM = readFileSync(join(__dirname, "public-key.pem"));
const PUBLIC_KEY = createPublicKey(PUBLIC_KEY_PEM);

interface V2Fixture {
  description: string;
  // A key fixture's own key, used instead of public-key.pem.
  publicKeyPem?: string;
  // Any field beside these three must match the signed canonical.
  receipt: {
    canonical: string;
    contentHash?: string;
    signature: string;
    [field: string]: unknown;
  };
  expected: { ok: boolean; reasonContains?: string };
}

interface InclusionFixture {
  description: string;
  leafHashHex: string;
  leafIndex: number;
  treeSize: number;
  auditPath: string[];
  rootHashHex: string;
  expected: { ok: boolean };
}

type AnyFixture = (V2Fixture | InclusionFixture) & { __filename: string };

function loadFixtures(): AnyFixture[] {
  const files = readdirSync(FIXTURES_DIR).filter((f) => f.endsWith(".json"));
  return files.map((f) => {
    const parsed = JSON.parse(
      readFileSync(join(FIXTURES_DIR, f), "utf8"),
    ) as Record<string, unknown>;
    return { ...parsed, __filename: f } as AnyFixture;
  });
}

describe("Cross-language conformance — TypeScript verifier", () => {
  const fixtures = loadFixtures();

  it("loaded at least 10 fixtures across both primitives", () => {
    expect(fixtures.length).toBeGreaterThanOrEqual(10);
  });

  for (const fixture of fixtures) {
    const isV2 = "receipt" in fixture;
    const isInclusion = "leafHashHex" in fixture;
    it(`${fixture.__filename} — ${fixture.description}`, () => {
      if (isV2) {
        const pem = (fixture as V2Fixture).publicKeyPem;
        const result = verifyV2Receipt(
          (fixture as V2Fixture).receipt,
          pem ? createPublicKey(pem) : PUBLIC_KEY,
        ) as { ok: boolean; reason?: string };
        expect(result.ok).toBe(fixture.expected.ok);
        const expectedReason = (fixture as V2Fixture).expected.reasonContains;
        if (expectedReason && !result.ok) {
          expect(result.reason ?? "").toMatch(new RegExp(expectedReason, "i"));
        }
      } else if (isInclusion) {
        const f = fixture as InclusionFixture;
        const result = verifyInclusionProof(
          f.leafHashHex,
          f.leafIndex,
          f.treeSize,
          f.auditPath,
          f.rootHashHex,
        );
        expect(result).toBe(fixture.expected.ok);
      } else {
        const name = (fixture as { __filename: string }).__filename;
        throw new Error(
          `unknown fixture shape in ${name} — must contain "receipt" or "leafHashHex"`,
        );
      }
    });
  }
});
