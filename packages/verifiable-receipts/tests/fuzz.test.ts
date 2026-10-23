/**
 * Property tests for the v2 receipt verifier and the Merkle proof
 * verifiers. FC_NUM_RUNS raises the number of runs per property
 * (fast-check's default is 100).
 */
import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";

import { verifyV2Receipt } from "../conformance/verify-v2.mjs";
import {
  leafHash,
  treeRoot,
  inclusionProof,
  verifyInclusionProof,
  consistencyProof,
  verifyConsistencyProof,
} from "../src/transparency.js";

const numRuns = process.env.FC_NUM_RUNS ? Number(process.env.FC_NUM_RUNS) : undefined;
if (numRuns !== undefined) fc.configureGlobal({ numRuns });
const timeout = Math.max(5_000, (numRuns ?? 100) * 50);

const FIXTURES_DIR = join(__dirname, "..", "conformance", "fixtures");
const FIXTURE_KEY = createPublicKey(
  readFileSync(join(__dirname, "..", "conformance", "public-key.pem")),
);

// Ed25519 key from a fixed seed, so a failing case replays with its seed.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const FUZZ_PRIVATE = createPrivateKey({
  key: Buffer.concat([
    PKCS8_ED25519_PREFIX,
    createHash("sha256").update("verifiable-receipts fuzz key").digest(),
  ]),
  format: "der",
  type: "pkcs8",
});
const FUZZ_KEY = createPublicKey(FUZZ_PRIVATE);
const OTHER_KEY = generateKeyPairSync("ed25519").publicKey;

const rawSig = (canonical: string) => nodeSign(null, Buffer.from(canonical, "utf8"), FUZZ_PRIVATE);
const signV2 = (canonical: string) => `v2=${rawSig(canonical).toString("base64")}`;

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fixtureReceipts = readdirSync(FIXTURES_DIR)
  .filter((f) => f.startsWith("v2-") && f.endsWith(".json"))
  .sort()
  .map(
    (f) =>
      (JSON.parse(readFileSync(join(FIXTURES_DIR, f), "utf8")) as { receipt: Record<string, unknown> })
        .receipt,
  );

const canonicalArb = fc.oneof(
  fc.string(),
  fc.jsonValue().map((v) => JSON.stringify(v) ?? ""),
  fc.dictionary(fc.string(), fc.jsonValue()).map((v) => JSON.stringify(v)),
);

const keyArb = fc.constantFrom<KeyObject>(FUZZ_KEY, FIXTURE_KEY, OTHER_KEY);

function accepted(receipt: unknown, key: KeyObject): boolean {
  const result = verifyV2Receipt(receipt as Record<string, unknown>, key);
  if (!result.ok) {
    expect(typeof result.reason).toBe("string");
    expect(result.reason).not.toBe("");
  }
  return result.ok;
}

describe("verifyV2Receipt — arbitrary input", () => {
  it("never throws on any value", () => {
    fc.assert(
      fc.property(fc.anything(), keyArb, (receipt, key) => {
        accepted(receipt, key);
      }),
    );
  }, timeout);

  it("accepts only the exact signature over the canonical", () => {
    const receiptArb = fc
      .record({
        canonical: canonicalArb,
        signer: fc.constantFrom("none", "fuzz", "garbage"),
        garbage: fc.oneof(fc.string(), fc.anything()),
        contentHash: fc.option(fc.oneof(fc.string(), fc.anything(), fc.constant("hash"))),
        extra: fc.dictionary(fc.string(), fc.jsonValue(), { maxKeys: 3 }),
      })
      .map(({ canonical, signer, garbage, contentHash, extra }) => {
        const receipt: Record<string, unknown> = { ...extra, canonical };
        if (typeof canonical === "string" && canonical !== "") {
          receipt.signature = signer === "fuzz" ? signV2(canonical) : garbage;
        }
        if (contentHash === "hash") {
          receipt.contentHash = createHash("sha256").update(canonical, "utf8").digest("hex");
        } else if (contentHash !== null) {
          receipt.contentHash = contentHash;
        }
        return receipt;
      });
    fc.assert(
      fc.property(fc.oneof(receiptArb, fc.constantFrom(...fixtureReceipts)), keyArb, (receipt, key) => {
        if (accepted(receipt, key)) {
          const canonical = receipt.canonical as string;
          if (key === FUZZ_KEY) {
            expect(receipt.signature).toBe(signV2(canonical));
          } else {
            expect(key).toBe(FIXTURE_KEY);
            expect(fixtureReceipts.some((r) => r.signature === receipt.signature)).toBe(true);
          }
        }
      }),
    );
  }, timeout);
});

function signedReceipt(body: string, withHash: boolean) {
  const canonical = JSON.stringify({ body });
  const receipt: Record<string, unknown> = { canonical, signature: signV2(canonical) };
  if (withHash) {
    receipt.contentHash = `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
  }
  return receipt;
}

function replaceAt(s: string, i: number, c: string): string {
  return s.slice(0, i) + c + s.slice(i + 1);
}

describe("verifyV2Receipt — mutations of a valid receipt", () => {
  it("rejects a change to one character of the signature", () => {
    fc.assert(
      fc.property(
        fc.string(),
        fc.boolean(),
        fc.nat(),
        fc.constantFrom(...(B64 + "=-_ .\n\r\t")),
        (body, withHash, pos, c) => {
          const receipt = signedReceipt(body, withHash);
          expect(accepted(receipt, FUZZ_KEY)).toBe(true);
          const sig = receipt.signature as string;
          const i = pos % sig.length;
          fc.pre(sig[i] !== c);
          expect(accepted({ ...receipt, signature: replaceAt(sig, i, c) }, FUZZ_KEY)).toBe(false);
        },
      ),
    );
  }, timeout);

  it("rejects a change to one byte of the raw signature", () => {
    fc.assert(
      fc.property(fc.string(), fc.boolean(), fc.nat(63), fc.integer({ min: 1, max: 255 }), (body, withHash, pos, flip) => {
        const receipt = signedReceipt(body, withHash);
        const sig = rawSig(receipt.canonical as string);
        sig[pos] ^= flip;
        expect(accepted({ ...receipt, signature: `v2=${sig.toString("base64")}` }, FUZZ_KEY)).toBe(false);
      }),
    );
  }, timeout);

  it("rejects a change to one character of the canonical", () => {
    fc.assert(
      fc.property(
        fc.string({ unit: "binary" }),
        fc.boolean(),
        fc.nat(),
        fc.string({ minLength: 1, maxLength: 1, unit: "grapheme-ascii" }),
        (body, withHash, pos, c) => {
          const receipt = signedReceipt(body, withHash);
          const canonical = receipt.canonical as string;
          const i = pos % canonical.length;
          fc.pre(canonical[i] !== c);
          expect(accepted({ ...receipt, canonical: replaceAt(canonical, i, c) }, FUZZ_KEY)).toBe(false);
        },
      ),
    );
  }, timeout);

  it("rejects every non-canonical base64 spelling of the signature", () => {
    fc.assert(
      fc.property(
        fc.string(),
        fc.integer({ min: 1, max: 15 }),
        fc.nat(),
        fc.constantFrom(" ", "\n", "\r\n", "\t", "="),
        (body, padBits, pos, junk) => {
          const receipt = signedReceipt(body, true);
          const b64 = (receipt.signature as string).slice(3);
          // 64 bytes: the last group is two characters and "==".
          const last = b64.length - 3;
          const spellings = [
            replaceAt(b64, last, B64[B64.indexOf(b64[last]) | padBits]),
            b64.slice(0, -1),
            b64.slice(0, -2),
            `${b64}=`,
            b64.replace(/\+/g, "-").replace(/\//g, "_"),
            b64.slice(0, pos % b64.length) + junk + b64.slice(pos % b64.length),
            `${junk}${b64}`,
            `${b64}${junk}`,
          ].filter((s) => s !== b64);
          for (const s of spellings) {
            expect(accepted({ ...receipt, signature: `v2=${s}` }, FUZZ_KEY)).toBe(false);
          }
          expect(accepted({ ...receipt, signature: `V2=${b64}` }, FUZZ_KEY)).toBe(false);
        },
      ),
    );
  }, timeout);
});

const hexArb = fc.uint8Array({ minLength: 32, maxLength: 32 }).map((b) => Buffer.from(b).toString("hex"));
const sizeArb = fc.oneof(
  fc.integer({ min: -4, max: 70 }),
  fc.integer(),
  fc.double(),
  fc.constantFrom(Number.MAX_SAFE_INTEGER, 2 ** 31, 2 ** 32 + 1),
);

function treeArb(maxLeaves: number) {
  return fc
    .tuple(fc.integer({ min: 1, max: maxLeaves }), fc.string())
    .map(([n, salt]) => Array.from({ length: n }, (_, i) => leafHash(`${salt}:${i}`)));
}

describe("verifyInclusionProof", () => {
  it("never throws on arbitrary input", () => {
    fc.assert(
      fc.property(
        fc.oneof(hexArb, fc.string()),
        sizeArb,
        sizeArb,
        fc.array(fc.oneof(hexArb, fc.string()), { maxLength: 40 }),
        fc.oneof(hexArb, fc.string()),
        (leaf, idx, size, proof, root) => {
          const ok = verifyInclusionProof(leaf, idx, size, proof, root);
          expect(typeof ok).toBe("boolean");
          if (ok) {
            expect(verifyInclusionProof(leaf, idx, size, proof, `${root}0`)).toBe(false);
            // One spelling: what passes is safe integers and 64 lowercase hex digits.
            expect(Number.isSafeInteger(idx) && Number.isSafeInteger(size)).toBe(true);
            for (const h of [leaf, root, ...proof]) expect(h).toMatch(/^[0-9a-f]{64}$/);
          }
        },
      ),
    );
  }, timeout);

  it("verifies a real proof and rejects a wrong root or a changed proof", () => {
    fc.assert(
      fc.property(treeArb(64), fc.nat(), hexArb, fc.nat(), (leaves, pick, wrongRoot, entry) => {
        const idx = pick % leaves.length;
        const root = treeRoot(leaves);
        const proof = inclusionProof(idx, leaves);
        expect(verifyInclusionProof(leaves[idx], idx, leaves.length, proof, root)).toBe(true);
        if (wrongRoot !== root) {
          expect(verifyInclusionProof(leaves[idx], idx, leaves.length, proof, wrongRoot)).toBe(false);
        }
        if (proof.length > 0) {
          const tampered = [...proof];
          tampered[entry % proof.length] = wrongRoot;
          fc.pre(wrongRoot !== proof[entry % proof.length]);
          expect(verifyInclusionProof(leaves[idx], idx, leaves.length, tampered, root)).toBe(false);
        }
      }),
    );
  }, timeout);
});

describe("verifyConsistencyProof", () => {
  it("never throws on arbitrary sizes and hashes", () => {
    fc.assert(
      fc.property(
        sizeArb,
        sizeArb,
        fc.oneof(hexArb, fc.string()),
        fc.oneof(hexArb, fc.string()),
        fc.array(fc.oneof(hexArb, fc.string()), { maxLength: 40 }),
        (oldSize, newSize, oldRoot, newRoot, proof) => {
          const ok = verifyConsistencyProof(oldSize, newSize, oldRoot, newRoot, proof);
          expect(typeof ok).toBe("boolean");
          if (ok) {
            expect(Number.isSafeInteger(oldSize) && Number.isSafeInteger(newSize)).toBe(true);
            for (const h of [oldRoot, newRoot, ...proof]) expect(h).toMatch(/^[0-9a-f]{64}$/);
          }
        },
      ),
    );
  }, timeout);

  it("verifies a real proof and rejects a wrong old or new root", () => {
    fc.assert(
      fc.property(treeArb(64), fc.nat(), hexArb, (leaves, pick, wrongRoot) => {
        const oldSize = pick % (leaves.length + 1);
        const oldRoot = treeRoot(leaves.slice(0, oldSize));
        const newRoot = treeRoot(leaves);
        const proof = consistencyProof(oldSize, leaves);
        expect(verifyConsistencyProof(oldSize, leaves.length, oldRoot, newRoot, proof)).toBe(true);
        // Every tree extends the empty tree, whatever its root.
        if (oldSize > 0 && wrongRoot !== oldRoot) {
          expect(verifyConsistencyProof(oldSize, leaves.length, wrongRoot, newRoot, proof)).toBe(false);
        }
        if (wrongRoot !== newRoot && !(oldSize === 0 && proof.length === 0)) {
          expect(verifyConsistencyProof(oldSize, leaves.length, oldRoot, wrongRoot, proof)).toBe(false);
        }
      }),
    );
  }, timeout);
});
