/**
 * Guardian runner, signed bundle and dual signature, plus regression
 * tests for malformed and policy-free envelopes.
 */
import { describe, it, expect } from "vitest";
import {
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";
import {
  runGuardian,
  verifyGuardianAttestation,
  outputSizeRule,
  forbiddenSubstringRule,
  requireTokenRule,
  quorumCollapse,
  type GuardianRule,
} from "../src/guardian.js";
import { buildSignedBundle, verifyManifest } from "../src/bundle.js";
import {
  generateMlDsa65Keypair,
  signMlDsa65,
  verifyDualSig,
  formatV3Wire,
} from "../src/pq-sign.js";
import { verifyThresholdAttestation } from "../src/threshold.js";
import { parseVapt, verifyVapt } from "../src/vapt.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signV2 = (canonical: string) =>
  `v2=${nodeSign(null, Buffer.from(canonical), privateKey).toString("base64")}`;
const verifyV2 = (canonical: string, signature: string) =>
  signature.startsWith("v2=") &&
  nodeVerify(
    null,
    Buffer.from(canonical),
    publicKey,
    Buffer.from(signature.slice(3), "base64"),
  );

const ctx = {
  runId: "run_1",
  agentSlug: "sample-agent",
  tokenId: "tok_1",
  input: { q: "sample" },
  output: { a: "sample answer" },
};

describe("runGuardian", () => {
  it("signs a verdict that verifies", async () => {
    const att = await runGuardian(
      [outputSizeRule(1024), requireTokenRule],
      ctx,
      signV2,
    );
    expect(att.overall).toBe("pass");
    expect(verifyGuardianAttestation(att, verifyV2)).toEqual({ ok: true });
  });

  it("collapses block > warn > pass and turns a throwing rule into warn", async () => {
    const throwing: GuardianRule = {
      id: "throws",
      description: "always throws",
      evaluate: async () => {
        throw new Error("boom");
      },
    };
    const warned = await runGuardian([throwing], ctx, signV2);
    expect(warned.overall).toBe("warn");
    expect(warned.rules[0].reason).toBe("boom");

    const blocked = await runGuardian(
      [throwing, outputSizeRule(1)],
      ctx,
      signV2,
    );
    expect(blocked.overall).toBe("block");
  });

  it("rejects an edited overall, a forged signature and a malformed canonical", async () => {
    const att = await runGuardian(
      [forbiddenSubstringRule(["answer"], "block")],
      ctx,
      signV2,
    );
    expect(att.overall).toBe("block");
    expect(
      verifyGuardianAttestation({ ...att, overall: "pass" }, verifyV2).ok,
    ).toBe(false);
    expect(
      verifyGuardianAttestation({ ...att, signature: "v2=AAAA" }, verifyV2),
    ).toEqual({ ok: false, reason: "signature-mismatch" });
    expect(
      verifyGuardianAttestation({ ...att, canonical: "{not json" }, verifyV2),
    ).toEqual({ ok: false, reason: "canonical-mismatch" });
    expect(
      verifyGuardianAttestation({ ...att, canonical: "null" }, verifyV2).ok,
    ).toBe(false);
  });

  it("orders rules by code unit, independent of locale", async () => {
    const pass = (id: string): GuardianRule => ({
      id,
      description: id,
      evaluate: async () => ({ verdict: "pass" }),
    });
    const att = await runGuardian([pass("b"), pass("B"), pass("a-")], ctx, signV2);
    const ids = (JSON.parse(att.canonical).rules as { ruleId: string }[]).map(
      (r) => r.ruleId,
    );
    expect(ids).toEqual(["B", "a-", "b"]);
  });

  it("quorumCollapse needs `required` warns, and block always wins", () => {
    expect(quorumCollapse(["warn", "pass"], 2)).toBe("pass");
    expect(quorumCollapse(["warn", "warn"], 2)).toBe("warn");
    expect(quorumCollapse(["pass", "block"], 5)).toBe("block");
  });
});

describe("signed bundle", () => {
  const rows = [
    {
      id: "r1",
      agentName: "sample-agent",
      modelUsed: "example-model",
      durationMs: 5,
      createdAt: "2026-01-01T00:00:00.000Z",
      signature: "v2=x",
      canonical: "{}",
    },
  ];

  it("verifies its manifest and rejects an edited one", () => {
    const { zip, manifest } = buildSignedBundle(rows, signV2);
    expect(zip.readUInt32LE(0)).toBe(0x04034b50);
    expect(verifyManifest(manifest, verifyV2)).toEqual({ ok: true });
    const edited = {
      ...manifest,
      receipts: [{ ...manifest.receipts[0], agentName: "other" }],
    };
    expect(verifyManifest(edited, verifyV2)).toEqual({
      ok: false,
      reason: "hash-mismatch",
    });
  });

  it("signs a __proto__ key in a receipt row", () => {
    const { manifest } = buildSignedBundle(rows, signV2);
    const receipt = JSON.parse(
      JSON.stringify(manifest.receipts[0]).replace(/}$/, ',"__proto__":{"x":1}}'),
    );
    expect(Object.hasOwn(receipt, "__proto__")).toBe(true);
    expect(verifyManifest({ ...manifest, receipts: [receipt] }, verifyV2)).toEqual({
      ok: false,
      reason: "hash-mismatch",
    });
  });
});

describe("v3 dual signature", () => {
  it("passes only when both halves hold", () => {
    const canonical = '{"sample":true}';
    const ml = generateMlDsa65Keypair();
    const mlPub = Buffer.from(ml.publicKeyB64, "base64");
    const ed = signV2(canonical).slice(3);
    const mlSig = signMlDsa65(canonical, Buffer.from(ml.secretKeyB64, "base64"));
    const wire = formatV3Wire(ed, mlSig);

    expect(verifyDualSig(canonical, wire, mlPub, verifyV2).ok).toBe(true);
    const badMl = verifyDualSig(canonical, formatV3Wire(ed, "AAAA"), mlPub, verifyV2);
    expect(badMl).toEqual({ ok: false, ed25519: true, mldsa65: false });
    const badEd = verifyDualSig(canonical, formatV3Wire("AAAA", mlSig), mlPub, verifyV2);
    expect(badEd).toEqual({ ok: false, ed25519: false, mldsa65: true });
    expect(verifyDualSig(canonical, `v2=${ed}`, mlPub, verifyV2).ok).toBe(false);
    expect(verifyDualSig("{}", wire, mlPub, verifyV2).ok).toBe(false);
    // Base64 that Buffer would accept leniently is rejected.
    const loose = formatV3Wire(ed, ` ${mlSig}`);
    expect(verifyDualSig(canonical, loose, mlPub, verifyV2).mldsa65).toBe(false);
    const unpadded = formatV3Wire(ed.replace(/=+$/, ""), mlSig);
    expect(verifyDualSig(canonical, unpadded, mlPub, verifyV2).ed25519).toBe(false);
  });
});

describe("threshold policy", () => {
  it("rejects m = 0, m > n and a short issuer list", async () => {
    const base = {
      scheme: "trs1" as const,
      canonical: "{}",
      contentHash:
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
      authorizedIssuers: ["a"],
      cosigners: [],
      assembledAt: "2026-01-01T00:00:00Z",
    };
    const opts = { verifyIssuerSignature: () => true };
    for (const threshold of [
      { m: 0, n: 1 },
      { m: 2, n: 1 },
      { m: 1, n: 2 },
      { m: 0.5, n: 1 },
    ]) {
      const r = await verifyThresholdAttestation({ ...base, threshold }, opts);
      expect(r.ok).toBe(false);
    }
  });
});

describe("VAPT parsing", () => {
  it("returns null for a payload that is JSON but not an object", () => {
    const b64 = (s: string) => Buffer.from(s).toString("base64url");
    for (const body of ["null", "1", "[]", '"vapt1"']) {
      expect(parseVapt(`vapt1.${b64(body)}.${b64("sig")}`)).toBeNull();
      const r = verifyVapt(`vapt1.${b64(body)}.${b64("sig")}`, {
        proposedAmount: 1,
        proposedCurrency: "USD",
        proposedMerchantId: "m",
        verifySignature: () => true,
        publicKeyMaterial: null,
      });
      expect(r.ok).toBe(false);
    }
  });
});
