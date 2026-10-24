/**
 * Guardian rule runner. The caller passes a list of rules; the runner
 * evaluates them in parallel against a `GuardianContext` and collapses
 * the verdicts into a single signed attestation envelope.
 *
 * The caller's `sign()` callback signs the canonical: Node's
 * crypto.sign(Ed25519), the pq-sign module of this package, or a KMS or
 * HSM.
 *
 * @packageDocumentation
 */

import { randomUUID } from "node:crypto";
import { sha256Hex } from "./hash.js";
import { nestsDeeperThan } from "./nesting.js";

export type GuardianVerdict = "pass" | "warn" | "block";

export interface GuardianContext {
  runId: string;
  agentSlug: string;
  tokenId?: string;
  input: unknown;
  output: unknown;
  /** Optional identifier of the model that produced the output. Not signed. */
  modelUsed?: string;
}

export interface GuardianRule {
  id: string;
  description: string;
  evaluate: (ctx: GuardianContext) => Promise<{
    verdict: GuardianVerdict;
    reason?: string;
    evidence?: Record<string, unknown>;
  }>;
}

export interface RuleVerdict {
  ruleId: string;
  verdict: GuardianVerdict;
  reason?: string;
  evidence?: Record<string, unknown>;
  durationMs: number;
}

export interface GuardianAttestation {
  verdictId: string;
  overall: GuardianVerdict;
  rules: RuleVerdict[];
  totalMs: number;
  issuedAt: string;
  canonical: string;
  contentHash: string;
  signature: string;
}

/**
 * Run every rule in parallel against the context, collapse the
 * verdicts (block > warn > pass), and sign the envelope.
 *
 * Throwing rules become `warn` verdicts with the error message —
 * rules never break the pipeline.
 */
export async function runGuardian(
  rules: GuardianRule[],
  ctx: GuardianContext,
  sign: (canonical: string) => string,
): Promise<GuardianAttestation> {
  const startedAt = Date.now();
  const verdictId = randomUUID();

  const evaluated: RuleVerdict[] = await Promise.all(
    rules.map(async (rule) => {
      const t = Date.now();
      try {
        const outcome = await rule.evaluate(ctx);
        return {
          ruleId: rule.id,
          verdict: outcome.verdict,
          reason: outcome.reason,
          evidence: outcome.evidence,
          durationMs: Date.now() - t,
        };
      } catch (err) {
        return {
          ruleId: rule.id,
          verdict: "warn" as const,
          reason: err instanceof Error ? err.message : String(err),
          durationMs: Date.now() - t,
        };
      }
    }),
  );

  const overall: GuardianVerdict = evaluated.some((r) => r.verdict === "block")
    ? "block"
    : evaluated.some((r) => r.verdict === "warn")
      ? "warn"
      : "pass";

  const issuedAt = new Date().toISOString();
  const totalMs = Date.now() - startedAt;

  const canonical = canonicalize({
    verdictId,
    runId: ctx.runId,
    agentSlug: ctx.agentSlug,
    tokenId: ctx.tokenId,
    overall,
    rules: evaluated,
    issuedAt,
  });
  const contentHash = sha256Hex(canonical);
  const signature = sign(canonical);

  return {
    verdictId,
    overall,
    rules: evaluated,
    totalMs,
    issuedAt,
    canonical,
    contentHash,
    signature,
  };
}

/**
 * Re-derive the canonical from the attestation's fields, compare it with
 * `canonical` and `contentHash`, and check the signature with the
 * caller's `verify`. An attestation nested deeper than 64 (VAOS 2.0
 * section 7.2) is rejected first, with reason "nesting-too-deep".
 */
export function verifyGuardianAttestation(
  attestation: GuardianAttestation,
  verify: (canonical: string, signature: string) => boolean,
): { ok: boolean; reason?: string } {
  if (nestsDeeperThan(attestation)) return { ok: false, reason: "nesting-too-deep" };
  // runId, agentSlug and tokenId are not envelope fields; they are read
  // from the canonical, which bound them at issuance.
  let raw: unknown;
  try {
    raw = JSON.parse(attestation.canonical);
  } catch {
    return { ok: false, reason: "canonical-mismatch" };
  }
  if (raw === null || typeof raw !== "object") {
    return { ok: false, reason: "canonical-mismatch" };
  }
  const parsed = raw as { runId: string; agentSlug: string; tokenId?: string | null };
  const recomputed = canonicalize({
    verdictId: attestation.verdictId,
    runId: parsed.runId,
    agentSlug: parsed.agentSlug,
    tokenId: parsed.tokenId ?? undefined,
    overall: attestation.overall,
    rules: attestation.rules,
    issuedAt: attestation.issuedAt,
  });
  if (recomputed !== attestation.canonical) {
    return { ok: false, reason: "canonical-mismatch" };
  }
  if (sha256Hex(recomputed) !== attestation.contentHash) {
    return { ok: false, reason: "hash-mismatch" };
  }
  if (!verify(recomputed, attestation.signature)) {
    return { ok: false, reason: "signature-mismatch" };
  }
  return { ok: true };
}

/**
 * Collapse multiple independently-run verdicts under an M-of-N
 * quorum. Block beats everything; warn requires `required` warns;
 * pass otherwise.
 */
export function quorumCollapse(
  verdicts: GuardianVerdict[],
  required: number,
): GuardianVerdict {
  if (verdicts.some((v) => v === "block")) return "block";
  const warns = verdicts.filter((v) => v === "warn").length;
  if (warns >= required) return "warn";
  return "pass";
}

// ── Built-in rule library ────────────────────────────────────────────

/** Block when the output exceeds maxBytes (scope-drift by volume). */
export function outputSizeRule(maxBytes: number): GuardianRule {
  return {
    id: "output-size",
    description: `Block outputs larger than ${maxBytes} bytes`,
    evaluate: async (ctx) => {
      const size = Buffer.byteLength(JSON.stringify(ctx.output ?? ""), "utf8");
      if (size > maxBytes) {
        return {
          verdict: "block",
          reason: `output ${size}b > limit ${maxBytes}b`,
          evidence: { size, maxBytes },
        };
      }
      return { verdict: "pass" };
    },
  };
}

/** Warn/block on forbidden substrings (PII, brand-ban terms, etc.). */
export function forbiddenSubstringRule(
  needles: string[],
  level: GuardianVerdict = "warn",
): GuardianRule {
  return {
    id: "forbidden-substring",
    description: `${level} when output contains any of [${needles.length} terms]`,
    evaluate: async (ctx) => {
      const text = JSON.stringify(ctx.output ?? "").toLowerCase();
      const hits = needles.filter((n) => text.includes(n.toLowerCase()));
      if (hits.length === 0) return { verdict: "pass" };
      return {
        verdict: level,
        reason: `output contains ${hits.length} forbidden substring(s)`,
        evidence: { hits },
      };
    },
  };
}

/** Block runs that carry no `tokenId` (bring your own token issuance). */
export const requireTokenRule: GuardianRule = {
  id: "require-token",
  description: "Block runs that did not carry a JIT identity token",
  evaluate: async (ctx) => {
    if (!ctx.tokenId) {
      return {
        verdict: "block",
        reason: "no JIT token bound to this run",
      };
    }
    return { verdict: "pass" };
  },
};

// ── Internals ─────────────────────────────────────────────────────────

function canonicalize(input: {
  verdictId: string;
  runId: string;
  agentSlug: string;
  tokenId?: string;
  overall: GuardianVerdict;
  rules: RuleVerdict[];
  issuedAt: string;
}): string {
  return JSON.stringify({
    v: 1,
    type: "guardian-verdict",
    verdictId: input.verdictId,
    runId: input.runId,
    agentSlug: input.agentSlug,
    tokenId: input.tokenId ?? null,
    overall: input.overall,
    rules: input.rules
      .slice()
      .sort((a, b) => (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0))
      .map((r) => ({
        ruleId: r.ruleId,
        verdict: r.verdict,
        reason: r.reason ?? null,
      })),
    issuedAt: input.issuedAt,
  });
}
