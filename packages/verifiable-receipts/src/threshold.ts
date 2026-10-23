/**
 * Threshold Receipt Signatures (TRS) — m-of-n issuer co-signing.
 *
 * A TRS envelope verifies only when at least `m` of its `n` authorized
 * issuers have signed the same bytes, so forging one takes `m` issuers'
 * keys rather than one.
 *
 * The envelope carries its own policy (m, n, authorizedIssuers), and
 * each cosigner signs `trsSigningBytes()`, which binds that policy.
 * The verifier checks that the policy is well formed, but whether m
 * and the issuer list are the ones the relying party expects is the
 * caller's decision: compare them with your own policy before
 * trusting `ok`.
 *
 * The receipt's `canonical` is the VAOS 2.0 projection, unchanged.
 * Cosigners do not sign it directly: they sign `trsSigningBytes()`,
 * which wraps it with the policy, so a VAOS 2.0 signature over the
 * same canonical does not count as a cosignature.
 *
 * @packageDocumentation
 */

import { sha256Hex } from "./hash.js";

/** The threshold-signed envelope; its wire format is this object as JSON. */
export interface ThresholdAttestation {
  /** Stable schema version. Verifiers MUST tolerate additive fields. */
  scheme: "trs1";
  /** The receipt's VAOS 2.0 canonical projection, wrapped by `trsSigningBytes()` for signing. */
  canonical: string;
  /** sha256(canonical) for cross-check. */
  contentHash: string;
  /** Threshold parameters. */
  threshold: {
    /** Minimum number of valid signatures required. */
    m: number;
    /** Total number of designated issuers. */
    n: number;
  };
  /**
   * The full set of authorized issuer ids. Verifiers MUST only count
   * signatures whose issuerId is in this list (defense against an
   * attacker padding the cosigners array with rogue keys).
   */
  authorizedIssuers: string[];
  /** Each issuer's contribution. Order does not matter. */
  cosigners: ThresholdCosigner[];
  /** ISO-8601 of when this envelope was assembled. */
  assembledAt: string;
}

export interface ThresholdCosigner {
  /** Stable issuer id (must appear in authorizedIssuers). */
  issuerId: string;
  /** Wire-format signature: v2= or v3= prefix, base64 body. */
  signature: string;
  /** Optional pubkey URL where verifiers can fetch the issuer's PEM. */
  publicKeyUrl?: string;
}

export interface ThresholdVerifyOptions {
  /**
   * Verifier callback: given (canonical, signature, issuerId), return
   * true if the signature verifies under that issuer's public key.
   * The caller supplies the signature check and the mapping from issuer
   * id to public key.
   */
  verifyIssuerSignature: (
    canonical: string,
    signature: string,
    issuerId: string,
  ) => boolean | Promise<boolean>;
}

export interface ThresholdVerifyResult {
  ok: boolean;
  reason?: string;
  /** Number of issuers whose signature verified AND appears in authorizedIssuers. */
  validSignatureCount: number;
  /** Threshold requirement. */
  required: number;
  /** Verifying issuers, in canonical order (for audit). */
  verifyingIssuers: string[];
  /** Cosigners we rejected and why. */
  rejected: Array<{ issuerId: string; reason: string }>;
}

/**
 * Compute the bytes each cosigner MUST sign for a TRS envelope.
 *
 * Binds the canonical receipt bytes together with the threshold
 * parameters (m, n) and the sorted authorizedIssuers list. Without
 * this binding, an attacker who collects valid VAOS v2 signatures
 * for the same canonical from m authorized issuers could rewrap
 * them into a TRS envelope with arbitrary (m, n) and authorizedIssuers
 * values — none of which the cosigners explicitly agreed to.
 *
 * The wire-tag `trs1:` plus the sorted authorizedIssuers commit each
 * signature to a specific TRS configuration. Reusing a signature
 * collected for VAOS v2 (which signs raw canonical, no tag) is
 * impossible because the byte strings differ.
 *
 * @public
 */
export function trsSigningBytes(
  canonical: string,
  threshold: { m: number; n: number },
  authorizedIssuers: readonly string[],
): string {
  const sorted = [...authorizedIssuers].sort();
  return JSON.stringify({
    scheme: "trs1",
    canonical,
    m: threshold.m,
    n: threshold.n,
    authorizedIssuers: sorted,
  });
}

/**
 * Assemble a threshold envelope from a canonical projection and the
 * cosigners' signatures. It does not verify the signatures.
 *
 * Throws on malformed inputs (negative m, m > n, duplicate issuerIds,
 * etc.) — these are programmer errors, not adversarial inputs.
 */
export function assembleThresholdAttestation(args: {
  canonical: string;
  threshold: { m: number; n: number };
  authorizedIssuers: string[];
  cosigners: ThresholdCosigner[];
  assembledAt?: string;
}): ThresholdAttestation {
  const { canonical, threshold, authorizedIssuers, cosigners } = args;

  if (!canonical || typeof canonical !== "string") {
    throw new Error("TRS: canonical must be a non-empty string");
  }
  if (
    !Number.isInteger(threshold.m) ||
    !Number.isInteger(threshold.n) ||
    threshold.m < 1 ||
    threshold.n < 1
  ) {
    throw new Error("TRS: threshold m and n must be positive integers");
  }
  if (threshold.m > threshold.n) {
    throw new Error("TRS: threshold m cannot exceed n");
  }
  if (authorizedIssuers.length !== threshold.n) {
    throw new Error(
      `TRS: authorizedIssuers length (${authorizedIssuers.length}) must equal threshold.n (${threshold.n})`,
    );
  }
  if (new Set(authorizedIssuers).size !== authorizedIssuers.length) {
    throw new Error("TRS: authorizedIssuers must be unique");
  }

  const seen = new Set<string>();
  for (const c of cosigners) {
    if (!c.issuerId) throw new Error("TRS: cosigner issuerId required");
    if (!c.signature) throw new Error("TRS: cosigner signature required");
    if (seen.has(c.issuerId)) {
      throw new Error(
        `TRS: duplicate cosigner issuerId "${c.issuerId}" — each issuer signs at most once`,
      );
    }
    seen.add(c.issuerId);
  }

  return {
    scheme: "trs1",
    canonical,
    contentHash: sha256Hex(canonical),
    threshold,
    authorizedIssuers,
    cosigners,
    assembledAt: args.assembledAt ?? new Date().toISOString(),
  };
}

/**
 * Verify a threshold attestation. Returns ok=true only when:
 *   - scheme is "trs1"
 *   - the policy is well formed (below)
 *   - contentHash matches sha256(canonical)
 *   - at least threshold.m distinct authorized cosigners have a
 *     signature that verifies over `trsSigningBytes()`
 *
 * Cosigners with unknown issuerIds or invalid signatures are reported
 * in `rejected` but do NOT cause verification failure on their own —
 * verification fails only if the COUNT falls below m.
 *
 * The threshold itself must be well formed: integers with
 * 1 <= m <= n, and exactly n unique authorizedIssuers. An envelope
 * with m = 0 would otherwise verify with no signatures at all.
 *
 * The caller's `verifyIssuerSignature` checks each signature.
 */
export async function verifyThresholdAttestation(
  attestation: ThresholdAttestation,
  opts: ThresholdVerifyOptions,
): Promise<ThresholdVerifyResult> {
  const rejected: ThresholdVerifyResult["rejected"] = [];

  if (attestation.scheme !== "trs1") {
    return {
      ok: false,
      reason: `unknown scheme "${String(attestation.scheme)}"`,
      validSignatureCount: 0,
      required: 0,
      verifyingIssuers: [],
      rejected,
    };
  }

  const policyError = thresholdPolicyError(attestation);
  if (policyError) {
    return {
      ok: false,
      reason: policyError,
      validSignatureCount: 0,
      required: 0,
      verifyingIssuers: [],
      rejected,
    };
  }

  const expectedHash = sha256Hex(attestation.canonical);
  if (expectedHash !== attestation.contentHash) {
    return {
      ok: false,
      reason: "contentHash mismatch with canonical bytes",
      validSignatureCount: 0,
      required: attestation.threshold.m,
      verifyingIssuers: [],
      rejected,
    };
  }

  const authorized = new Set(attestation.authorizedIssuers);
  const seen = new Set<string>();
  const verifying: string[] = [];

  // Bind the canonical bytes with the TRS configuration. Every
  // cosigner MUST have signed this same byte string — never the raw
  // canonical alone. This prevents reusing a VAOS v2 signature
  // (which signs raw canonical, no tag) as a TRS cosignature.
  const boundBytes = trsSigningBytes(
    attestation.canonical,
    attestation.threshold,
    attestation.authorizedIssuers,
  );

  for (const c of attestation.cosigners) {
    if (!authorized.has(c.issuerId)) {
      rejected.push({
        issuerId: c.issuerId,
        reason: "issuer not in authorizedIssuers",
      });
      continue;
    }
    if (seen.has(c.issuerId)) {
      rejected.push({
        issuerId: c.issuerId,
        reason: "duplicate cosigner (already counted)",
      });
      continue;
    }
    seen.add(c.issuerId);
    let ok: boolean;
    try {
      ok = await opts.verifyIssuerSignature(
        boundBytes,
        c.signature,
        c.issuerId,
      );
    } catch (err) {
      rejected.push({
        issuerId: c.issuerId,
        reason: `verifier threw: ${err instanceof Error ? err.message : String(err)}`,
      });
      continue;
    }
    if (!ok) {
      rejected.push({
        issuerId: c.issuerId,
        reason: "signature did not verify",
      });
      continue;
    }
    verifying.push(c.issuerId);
  }

  // Canonical sort for stable audit ordering.
  verifying.sort();

  const ok = verifying.length >= attestation.threshold.m;
  return {
    ok,
    reason: ok
      ? undefined
      : `insufficient valid signatures (have ${verifying.length}, need ${attestation.threshold.m})`,
    validSignatureCount: verifying.length,
    required: attestation.threshold.m,
    verifyingIssuers: verifying,
    rejected,
  };
}

function thresholdPolicyError(a: ThresholdAttestation): string | null {
  const t = a.threshold as { m?: unknown; n?: unknown } | undefined;
  if (
    !t ||
    !Number.isInteger(t.m) ||
    !Number.isInteger(t.n) ||
    (t.m as number) < 1 ||
    (t.m as number) > (t.n as number)
  ) {
    return "threshold must have integers 1 <= m <= n";
  }
  if (
    !Array.isArray(a.authorizedIssuers) ||
    a.authorizedIssuers.length !== t.n ||
    new Set(a.authorizedIssuers).size !== a.authorizedIssuers.length
  ) {
    return "authorizedIssuers must list exactly n unique issuers";
  }
  if (typeof a.canonical !== "string" || !Array.isArray(a.cosigners)) {
    return "malformed envelope";
  }
  return null;
}
