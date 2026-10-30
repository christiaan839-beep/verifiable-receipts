/**
 * @sovereignos/verifiable-receipts
 *
 * Sign receipts for AI agent actions and verify them later.
 *
 * - `pq-sign`: ML-DSA-65 (FIPS 204) signing and the `v3=` Ed25519 +
 *   ML-DSA-65 dual signature. Ed25519 is supplied by the caller.
 * - `guardian`: runs rules over an agent run and signs the verdict.
 * - `bundle`: a deterministic STORE-method ZIP with a signed manifest.
 * - `transparency`, `log-store`: an RFC 6962 / RFC 9162 Merkle log with
 *   inclusion and consistency proofs and unsigned tree heads.
 * - `threshold`: m-of-n co-signed receipts.
 * - `stream-attestation`: a Merkle commitment over a stream's chunks.
 * - `vapt`: short-lived, scoped Ed25519 payment tokens.
 * - `loadEd25519PublicKey`: loads a verification key, refusing the weak
 *   keys of VAOS 2.0 section 7.3; `verifyEd25519` verifies a signature
 *   under that section's strict profile.
 *
 * The wire formats are in SPEC.md and docs/specs/.
 *
 * @packageDocumentation
 */

export {
  signMlDsa65,
  verifyMlDsa65,
  verifyDualSig,
  formatV3Wire,
  generateMlDsa65Keypair,
  type DualSigVerdict,
} from "./pq-sign.js";

export {
  mintVapt,
  parseVapt,
  verifyVapt,
  vaptHash,
  type VaptPayload,
  type VerifyVaptOptions,
  type VaptVerifyResult,
} from "./vapt.js";

export {
  assembleThresholdAttestation,
  verifyThresholdAttestation,
  trsSigningBytes,
  type ThresholdAttestation,
  type ThresholdCosigner,
  type ThresholdVerifyOptions,
  type ThresholdVerifyResult,
} from "./threshold.js";

export {
  StreamAttestationBuilder,
  canonicalizeStreamAttestation,
  verifyChunkInclusion,
  verifyFinalOutputHash,
  type StreamChunk,
  type StreamAttestation,
  type ChunkInclusionOptions,
} from "./stream-attestation.js";

export {
  runGuardian,
  verifyGuardianAttestation,
  quorumCollapse,
  outputSizeRule,
  forbiddenSubstringRule,
  requireTokenRule,
  type GuardianVerdict,
  type GuardianContext,
  type GuardianRule,
  type RuleVerdict,
  type GuardianAttestation,
} from "./guardian.js";

export {
  buildZip,
  bundleDigest,
  buildSignedBundle,
  verifyManifest,
  type ZipEntry,
  type BundleReceiptRow,
  type BundleManifest,
} from "./bundle.js";

export {
  leafHash,
  innerHash,
  treeRoot,
  inclusionProof,
  verifyInclusionProof,
  consistencyProof,
  verifyConsistencyProof,
  buildSth,
  canonicalizeSth,
  type SignedTreeHead,
} from "./transparency.js";

export {
  ed25519PublicKeyProblem,
  ed25519SignatureProblem,
  loadEd25519PublicKey,
  verifyEd25519,
} from "./ed25519-key.js";

export {
  TransparencyLog,
  InMemoryLogStore,
  FileLogStore,
  type LogStore,
  type AppendResult,
} from "./log-store.js";
