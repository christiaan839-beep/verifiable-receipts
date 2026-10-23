/**
 * Regenerates the v2 signature fixtures (v2-*.json) and public-key.pem
 * of the cross-language conformance corpus: it makes a fresh key pair,
 * signs the fixtures and writes the public key beside them. The
 * private keys are never written; verification needs only the public
 * key.
 *
 * Inclusion-proof fixtures (inclusion-*.json) are key-independent
 * and are NOT touched by this script.
 *
 * Usage: node packages/verifiable-receipts/conformance/generate-fixtures.mjs
 */
import { generateKeyPairSync, createHash, sign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "fixtures");

const CANONICAL =
  '{"agentSlug":"loan-underwriter","issuedAt":"2026-05-18T10:00:00Z","overall":"pass","rules":[{"ruleId":"hipaa-no-raw-ssn","verdict":"pass","durationMs":2}],"runId":"run_conformance_001","tokenId":"tok_001","verdictId":"v_conf_001"}';
// Same receipt with overall flipped to "warn" — the signature and
// contentHash still cover the "pass" bytes, so verifiers must reject
// on contentHash mismatch first.
const CANONICAL_TAMPERED = CANONICAL.replace(
  '"overall":"pass"',
  '"overall":"warn"',
);

const contentHash =
  "sha256:" + createHash("sha256").update(CANONICAL, "utf8").digest("hex");

// CANONICAL's fields repeated beside it, as a receipt carries them. The
// rule's keys are in another order: verifiers compare JSON values, so
// key order does not matter. Every field beside canonical, contentHash
// and signature must equal the canonical's.
const ENVELOPE = {
  agentSlug: "loan-underwriter",
  issuedAt: "2026-05-18T10:00:00Z",
  overall: "pass",
  rules: [{ durationMs: 2, ruleId: "hipaa-no-raw-ssn", verdict: "pass" }],
  runId: "run_conformance_001",
  tokenId: "tok_001",
  verdictId: "v_conf_001",
};

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const { privateKey: wrongKey } = generateKeyPairSync("ed25519");

const signWith = (key) =>
  "v2=" + sign(null, Buffer.from(CANONICAL, "utf8"), key).toString("base64");

// The same signature spelled differently: a 64-byte value ends in a
// base64 character with four unused bits; set one. Lenient decoders
// return the same bytes, so only a strict decoder rejects it.
const ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function respell(wire) {
  const b64 = wire.slice(3);
  const last = ALPHABET.indexOf(b64[b64.length - 3]);
  return `v2=${b64.slice(0, -3)}${ALPHABET[last ^ 1]}==`;
}

// The same signature with a line feed after its fourth character. Some
// base64 decoders skip CR and LF (Go's does even in strict mode) and
// return the same bytes; a verifier must reject the spelling.
function withLineFeed(wire) {
  const b64 = wire.slice(3);
  return `v2=${b64.slice(0, 4)}\n${b64.slice(4)}`;
}

const fixtures = {
  "v2-valid-001.json": {
    description: "v2 valid — well-formed Guardian attestation",
    receipt: {
      canonical: CANONICAL,
      contentHash,
      signature: signWith(privateKey),
    },
    expected: { ok: true },
  },
  "v2-invalid-tampered.json": {
    description: "v2 invalid — canonical bytes tampered post-sign",
    receipt: {
      canonical: CANONICAL_TAMPERED,
      contentHash,
      signature: signWith(privateKey),
    },
    expected: { ok: false, reasonContains: "contentHash" },
  },
  // A present contentHash must be a hash, even when empty: the valid
  // signature over the valid canonical, with contentHash "". A verifier
  // that tests the field for truthiness treats it as absent and accepts.
  "v2-invalid-empty-contenthash.json": {
    description:
      "v2 invalid — contentHash present but empty (a present contentHash must be a hash; the signature is valid)",
    receipt: {
      canonical: CANONICAL,
      contentHash: "",
      signature: signWith(privateKey),
    },
    expected: { ok: false, reasonContains: "contentHash" },
  },
  "v2-invalid-wrong-key.json": {
    description: "v2 invalid — signature under wrong key",
    receipt: {
      canonical: CANONICAL,
      contentHash,
      signature: signWith(wrongKey),
    },
    expected: { ok: false, reasonContains: "signature" },
  },
  "v2-invalid-bad-base64.json": {
    description: "v2 invalid — signature base64 malformed",
    receipt: {
      canonical: CANONICAL,
      signature: "v2=!!!notbase64!!!",
    },
    expected: { ok: false, reasonContains: "base64" },
  },
  "v2-invalid-noncanonical-base64.json": {
    description:
      "v2 invalid — signature base64 is not canonical (non-zero padding bits; decodes to the valid signature's bytes)",
    receipt: {
      canonical: CANONICAL,
      contentHash,
      signature: respell(signWith(privateKey)),
    },
    expected: { ok: false, reasonContains: "base64" },
  },
  "v2-invalid-crlf-base64.json": {
    description:
      "v2 invalid — signature base64 has a line feed inside (decoders that skip whitespace return the valid signature's bytes)",
    receipt: {
      canonical: CANONICAL,
      contentHash,
      signature: withLineFeed(signWith(privateKey)),
    },
    expected: { ok: false, reasonContains: "base64" },
  },
  "v2-invalid-wrong-version.json": {
    description: "v2 invalid — signature has v1 prefix",
    receipt: {
      canonical: CANONICAL,
      signature: "v1=aG1hYw==",
    },
    expected: { ok: false, reasonContains: "v2" },
  },
  "v2-valid-envelope-agrees.json": {
    description:
      "v2 valid — envelope fields repeat the signed canonical (a nested object's keys in another order)",
    receipt: {
      ...ENVELOPE,
      canonical: CANONICAL,
      contentHash,
      signature: signWith(privateKey),
    },
    expected: { ok: true },
  },
  "v2-invalid-envelope-disagrees.json": {
    description:
      "v2 invalid — envelope field overall says fail, the signed canonical says pass",
    receipt: {
      ...ENVELOPE,
      overall: "fail",
      canonical: CANONICAL,
      contentHash,
      signature: signWith(privateKey),
    },
    expected: {
      ok: false,
      reasonContains: 'envelope field "overall" disagrees',
    },
  },
  "v2-invalid-envelope-unsigned.json": {
    description:
      "v2 invalid — envelope field approvedBy is not in the signed canonical",
    receipt: {
      ...ENVELOPE,
      approvedBy: "compliance-officer",
      canonical: CANONICAL,
      contentHash,
      signature: signWith(privateKey),
    },
    expected: {
      ok: false,
      reasonContains: 'envelope field "approvedBy" is not in the signed canonical',
    },
  },
};

const pem = publicKey.export({ type: "spki", format: "pem" });
writeFileSync(join(HERE, "public-key.pem"), pem);
console.log("wrote public-key.pem");

for (const [name, fixture] of Object.entries(fixtures)) {
  const body = JSON.stringify(fixture, null, 2) + "\n";
  writeFileSync(join(FIXTURES, name), body);
  const sha = createHash("sha256").update(body, "utf8").digest("hex");
  console.log(`wrote fixtures/${name}  sha256:${sha}`);
}

console.log(
  "\nDone. Private keys were held in memory only and are now discarded.",
);
