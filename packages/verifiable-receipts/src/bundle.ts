/**
 * A STORE-method ZIP writer (no compression) and a signed receipt
 * bundle.
 *
 * The same entries give the same bytes: modification times are zero
 * and there are no extra fields. The caller's sign() callback signs the
 * manifest hash, so a set of receipts can be handed over as one file
 * whose manifest is checked without unzipping it.
 */

import { createHash } from "node:crypto";
import { canonicalJson } from "./canonical-json.js";
import { sha256Hex } from "./hash.js";

export interface ZipEntry {
  /** Path inside the archive (forward-slash separated). */
  path: string;
  /** The file's bytes; a string is written as UTF-8. */
  content: Buffer | string;
}

/** Build a STORE-method ZIP from a flat entry list. Returns a Buffer. */
export function buildZip(entries: ZipEntry[]): Buffer {
  if (entries.length > 65_535) {
    throw new Error("buildZip: max 65535 entries (ZIP format limit)");
  }
  const fileChunks: Buffer[] = [];
  const centralChunks: Buffer[] = [];
  let runningOffset = 0;

  for (const e of entries) {
    const nameBytes = Buffer.from(e.path, "utf8");
    const data = entryBytes(e);
    if (data.length > 0xffff_ffff) {
      throw new Error(`buildZip: file too large: ${e.path}`);
    }
    const crc = crc32(data);
    const size = data.length;

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(size, 18);
    localHeader.writeUInt32LE(size, 22);
    localHeader.writeUInt16LE(nameBytes.length, 26);
    localHeader.writeUInt16LE(0, 28);
    fileChunks.push(localHeader, nameBytes, data);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(size, 20);
    centralHeader.writeUInt32LE(size, 24);
    centralHeader.writeUInt16LE(nameBytes.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(runningOffset, 42);
    centralChunks.push(centralHeader, nameBytes);

    runningOffset += localHeader.length + nameBytes.length + data.length;
  }

  const centralDir = Buffer.concat(centralChunks);
  const centralOffset = runningOffset;
  const endRecord = Buffer.alloc(22);
  endRecord.writeUInt32LE(0x06054b50, 0);
  endRecord.writeUInt16LE(0, 4);
  endRecord.writeUInt16LE(0, 6);
  endRecord.writeUInt16LE(entries.length, 8);
  endRecord.writeUInt16LE(entries.length, 10);
  endRecord.writeUInt32LE(centralDir.length, 12);
  endRecord.writeUInt32LE(centralOffset, 16);
  endRecord.writeUInt16LE(0, 20);

  return Buffer.concat([...fileChunks, centralDir, endRecord]);
}

/** SHA-256 over a deterministic concatenation of (path, bytes) pairs. */
export function bundleDigest(entries: ZipEntry[]): string {
  const h = createHash("sha256");
  for (const e of entries) {
    h.update(e.path, "utf8");
    h.update("\0");
    h.update(entryBytes(e));
    h.update("\0");
  }
  return h.digest("hex");
}

// ── Signed receipt bundle ─────────────────────────────────────────────

export interface BundleReceiptRow {
  id: string;
  agentName: string;
  modelUsed: string;
  durationMs: number;
  createdAt: Date | string;
  signature: string;
  canonical: string;
}

export interface BundleManifest {
  v: 1;
  type: "verifiable-receipt-bundle";
  generatedAt: string;
  receiptCount: number;
  bundleDigest: string;
  manifestHash: string;
  signature: string;
  receipts: Array<{
    id: string;
    agentName: string;
    modelUsed: string;
    issuedAt: string;
    signature: string;
  }>;
}

/**
 * Build a signed bundle: three files per receipt and a
 * MANIFEST.signed.json whose `manifestHash` the caller's `sign` signs.
 */
export function buildSignedBundle(
  rows: BundleReceiptRow[],
  sign: (manifestHash: string) => string,
): { zip: Buffer; manifest: BundleManifest } {
  const generatedAt = new Date().toISOString();
  const entries: ZipEntry[] = [];
  for (const r of rows) {
    const id = sanitizePath(r.id);
    const issuedAt = isoString(r.createdAt);
    entries.push({ path: `receipts/${id}.canonical.txt`, content: r.canonical });
    entries.push({ path: `receipts/${id}.signature.txt`, content: r.signature });
    entries.push({
      path: `receipts/${id}.meta.json`,
      content: JSON.stringify(
        {
          id: r.id,
          agentName: r.agentName,
          modelUsed: r.modelUsed,
          durationMs: r.durationMs,
          issuedAt,
        },
        null,
        2,
      ),
    });
  }
  const digest = bundleDigest(entries);
  const body = {
    v: 1 as const,
    type: "verifiable-receipt-bundle" as const,
    generatedAt,
    receiptCount: rows.length,
    bundleDigest: digest,
    receipts: rows.map((r) => ({
      id: r.id,
      agentName: r.agentName,
      modelUsed: r.modelUsed,
      issuedAt: isoString(r.createdAt),
      signature: r.signature,
    })),
  };
  const manifestHash = sha256Hex(canonicalJson(body));
  const signature = sign(manifestHash);
  const manifest: BundleManifest = { ...body, manifestHash, signature };
  entries.push({
    path: "MANIFEST.signed.json",
    content: JSON.stringify(manifest, null, 2),
  });
  return { zip: buildZip(entries), manifest };
}

/**
 * Verify a manifest's type, version, hash and signature.
 *
 * This checks the manifest only. It does not open the ZIP: to check
 * the files, recompute `bundleDigest()` over the archive's entries
 * (without MANIFEST.signed.json) and compare it with
 * `manifest.bundleDigest`. The receipts' own signatures are not
 * checked here either.
 */
export function verifyManifest(
  manifest: BundleManifest,
  verify: (canonical: string, signature: string) => boolean,
):
  | { ok: true }
  | {
      ok: false;
      reason:
        | "hash-mismatch"
        | "signature-mismatch"
        | "wrong-type"
        | "wrong-version";
    } {
  if (manifest.type !== "verifiable-receipt-bundle") {
    return { ok: false, reason: "wrong-type" };
  }
  if (manifest.v !== 1) return { ok: false, reason: "wrong-version" };
  const body = {
    v: manifest.v,
    type: manifest.type,
    generatedAt: manifest.generatedAt,
    receiptCount: manifest.receiptCount,
    bundleDigest: manifest.bundleDigest,
    receipts: manifest.receipts,
  };
  if (sha256Hex(canonicalJson(body)) !== manifest.manifestHash) {
    return { ok: false, reason: "hash-mismatch" };
  }
  if (!verify(manifest.manifestHash, manifest.signature)) {
    return { ok: false, reason: "signature-mismatch" };
  }
  return { ok: true };
}

// ── Internals ─────────────────────────────────────────────────────────

function entryBytes(entry: ZipEntry): Buffer {
  return typeof entry.content === "string"
    ? Buffer.from(entry.content, "utf8")
    : entry.content;
}

function isoString(date: Date | string): string {
  return date instanceof Date ? date.toISOString() : date;
}

function sanitizePath(s: string): string {
  return s.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 128);
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) === 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = (c >>> 8) ^ CRC_TABLE[(c ^ buf[i]) & 0xff];
  }
  return (c ^ 0xffffffff) >>> 0;
}
