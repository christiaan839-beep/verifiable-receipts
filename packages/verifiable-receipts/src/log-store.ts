/**
 * Append-only log store for the receipt transparency log.
 *
 * A `LogStore` is a sequence of leaf hashes that supports only
 * `append` and `read`. Combined with the Merkle primitives in
 * `transparency.ts`, it is the storage layer of the log described
 * in `docs/specs/transparency-log.md`.
 *
 * Two implementations ship:
 *
 *   - InMemoryLogStore — pure-RAM array. For tests + ephemeral demos.
 *   - FileLogStore — append-only file. Each line is exactly 65 chars:
 *     64 lowercase hex + a `\n`. O_APPEND + fsync on every append;
 *     one writer per file; the line count is the leaf count.
 *
 * `TransparencyLog` wraps a store, builds proofs and returns unsigned
 * tree heads; the caller signs them (`v2=` or `v3=`).
 */

import {
  appendFileSync,
  readFileSync,
  existsSync,
  openSync,
  fsyncSync,
  closeSync,
} from "node:fs";
import { isHashHex } from "./hash.js";
import {
  inclusionProof,
  consistencyProof,
  buildSth,
  leafHash,
  type SignedTreeHead,
} from "./transparency.js";

// ── Storage interface ─────────────────────────────────────────────────

/**
 * Append-only sequence of leaf hashes. The store NEVER deletes or
 * mutates a leaf.
 */
export interface LogStore {
  /** Append a leaf hash (lowercase hex). Returns the new leaf's index. */
  append(leafHashHex: string): number;
  /** Current number of leaves. */
  count(): number;
  /** Get a leaf hash by index. Throws if idx is out of range. */
  get(idx: number): string;
  /** Read-only view of all leaves (for proof generation). */
  snapshot(): readonly string[];
}

/** In-memory implementation. Resets on process exit. */
export class InMemoryLogStore implements LogStore {
  private leaves: string[] = [];

  append(leafHashHex: string): number {
    assertLeafHash(leafHashHex);
    this.leaves.push(leafHashHex);
    return this.leaves.length - 1;
  }

  count(): number {
    return this.leaves.length;
  }

  get(idx: number): string {
    return leafAtIndex(this.leaves, idx);
  }

  snapshot(): readonly string[] {
    return this.leaves.slice();
  }
}

/**
 * Append-only file-backed store. Each line is `<64-hex-chars>\n` so:
 *
 *   - Append is one O_APPEND write followed by fsync. A crash during
 *     the write can leave a short last line, which the constructor
 *     rejects.
 *   - The line count is the leaf count.
 *   - The constructor reads the whole file and keeps every leaf in
 *     memory (65 bytes of file per leaf). For a log too large for
 *     that, implement `LogStore` over a database.
 */
export class FileLogStore implements LogStore {
  private leaves: string[];
  private filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
    if (existsSync(filePath)) {
      const raw = readFileSync(filePath, "utf8");
      this.leaves =
        raw === "" ? [] : raw.split("\n").filter((s) => s.length > 0);
      // Defensive: every line must be a 64-hex leaf hash. A corrupted
      // line aborts construction; the operator MUST inspect manually
      // rather than silently truncate.
      for (const [i, line] of this.leaves.entries()) {
        if (!isHashHex(line)) {
          throw new Error(
            `FileLogStore: line ${i + 1} of ${filePath} is not a valid leaf hash`,
          );
        }
      }
    } else {
      this.leaves = [];
    }
  }

  append(leafHashHex: string): number {
    assertLeafHash(leafHashHex);
    // Append with O_APPEND, then fsync before returning. The store
    // keeps its leaves in memory and takes no file lock: use one
    // FileLogStore per file, in one process.
    appendFileSync(this.filePath, leafHashHex + "\n", { mode: 0o600 });
    const fd = openSync(this.filePath, "r+");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    this.leaves.push(leafHashHex);
    return this.leaves.length - 1;
  }

  count(): number {
    return this.leaves.length;
  }

  get(idx: number): string {
    return leafAtIndex(this.leaves, idx);
  }

  snapshot(): readonly string[] {
    return this.leaves.slice();
  }
}

function assertLeafHash(leafHashHex: string): void {
  if (!isHashHex(leafHashHex)) {
    throw new Error("leafHashHex must be 64 lowercase hex characters");
  }
}

function leafAtIndex(leaves: readonly string[], idx: number): string {
  if (idx < 0 || idx >= leaves.length) {
    throw new Error(`leaf idx ${idx} out of range (count=${leaves.length})`);
  }
  return leaves[idx];
}

// ── TransparencyLog ───────────────────────────────────────────────────

export interface AppendResult {
  /** Zero-based index of the newly appended leaf. */
  index: number;
  /** SHA-256 leaf hash that was actually stored (= the input). */
  leafHashHex: string;
  /** Unsigned STH committing to the tree state after the append. */
  sth: SignedTreeHead;
}

/**
 * Thin coordinator over a `LogStore`. Computes Merkle roots, builds
 * proofs, and produces unsigned STHs. The caller is responsible for
 * signing each STH with their preferred primitive (Ed25519 in v2,
 * dual Ed25519 + ML-DSA-65 in v3).
 */
export class TransparencyLog {
  readonly logId: string;
  private readonly store: LogStore;
  private readonly clock: () => Date;

  constructor(
    logId: string,
    store: LogStore = new InMemoryLogStore(),
    clock: () => Date = () => new Date(),
  ) {
    if (!logId || typeof logId !== "string") {
      throw new Error("logId is required");
    }
    this.logId = logId;
    this.store = store;
    this.clock = clock;
  }

  /**
   * Append a leaf to the log and return the post-append STH.
   * Accepts either a raw 64-hex leaf hash or arbitrary leaf bytes
   * (will be RFC 6962 leaf-hashed automatically).
   */
  append(
    input: string | Buffer,
    opts: { alreadyHashed?: boolean } = {},
  ): AppendResult {
    let leafHashHex: string;
    if (opts.alreadyHashed) {
      if (typeof input !== "string") {
        throw new Error("alreadyHashed=true requires a string leaf hash");
      }
      leafHashHex = input;
    } else {
      leafHashHex = leafHash(input);
    }
    const index = this.store.append(leafHashHex);
    const sth = buildSth(this.logId, this.store.snapshot(), this.clock);
    return { index, leafHashHex, sth };
  }

  /** Current STH (unsigned). */
  currentSth(): SignedTreeHead {
    return buildSth(this.logId, this.store.snapshot(), this.clock);
  }

  /** Current tree size. */
  size(): number {
    return this.store.count();
  }

  /** Get the leaf hash at idx. */
  leafAt(idx: number): string {
    return this.store.get(idx);
  }

  /**
   * Inclusion proof for the leaf at `idx` against the tree of size
   * `treeSize`. Defaults to the current tree size. Throws if
   * `treeSize` exceeds the current count (can't prove against a
   * future state).
   */
  proveInclusion(idx: number, treeSize?: number): string[] {
    const n = treeSize ?? this.store.count();
    if (n > this.store.count()) {
      throw new Error(
        `treeSize ${n} exceeds current count ${this.store.count()}`,
      );
    }
    if (idx >= n) {
      throw new Error(`idx ${idx} out of range for treeSize ${n}`);
    }
    return inclusionProof(idx, this.store.snapshot().slice(0, n));
  }

  /**
   * Consistency proof from `oldSize` to `newSize`. Defaults `newSize`
   * to the current count. Throws if either size is out of range —
   * better to fail loud than silently produce an unverifiable proof.
   */
  proveConsistency(oldSize: number, newSize?: number): string[] {
    const n = newSize ?? this.store.count();
    if (n > this.store.count()) {
      throw new Error(
        `newSize ${n} exceeds current count ${this.store.count()}`,
      );
    }
    if (oldSize < 0 || oldSize > n) {
      throw new Error(`oldSize ${oldSize} out of range for newSize ${n}`);
    }
    return consistencyProof(oldSize, this.store.snapshot().slice(0, n));
  }
}
