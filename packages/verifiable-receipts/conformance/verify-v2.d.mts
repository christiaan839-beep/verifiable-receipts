// Types for verify-v2.mjs, the conformance harness's own v2 verifier.
import type { KeyObject } from "node:crypto";

export function jsonEqual(a: unknown, b: unknown): boolean;
export function verifyV2Receipt(
  receipt: Record<string, unknown>,
  publicKey: KeyObject,
): { ok: boolean; reason?: string };
