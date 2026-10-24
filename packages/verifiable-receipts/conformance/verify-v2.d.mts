// Types for verify-v2.mjs, the conformance harness's own v2 verifier.
import type { KeyObject } from "node:crypto";

export function jsonEqual(a: unknown, b: unknown, depth?: number): boolean;
export function nestsTooDeep(value: unknown): boolean;
export function textNestsTooDeep(text: string): boolean;
export function parseReceipt(text: string): Record<string, unknown>;
export function verifyV2Receipt(
  receipt: Record<string, unknown>,
  publicKey: KeyObject,
): { ok: boolean; reason?: string };
