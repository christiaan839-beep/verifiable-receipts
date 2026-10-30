"""
Judges every case in cases.jsonl with the Python verifiers.

Usage: python verify.py <public.pem> <cases.jsonl> <out.jsonl>
Writes one {"id", "ok", "reason"} line per case, in case order, as it
judges it; "threw" records an exception, which the verifiers must never
raise. Receipts and Guardian
attestations are read with parse_receipt, which gives the verifiers'
reason for a receipt nested deeper than 64; any other text that does
not parse has the reason "parse failed", as in the other runners.
"""

from __future__ import annotations

import json
import sys

from sovereign_matrix.verifiable_receipts import (
    parse_receipt,
    verify_guardian_attestation,
    verify_inclusion_proof,
    verify_v2_receipt,
)

TOO_DEEP = "receipt nesting deeper than 64"


def judge(kind: str, raw: str, pem: bytes) -> tuple[bool, str | None]:
    if kind in ("receipt", "guardian"):
        try:
            value = parse_receipt(raw)
        except ValueError as err:
            return False, str(err) if str(err) == TOO_DEEP else "parse failed"
        verify = verify_v2_receipt if kind == "receipt" else verify_guardian_attestation
        result = verify(value, pem)
        return result.ok, result.reason
    try:
        proof = json.loads(raw)
    except (ValueError, RecursionError):
        return False, "parse failed"
    if not isinstance(proof, dict):
        return False, None
    ok = verify_inclusion_proof(proof, proof.get("leafHashHex"), proof.get("rootHashHex"))  # type: ignore[arg-type]
    return ok, None


def main() -> int:
    key_path, cases_path, out_path = sys.argv[1:]
    with open(key_path, "rb") as fh:
        pem = fh.read()
    with open(cases_path, encoding="utf-8") as fh, open(out_path, "w", encoding="utf-8") as out:
        for line in fh:
            case = json.loads(line)
            verdict: dict[str, object] = {"id": case["id"]}
            try:
                verdict["ok"], verdict["reason"] = judge(case["kind"], case["raw"], pem)
            except Exception as err:  # noqa: BLE001 - recorded, and fails the run
                verdict.update(ok=False, threw=repr(err))
            out.write(json.dumps(verdict) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
