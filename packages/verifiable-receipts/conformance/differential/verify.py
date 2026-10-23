"""
Judges every case in cases.jsonl with the Python verifiers.

Usage: python verify.py <public.pem> <cases.jsonl> <out.jsonl>
Writes one {"id", "ok"} line per case; "threw" records an exception,
which the verifiers must never raise.
"""

from __future__ import annotations

import json
import sys

from sovereign_matrix.verifiable_receipts import verify_inclusion_proof, verify_v2_receipt


def judge(kind: str, value: object, pem: bytes) -> bool:
    if kind == "receipt":
        return verify_v2_receipt(value, pem).ok  # type: ignore[arg-type]
    if not isinstance(value, dict):
        return False
    return verify_inclusion_proof(value, value.get("leafHashHex"), value.get("rootHashHex"))  # type: ignore[arg-type]


def main() -> int:
    key_path, cases_path, out_path = sys.argv[1:]
    with open(key_path, "rb") as fh:
        pem = fh.read()
    lines = []
    with open(cases_path, encoding="utf-8") as fh:
        for line in fh:
            case = json.loads(line)
            result: dict[str, object] = {"id": case["id"]}
            try:
                value = json.loads(case["raw"])
            except ValueError:
                result["ok"] = False
            else:
                try:
                    result["ok"] = judge(case["kind"], value, pem)
                except Exception as err:  # noqa: BLE001 - recorded, and fails the run
                    result.update(ok=False, threw=repr(err))
            lines.append(json.dumps(result))
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
