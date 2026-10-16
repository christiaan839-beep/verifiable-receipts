"""
Verifies a receipt or Guardian attestation with the Python verifier.

Usage: python verify.py <ed25519-public.pem> <receipt|guardian> <file.json>
Prints "ok" and exits 0, or prints "rejected: <reason>" and exits 1.
"""

from __future__ import annotations

import json
import sys

from sovereign_matrix.verifiable_receipts import (
    verify_guardian_attestation,
    verify_v2_receipt,
)


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[2] not in ("receipt", "guardian"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    key_path, kind, path = sys.argv[1:]
    with open(key_path, "rb") as fh:
        pem = fh.read()
    with open(path, encoding="utf-8") as fh:
        receipt = json.load(fh)
    verify = verify_v2_receipt if kind == "receipt" else verify_guardian_attestation
    result = verify(receipt, pem)
    if result.ok:
        print("ok")
        return 0
    print(f"rejected: {result.reason}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
