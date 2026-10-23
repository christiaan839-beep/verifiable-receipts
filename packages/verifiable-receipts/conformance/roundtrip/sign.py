"""
Signs a receipt body with the Python signer, sign_v2_receipt().

Usage: python sign.py <ed25519-private.pem> <body.json> <out.json>
"""

from __future__ import annotations

import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from sovereign_matrix.verifiable_receipts import sign_v2_receipt


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    key_path, body_path, out_path = sys.argv[1:]
    with open(key_path, "rb") as fh:
        key = load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        print("error: not an Ed25519 private key", file=sys.stderr)
        return 2
    with open(body_path, encoding="utf-8") as fh:
        body = json.load(fh)
    receipt = sign_v2_receipt(body, key)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(receipt, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
