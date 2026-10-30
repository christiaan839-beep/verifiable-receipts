"""
Runs the Ed25519 fixtures through the Python pre-checks.

Usage: python ed25519-checks.py <fixtures-dir>
For each fixtures/ed25519-*.json, in name order, prints one line:
"<name>\t<key reason>\t<signature reason>", with "none" for no problem,
from ed25519_public_key_problem and ed25519_signature_problem. The
round trip checks that node and Go print the same lines.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from sovereign_matrix.verifiable_receipts import (
    ed25519_public_key_problem,
    ed25519_signature_problem,
)


def key_and_signature(fixture: dict) -> tuple[bytes, bytes]:
    if "ed25519" in fixture:
        vector = fixture["ed25519"]
        return bytes.fromhex(vector["publicKey"]), bytes.fromhex(vector["signature"])
    body = "".join(
        line for line in fixture["publicKeyPem"].splitlines() if not line.startswith("-----")
    )
    raw = base64.b64decode(body)[-32:]  # SPKI: a 12-byte prefix, then the key
    return raw, base64.b64decode(fixture["receipt"]["signature"].removeprefix("v2="))


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    for path in sorted(Path(sys.argv[1]).glob("ed25519-*.json")):
        raw, sig = key_and_signature(json.loads(path.read_text(encoding="utf-8")))
        key = ed25519_public_key_problem(raw) or "none"
        signature = ed25519_signature_problem(sig) or "none"
        print(f"{path.stem}\t{key}\t{signature}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
