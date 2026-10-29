#!/usr/bin/env python3
"""Verify v2 receipts against an Ed25519 public key.

Usage: verify_receipts.py --pubkey <pem> <file> [<file> ...]

Each file holds one receipt as a JSON object, or one receipt per line
(.jsonl). Prints one JSON line per receipt to stdout and a summary to
stderr. Exit 0 when every receipt verifies, 1 when any fails, 2 on a
usage, file or install error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from sovereign_matrix.verifiable_receipts import parse_receipt, verify_v2_receipt
except ImportError:
    print(
        "verify_receipts: the sovereign-matrix-verifiable-receipts package is not installed; "
        "see SKILL.md, step 2",
        file=sys.stderr,
    )
    sys.exit(2)


def _receipt_texts(path: Path) -> list[tuple[int, str]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        return [(n, line) for n, line in enumerate(text.splitlines(), 1) if line.strip()]
    return [(1, text)]


def _verdict(text: str, pem: bytes) -> tuple[bool, str | None]:
    try:
        receipt = parse_receipt(text)
    except ValueError as err:
        return False, str(err)
    result = verify_v2_receipt(receipt, pem)
    return result.ok, result.reason


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify v2 receipts against a public key.")
    parser.add_argument("--pubkey", required=True, type=Path, help="Ed25519 public key (PEM)")
    parser.add_argument("files", nargs="+", type=Path, help="receipt files (.json or .jsonl)")
    args = parser.parse_args(argv)

    try:
        pem = args.pubkey.read_bytes()
        batches = [(path, _receipt_texts(path)) for path in args.files]
    except (OSError, UnicodeDecodeError) as err:
        print(f"verify_receipts: {err}", file=sys.stderr)
        return 2

    passed = failed = 0
    for path, texts in batches:
        for line, text in texts:
            ok, reason = _verdict(text, pem)
            passed += ok
            failed += not ok
            print(json.dumps({"file": str(path), "line": line, "ok": ok, "reason": reason}))
    print(f"verify_receipts: {passed} verified, {failed} failed", file=sys.stderr)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
