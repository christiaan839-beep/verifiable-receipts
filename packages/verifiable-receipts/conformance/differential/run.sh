#!/usr/bin/env bash
# Differential run: the TypeScript, Python and Go verifiers judge the same
# random receipts and inclusion proofs, and must agree on every one.
#
# gen.py writes the cases (most start valid and get one or two mutations:
# signature spellings, contentHash forms, envelope fields, numbers, hex
# case and prefixes, index and size edge values). Each verifier parses
# each case with its own JSON parser. compare.py fails on any
# disagreement or exception and writes the cases to disagreements.jsonl.
# Every stage reads and writes its JSONL a line at a time, and each
# runner writes its verdicts in case order, so compare.py reads the four
# files side by side: memory stays flat at any number of cases.
#
# Needs node 22+ with packages/verifiable-receipts built, python 3.10+
# with `cryptography`, and go 1.22+. The Python package is read from the
# working tree (PYTHONPATH).
#
# Usage: bash run.sh [cases] [seed] [out-dir]   (defaults: 2000, 1, a temp dir)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="$(cd "$HERE/../.." && pwd)"
PY_PKG="$(cd "$PKG/../verifiable-receipts-py" && pwd)"
PYTHON="${PYTHON:-python3}"
export PYTHONPATH="$PY_PKG${PYTHONPATH:+:$PYTHONPATH}"
CASES="${1:-2000}"
SEED="${2:-1}"
OUT="${3:-}"

if [ ! -f "$PKG/dist/transparency.js" ]; then
  echo "error: build the TypeScript package first (npm install && npm run build in $PKG)" >&2
  exit 2
fi
if [ -z "$OUT" ]; then
  OUT="$(mktemp -d)"
  trap 'rm -rf "$OUT"' EXIT
fi
mkdir -p "$OUT"

"$PYTHON" "$HERE/gen.py" "$OUT" "$CASES" "$SEED"
(cd "$HERE/go" && go build -o "$OUT/verify-go" .)
node "$HERE/verify.mjs" "$OUT/public.pem" "$OUT/cases.jsonl" "$OUT/ts.jsonl"
"$PYTHON" "$HERE/verify.py" "$OUT/public.pem" "$OUT/cases.jsonl" "$OUT/py.jsonl"
"$OUT/verify-go" "$OUT/public.pem" "$OUT/cases.jsonl" "$OUT/go.jsonl"
"$PYTHON" "$HERE/compare.py" "$OUT/cases.jsonl" "$OUT/ts.jsonl" "$OUT/py.jsonl" "$OUT/go.jsonl" \
  "$OUT/disagreements.jsonl"
