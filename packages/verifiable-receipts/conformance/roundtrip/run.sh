#!/usr/bin/env bash
# Cross-language round trip for v2 receipts.
#
# Makes a throwaway Ed25519 key, then signs:
#   - body.json with the Python signer (sign_v2_receipt),
#   - body.json with the verifiable-receipts-sign CLI,
#   - a Guardian attestation with the TypeScript runGuardian,
# and verifies each with the Python, Go and node verifiers. It checks
# that the two signers wrote the same canonical, contentHash and
# signature for body.json, then edits one field of each signed file and
# checks that all three verifiers reject the edit. The key lives in a
# temporary directory that is removed on exit.
#
# Needs node 18+ with packages/verifiable-receipts built (`npm install`
# there), python 3.10+ with `cryptography`, and go 1.22+. The Python
# package is read from the working tree (PYTHONPATH), not from site-packages.
#
# Usage: bash packages/verifiable-receipts/conformance/roundtrip/run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="$(cd "$HERE/../.." && pwd)"
PY_PKG="$(cd "$PKG/../verifiable-receipts-py" && pwd)"
PYTHON="${PYTHON:-python3}"
export PYTHONPATH="$PY_PKG${PYTHONPATH:+:$PYTHONPATH}"

if [ ! -f "$PKG/dist/index.js" ]; then
  echo "error: build the TypeScript package first (npm install in $PKG)" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PRIV="$WORK/ed25519-private.pem"
PUB="$WORK/ed25519-public.pem"

node "$HERE/keygen.mjs" "$WORK"
(cd "$HERE/go" && go build -o "$WORK/verify-go" .)

"$PYTHON" "$HERE/sign.py" "$PRIV" "$HERE/body.json" "$WORK/python-signer.json"
node "$PKG/bin/sign.mjs" --input "$HERE/body.json" --key "$PRIV" \
  --out "$WORK/cli-signer.json" 2>/dev/null
node "$HERE/guardian.mjs" "$PRIV" "$WORK/guardian.json"

# Same body, same key: the two signers must agree byte for byte.
node --input-type=module - "$WORK/python-signer.json" "$WORK/cli-signer.json" <<'EOF'
import { readFileSync } from "node:fs";
const [a, b] = process.argv.slice(2).map((p) => JSON.parse(readFileSync(p, "utf8")));
for (const field of ["canonical", "contentHash", "signature"]) {
  if (typeof a[field] !== "string" || a[field] === "" || a[field] !== b[field]) {
    console.error(`FAIL: the Python signer and the CLI differ on ${field}`);
    process.exit(1);
  }
}
console.log("Python signer and CLI: same canonical, contentHash and signature");
EOF

# edit <in> <out> <field> <value>: copy a signed file with one field set.
edit() {
  node --input-type=module - "$@" <<'EOF'
import { readFileSync, writeFileSync } from "node:fs";
const [src, dst, field, value] = process.argv.slice(2);
const receipt = JSON.parse(readFileSync(src, "utf8"));
receipt[field] = value;
writeFileSync(dst, JSON.stringify(receipt, null, 2) + "\n");
EOF
}
edit "$WORK/python-signer.json" "$WORK/python-signer-overall-edited.json" overall fail
edit "$WORK/cli-signer.json" "$WORK/cli-signer-unsigned-field.json" approvedBy someone
edit "$WORK/guardian.json" "$WORK/guardian-overall-edited.json" overall pass

failures=0

# check <expected ok|rejected> <receipt|guardian> <file>
check() {
  local expected="$1" kind="$2" file="$3" verifier out code
  for verifier in python go node; do
    case "$verifier" in
      python) out="$("$PYTHON" "$HERE/verify.py" "$PUB" "$kind" "$file")" && code=0 || code=$? ;;
      go) out="$("$WORK/verify-go" "$PUB" "$kind" "$file")" && code=0 || code=$? ;;
      node) out="$(node "$HERE/verify.mjs" "$PUB" "$kind" "$file")" && code=0 || code=$? ;;
    esac
    local got=other
    [ "$code" -eq 0 ] && got=ok
    [ "$code" -eq 1 ] && got=rejected
    local mark=pass
    if [ "$got" != "$expected" ]; then
      mark=FAIL
      failures=$((failures + 1))
    fi
    printf '%-4s %-34s %-8s %-6s %s\n' "$mark" "$(basename "$file")" "$kind" "$verifier" "$out"
  done
}

check ok receipt "$WORK/python-signer.json"
check ok receipt "$WORK/cli-signer.json"
check ok guardian "$WORK/guardian.json"
check rejected receipt "$WORK/python-signer-overall-edited.json"
check rejected receipt "$WORK/cli-signer-unsigned-field.json"
check rejected guardian "$WORK/guardian-overall-edited.json"

if [ "$failures" -ne 0 ]; then
  echo "round trip: $failures check(s) failed" >&2
  exit 1
fi
echo "round trip: 18 checks passed (3 signers x 3 verifiers, signed and edited)"
