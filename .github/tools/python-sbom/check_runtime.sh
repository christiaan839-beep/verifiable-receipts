#!/usr/bin/env bash
# Checks that runtime.txt, the runtime dependencies the Python SBOM lists,
# is what packages/verifiable-receipts-py/pyproject.toml compiles to: it
# compiles pyproject.toml again, with the --exclude-newer date recorded in
# runtime.txt's header, and fails on any difference. Run from anywhere:
#
#   .github/tools/python-sbom/check_runtime.sh
#
# Needs uv (CI installs it by hash from .github/tools/python-ci). After a
# dependency change in pyproject.toml, regenerate runtime.txt with the
# command in its header, with a new --exclude-newer date (RELEASING.md).
set -euo pipefail

root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
cd "$root"
lock=.github/tools/python-sbom/runtime.txt
date=$(sed -n 's/^#  *uv pip compile .*--exclude-newer \([0-9-]*\) .*/\1/p' "$lock")
[[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo "error: no --exclude-newer date in $lock's header" >&2; exit 1; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/vr-runtime.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
uv pip compile --quiet --no-header --generate-hashes --python-version 3.12 \
  --python-platform x86_64-manylinux_2_28 --exclude-newer "$date" \
  -o "$tmp/runtime.txt" packages/verifiable-receipts-py/pyproject.toml
if ! diff -u <(grep -v '^#' "$lock") <(grep -v '^#' "$tmp/runtime.txt"); then
  echo "error: $lock is not what pyproject.toml compiles to (exclude-newer $date); regenerate it" >&2
  exit 1
fi
echo "ok  $lock is what pyproject.toml compiles to (exclude-newer $date)"
