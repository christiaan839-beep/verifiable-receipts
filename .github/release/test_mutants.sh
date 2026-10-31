#!/usr/bin/env bash
# Mutation check for test_verify.sh and test_build.sh: removes one check
# from verify.sh or build.sh at a time and runs that script's tests against
# the copy, which must fail. A mutant that survives is a check the tests do
# not cover.
#
#   .github/release/test_mutants.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/vr-mutants.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# script<TAB>name<TAB>the exact text<TAB>what replaces it
cat >"$tmp/mutants" <<'M'
verify	no SBOM comparison	  if [ "$(jq -S . <<<"$predicate")" != "$(jq -S . "$f.cdx.json")" ]; then	  if false; then
verify	no duplicate-name check	      [ "$n" != "${BASH_REMATCH[2]}" ] || { echo "error: $expect lists $n twice" >&2; exit 1; }	      :
verify	no SHA256SUMS check	if [ -f SHA256SUMS ]; then	if false; then
verify	no --deny-self-hosted-runners	args=(--repo "$repo" --signer-workflow "$signer" --deny-self-hosted-runners)	args=(--repo "$repo" --signer-workflow "$signer")
verify	no --signer-workflow	args=(--repo "$repo" --signer-workflow "$signer" --deny-self-hosted-runners)	args=(--repo "$repo" --deny-self-hosted-runners)
verify	no --source-ref	[ -n "${2:-}" ] && args+=(--source-ref "$2")	:
verify	no --source-digest	  args+=(--source-digest "$source_digest")	  :
verify	no source-digest format check	  [[ "$source_digest" =~ ^[0-9a-f]{40}$ ]] || { echo "error: --source-digest must be a 40-hex commit SHA" >&2; exit 2; }	  :
verify	no digest comparison	    if [ "$have" != "${digests[$i]}" ]; then	    if false; then
verify	no listed-file presence check	    [ -f "$g" ] || { echo "error: the build made $g, which is not in $dir" >&2; exit 1; }	    :
verify	no stray-file check	    [ -n "$ok" ] && [ -f "$g" ] && [ ! -L "$g" ] ||	    true ||
verify	no name pattern	    [[ "$line" =~ ^([0-9a-f]{64})\ [\ *]([A-Za-z0-9][A-Za-z0-9._+-]*)$ ]] ||	    [[ "$line" =~ ^([0-9a-f]{64})\ [\ *](.*)$ ]] ||
verify	no empty-list check	  [ ${#names[@]} -ge 1 ] || { echo "error: $expect lists no files" >&2; exit 1; }	  :
verify	no provenance check	  gh attestation verify "$f" --bundle "$f.provenance.sigstore.json" "${args[@]}" >/dev/null	  :
build	no manifest restore	  if [ ${#restore[@]} -gt 0 ]; then git -C "$root" checkout --quiet -- "${restore[@]}"; fi	  :
build	no EXIT trap	trap cleanup EXIT	trap 'rm -rf "$work"' EXIT
build	no lockfile marking	      restore=("$dir/package.json" "$dir/package-lock.json")	      restore=("$dir/package.json")
build	lockfile root entry not marked	        data["packages"][""]["version"] = data["version"]	        pass
build	no py marking	text, n = re.subn(r'(?m)^(version = "[^"]+)"', lambda m: m.group(1) + suffix + '"', text, count=1)	text, n = re.subn(r'(?m)^(version = "[^"]+)"', lambda m: m.group(1) + '"', text, count=1)
build	no VR_DRY_RUN validation	case "$dry_run" in "" | 0) dry_run= ;; 1) ;; *) echo "error: VR_DRY_RUN must be 1 or unset" >&2; exit 2 ;; esac	case "$dry_run" in "" | 0) dry_run= ;; *) ;; esac
build	no dry-run/go-version refusal	if [ -n "$dry_run" ] && [ -n "${VR_GO_VERSION:-}" ]; then	if false; then
build	no clean-tree check of .github/release and .github/tools	checked=("$dir" .github/release .github/tools)	checked=("$dir")
build	symlinks chmod-ed	    120000 | 160000) ;;	    120000 | 160000) chmod -- 0644 "$file" ;;
build	mode reset without -z	done < <(git ls-files -s -z -- "$dir")	done < <(git ls-files -s -- "$dir" | tr '\\n' '\\0')
M

cp "$here/verify.sh" "$tmp/verify.sh"
cp "$here/build.sh" "$tmp/build.sh"
survived=0 n=0
while IFS=$'\t' read -r script name old new; do
  n=$((n + 1))
  python3 -I - "$here/$script.sh" "$tmp/$script.sh" "$old" "$new" <<'PY'
import sys
src, dst, old, new = sys.argv[1:]
text = open(src).read()
if text.count(old) != 1:
    raise SystemExit(f"mutant text not found exactly once: {old}")
open(dst, "w").write(text.replace(old, new))
PY
  chmod +x "$tmp/$script.sh"
  if VR_TEST_VERIFY=$tmp/verify.sh VR_TEST_BUILD=$tmp/build.sh "$here/test_$script.sh" >"$tmp/log" 2>&1; then
    echo "SURVIVED: $script.sh: $name"; survived=$((survived + 1))
  else
    echo "killed    $script.sh: $name ($(grep -c '^FAIL' "$tmp/log") failing cases, first: $(grep -m1 '^FAIL' "$tmp/log" | cut -c7-90))"
  fi
done <"$tmp/mutants"
[ "$survived" -eq 0 ] || { echo "$survived of $n mutants survived" >&2; exit 1; }
echo "all $n mutants killed"
