#!/usr/bin/env bash
# Verifies a directory of release files the way a user would:
#
#   .github/release/verify.sh [--expect SUMS] [--source-digest COMMIT] DIR [SOURCE_REF]
#
# For every release file (a .tgz, .tar.gz, .whl or .zip) in DIR:
#   - its SLSA provenance, from FILE.provenance.sigstore.json, was signed by
#     the reusable build workflow (SLSA Build L3) of this repository, on a
#     GitHub-hosted runner, and, given SOURCE_REF (refs/tags/js-v0.5.1, say),
#     from that ref and, given COMMIT, from that commit;
#   - its SBOM attestation, from FILE.sbom.sigstore.json, was signed the
#     same way, and its predicate is FILE.cdx.json;
# with --expect SUMS (sha256sum format: the digests build.yml output for
# the files it built), every release file and its SBOM is listed in SUMS,
# every file SUMS lists is in DIR, and each matches its digest, and DIR
# holds nothing else but the release files' bundles and SHA256SUMS; and, if DIR
# has a SHA256SUMS, every file in DIR matches it. Any failure exits non-zero
# (the publish jobs run this before they upload, and stop on a failure).
# Needs gh (logged in, or GH_TOKEN set) and jq.
set -euo pipefail

usage() { echo "usage: $0 [--expect SUMS] [--source-digest COMMIT] DIR [SOURCE_REF]" >&2; exit 2; }
expect='' source_digest=''
while [ $# -gt 0 ]; do
  case "$1" in
    --expect) [ $# -ge 2 ] || usage; expect=$2; shift 2 ;;
    --source-digest) [ $# -ge 2 ] || usage; source_digest=$2; shift 2 ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done
[ $# -ge 1 ] && [ $# -le 2 ] || usage
dir=$1
repo=${VR_REPO:-christiaan839-beep/verifiable-receipts}
signer="$repo/.github/workflows/build.yml"
args=(--repo "$repo" --signer-workflow "$signer" --deny-self-hosted-runners)
[ -n "${2:-}" ] && args+=(--source-ref "$2")
if [ -n "$source_digest" ]; then
  [[ "$source_digest" =~ ^[0-9a-f]{40}$ ]] || { echo "error: --source-digest must be a 40-hex commit SHA" >&2; exit 2; }
  args+=(--source-digest "$source_digest")
fi
sha256() { if command -v sha256sum >/dev/null; then sha256sum -- "$1"; else shasum -a 256 -- "$1"; fi | awk '{print $1}'; }

if [ -n "$expect" ]; then
  [ -f "$expect" ] || { echo "error: no digest list $expect" >&2; exit 1; }
  expect=$(cd "$(dirname "$expect")" && pwd)/$(basename "$expect")
fi
cd "$dir"
shopt -s nullglob
files=(*.tgz *.tar.gz *.whl *.zip)
[ ${#files[@]} -ge 1 ] || { echo "error: no release files in $dir" >&2; exit 1; }

# The digests the build job output, checked before anything else.
# (Plain arrays, not an associative one: macOS ships bash 3.2.)
if [ -n "$expect" ]; then
  names=() digests=()
  while IFS= read -r line || [ -n "$line" ]; do
    [[ "$line" =~ ^([0-9a-f]{64})\ [\ *]([A-Za-z0-9][A-Za-z0-9._+-]*)$ ]] ||
      { echo "error: $expect: not a digest line: $line" >&2; exit 1; }
    for n in ${names[@]+"${names[@]}"}; do
      [ "$n" != "${BASH_REMATCH[2]}" ] || { echo "error: $expect lists $n twice" >&2; exit 1; }
    done
    names+=("${BASH_REMATCH[2]}")
    digests+=("${BASH_REMATCH[1]}")
  done <"$expect"
  [ ${#names[@]} -ge 1 ] || { echo "error: $expect lists no files" >&2; exit 1; }
  for i in "${!names[@]}"; do
    g=${names[$i]}
    [ -f "$g" ] || { echo "error: the build made $g, which is not in $dir" >&2; exit 1; }
    have=$(sha256 "$g")
    if [ "$have" != "${digests[$i]}" ]; then
      echo "error: $g is $have, the build made ${digests[$i]}" >&2
      exit 1
    fi
    echo "ok  $g: the digest build.yml output"
  done
  # Nothing else may be in DIR (the release job uploads all of it): only
  # the listed files, each release file's two bundles, and SHA256SUMS.
  shopt -s dotglob
  for g in *; do
    ok=
    [ "$g" = SHA256SUMS ] && ok=1
    for n in "${names[@]}"; do [ "$g" != "$n" ] || ok=1; done
    for f in "${files[@]}"; do
      [ "$g" != "$f.provenance.sigstore.json" ] && [ "$g" != "$f.sbom.sigstore.json" ] || ok=1
    done
    [ -n "$ok" ] && [ -f "$g" ] && [ ! -L "$g" ] ||
      { echo "error: $g is not a file the build made, its bundle or SHA256SUMS" >&2; exit 1; }
  done
  shopt -u dotglob
fi

for f in "${files[@]}"; do
  gh attestation verify "$f" --bundle "$f.provenance.sigstore.json" "${args[@]}" >/dev/null
  echo "ok  $f: provenance signed by $signer"
  predicate=$(gh attestation verify "$f" --bundle "$f.sbom.sigstore.json" "${args[@]}" \
    --predicate-type https://cyclonedx.org/bom --format json \
    --jq '.[0].verificationResult.statement.predicate')
  if [ "$(jq -S . <<<"$predicate")" != "$(jq -S . "$f.cdx.json")" ]; then
    echo "error: the SBOM attested for $f is not $f.cdx.json" >&2
    exit 1
  fi
  echo "ok  $f: SBOM $f.cdx.json attested by $signer"
done
if [ -f SHA256SUMS ]; then
  if command -v sha256sum >/dev/null; then sha256sum --check --strict SHA256SUMS; else shasum -a 256 --check SHA256SUMS; fi
fi
