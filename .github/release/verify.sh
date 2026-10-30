#!/usr/bin/env bash
# Verifies a directory of release files the way a user would:
#
#   .github/release/verify.sh DIR [SOURCE_REF]
#
# For every release file (a .tgz, .tar.gz, .whl or .zip) in DIR:
#   - its SLSA provenance, from FILE.provenance.sigstore.json, was signed by
#     the reusable build workflow (SLSA Build L3) of this repository, on a
#     GitHub-hosted runner, and, given SOURCE_REF (refs/tags/js-v0.5.1, say),
#     from that ref;
#   - its SBOM attestation, from FILE.sbom.sigstore.json, was signed the
#     same way, and its predicate is FILE.cdx.json;
# and, if DIR has a SHA256SUMS, every file in DIR matches it.
# Needs gh (logged in, or GH_TOKEN set) and jq.
set -euo pipefail

[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: $0 DIR [SOURCE_REF]" >&2; exit 2; }
dir=$1
repo=${VR_REPO:-christiaan839-beep/verifiable-receipts}
signer="$repo/.github/workflows/build.yml"
args=(--repo "$repo" --signer-workflow "$signer" --deny-self-hosted-runners)
[ -n "${2:-}" ] && args+=(--source-ref "$2")

cd "$dir"
shopt -s nullglob
files=(*.tgz *.tar.gz *.whl *.zip)
[ ${#files[@]} -ge 1 ] || { echo "error: no release files in $dir" >&2; exit 1; }
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
