#!/usr/bin/env bash
# Tests for verify.sh, the check every publish job runs before it uploads.
# Offline: a stand-in for `gh attestation verify` reads a fake bundle (JSON:
# the attested digest, the signer workflow, the source ref and commit,
# whether a self-hosted runner built it, and the SBOM predicate) and checks
# each flag verify.sh passes against it, the way the real check does
# against a signed bundle. The real gh runs in the dry run's publish-guard
# job (release-dry-run.yml) against real attestations.
#
# Every failure case names the error it expects, so a check that is
# removed from verify.sh makes its case fail (not just any error).
#
#   .github/release/test_verify.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
verify=${VR_TEST_VERIFY:-$here/verify.sh}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/vr-test-verify.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok   $*"; }
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'; }

REPO=christiaan839-beep/verifiable-receipts
SIGNER=$REPO/.github/workflows/build.yml
REF=refs/tags/py-v1.0.0
COMMIT=0123456789abcdef0123456789abcdef01234567

mkdir "$tmp/bin"
cat >"$tmp/bin/gh" <<'GH'
#!/usr/bin/env bash
# gh attestation verify FILE --bundle BUNDLE [flags]
set -euo pipefail
echo "$*" >>"$VR_TEST_GH_LOG"
[ "$1 $2" = "attestation verify" ] || exit 99
file=$3; shift 3
bundle= signer= ref= digest= deny=
while [ $# -gt 0 ]; do
  case "$1" in
    --bundle) bundle=$2; shift 2 ;;
    --signer-workflow) signer=$2; shift 2 ;;
    --source-ref) ref=$2; shift 2 ;;
    --source-digest) digest=$2; shift 2 ;;
    --deny-self-hosted-runners) deny=1; shift ;;
    --repo | --predicate-type | --format | --jq) shift 2 ;;
    *) echo "stub: unknown flag $1" >&2; exit 98 ;;
  esac
done
b() { jq -r "$1" "$bundle"; }
have=$(if command -v sha256sum >/dev/null; then sha256sum "$file"; else shasum -a 256 "$file"; fi | awk '{print $1}')
[ "$have" = "$(b .digest)" ] || { echo "stub: no attestation for the digest of $file" >&2; exit 1; }
[ -n "$signer" ] && [ "$signer" != "$(b .signer)" ] && { echo "stub: signer is $(b .signer), not $signer" >&2; exit 1; }
[ -n "$ref" ] && [ "$ref" != "$(b .ref)" ] && { echo "stub: source ref is $(b .ref), not $ref" >&2; exit 1; }
[ -n "$digest" ] && [ "$digest" != "$(b .commit)" ] && { echo "stub: source digest is $(b .commit), not $digest" >&2; exit 1; }
[ -n "$deny" ] && [ "$(b .self_hosted)" = true ] && { echo "stub: built on a self-hosted runner" >&2; exit 1; }
case "$bundle" in *.sbom.sigstore.json) jq -c .predicate "$bundle" ;; esac
GH
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" VR_TEST_GH_LOG="$tmp/gh.log"

# A directory of release files as the attest job leaves it; $tmp/NAME.sums
# is the build job's digest list.
make_dir() { # name [self_hosted]
  local d=$tmp/$1 f
  mkdir -p "$d"
  printf 'wheel bytes' >"$d/pkg-1.0.0-py3-none-any.whl"
  printf 'sdist bytes' >"$d/pkg-1.0.0.tar.gz"
  for f in "$d"/*.whl "$d"/*.tar.gz; do
    echo '{"bomFormat":"CycloneDX","metadata":{"component":{"name":"pkg"}}}' >"$f.cdx.json"
    for kind in provenance sbom; do
      jq -n --arg d "$(sha "$f")" --arg s "$SIGNER" --arg r "$REF" --arg c "$COMMIT" \
        --argjson h "${2:-false}" --slurpfile p "$f.cdx.json" \
        '{digest: $d, signer: $s, ref: $r, commit: $c, self_hosted: $h, predicate: $p[0]}' >"$f.$kind.sigstore.json"
    done
  done
  (cd "$d" && for f in *.whl *.tar.gz *.cdx.json; do printf '%s  %s\n' "$(sha "$f")" "$f"; done) >"$tmp/$1.sums"
  echo "$d"
}

expect_ok() { # name, verify.sh args...
  local name=$1; shift
  if "$verify" "$@" >"$tmp/log" 2>&1; then pass "$name"; else fail "$name:"; cat "$tmp/log" >&2; fi
}
expect_fail() { # name, error (an ERE the output must match), verify.sh args...
  local name=$1 error=$2; shift 2
  if "$verify" "$@" >"$tmp/log" 2>&1; then
    fail "$name: verify.sh accepted it"; cat "$tmp/log" >&2
  elif grep -Eq -- "$error" "$tmp/log"; then
    pass "$name"
  else
    fail "$name: failed, but not with /$error/:"; cat "$tmp/log" >&2
  fi
}

d=$(make_dir good)
expect_ok "genuine files and digests pass" --expect "$tmp/good.sums" --source-digest $COMMIT "$d" $REF
expect_ok "genuine files pass without --expect" "$d"
expect_ok "a SHA256SUMS that matches passes" "$d"
(cd "$d" && for f in *; do printf '%s  %s\n' "$(sha "$f")" "$f"; done >../SUMS.tmp && mv ../SUMS.tmp SHA256SUMS)
expect_ok "genuine files with their SHA256SUMS pass" --expect "$tmp/good.sums" "$d" $REF

# The build's digests (--expect).
d=$(make_dir tampered)
printf 'x' >>"$d/pkg-1.0.0.tar.gz"
expect_fail "a tampered file fails against the build's digests" \
  'error: pkg-1\.0\.0\.tar\.gz is [0-9a-f]{64}, the build made' --expect "$tmp/tampered.sums" "$d"
expect_fail "a tampered file fails the attestation check" 'stub: no attestation for the digest of pkg-1\.0\.0\.tar\.gz' "$d"

d=$(make_dir wrongdigest)
awk 'NR == 1 { c = substr($1, 1, 1); $0 = (c == "0" ? "1" : "0") substr($1, 2) "  " $2 } { print }' \
  "$tmp/wrongdigest.sums" >"$tmp/wrongdigest.sums.2"
expect_fail "a digest that differs from the build's fails" 'the build made [0-9a-f]{64}' --expect "$tmp/wrongdigest.sums.2" "$d"

d=$(make_dir missing)
grep -v '\.whl$' "$tmp/missing.sums" >"$tmp/missing.sums.2"
expect_fail "a release file the build did not list fails" \
  'error: pkg-1\.0\.0-py3-none-any\.whl is not a file the build made' --expect "$tmp/missing.sums.2" "$d"

d=$(make_dir extra)
printf '%s  %s\n' "$(printf x | if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi | awk '{print $1}')" other-1.0.0.zip >>"$tmp/extra.sums"
expect_fail "a listed file that is not there fails" 'error: the build made other-1\.0\.0\.zip, which is not in' --expect "$tmp/extra.sums" "$d"

d=$(make_dir traversal)
printf '%s  %s\n' "$(sha "$d/pkg-1.0.0.tar.gz")" ../traversal/pkg-1.0.0.tar.gz >>"$tmp/traversal.sums"
expect_fail "a path in the digest list fails" 'not a digest line: [0-9a-f]{64}  \.\./traversal' --expect "$tmp/traversal.sums" "$d"

d=$(make_dir duplicate)
line=$(head -n 1 "$tmp/duplicate.sums")
echo "$line" >>"$tmp/duplicate.sums"
expect_fail "a file listed twice fails" 'lists [^ ]+ twice' --expect "$tmp/duplicate.sums" "$d"

d=$(make_dir empty)
: >"$tmp/empty.sums"
expect_fail "an empty digest list fails" 'lists no files' --expect "$tmp/empty.sums" "$d"
expect_fail "a missing digest list fails" 'error: no digest list' --expect "$tmp/no-such-file" "$d"

d=$(make_dir sbomexpect)
echo '{"bomFormat":"CycloneDX","x":1}' >"$d/pkg-1.0.0.tar.gz.cdx.json"
expect_fail "an SBOM that differs from the build's fails" \
  'error: pkg-1\.0\.0\.tar\.gz\.cdx\.json is [0-9a-f]{64}, the build made' --expect "$tmp/sbomexpect.sums" "$d"

# Only checked files may be in the directory with --expect (the release
# job uploads the directory).
for stray in notes.txt pkg-1.0.0.tar.gz.extra.sigstore.json .hidden; do
  d=$(make_dir "stray-$stray")
  echo x >"$d/$stray"
  expect_fail "a stray $stray in the directory fails" \
    "error: ${stray//./\\.} is not a file the build made, its bundle or SHA256SUMS" --expect "$tmp/stray-$stray.sums" "$d"
done
d=$(make_dir straydir)
mkdir "$d/sub"
expect_fail "a directory in the directory fails" 'error: sub is not a file the build made' --expect "$tmp/straydir.sums" "$d"

# The SBOM attestation (no --expect, so only the attestation can catch it).
d=$(make_dir sbom)
echo '{"bomFormat":"CycloneDX","metadata":{"component":{"name":"other"}}}' >"$d/pkg-1.0.0.tar.gz.cdx.json"
expect_fail "an SBOM that is not the attested one fails" 'error: the SBOM attested for pkg-1\.0\.0\.tar\.gz is not pkg-1\.0\.0\.tar\.gz\.cdx\.json' "$d"

# SHA256SUMS in the directory.
d=$(make_dir sums)
(cd "$d" && for f in *; do printf '%s  %s\n' "$(sha "$f")" "$f"; done >../SUMS.tmp && mv ../SUMS.tmp SHA256SUMS)
awk 'NR == 1 { c = substr($1, 1, 1); $0 = (c == "0" ? "1" : "0") substr($1, 2) "  " $2 } { print }' "$d/SHA256SUMS" >"$d/S" && mv "$d/S" "$d/SHA256SUMS"
expect_fail "a SHA256SUMS that does not match fails" 'FAILED' "$d"

# The pins passed to gh.
d=$(make_dir selfhosted true)
expect_fail "a file built on a self-hosted runner fails" 'stub: built on a self-hosted runner' "$d"
d=$(make_dir pinned)
expect_fail "another source ref fails" 'stub: source ref is refs/tags/py-v1\.0\.0, not refs/tags/py-v9\.9\.9' "$d" refs/tags/py-v9.9.9
expect_fail "another commit fails" 'stub: source digest is 0123' --source-digest ffffffffffffffffffffffffffffffffffffffff "$d"
VR_REPO=someone/else expect_fail "another signer workflow fails" 'stub: signer is christiaan839-beep' "$d"
: >"$tmp/gh.log"
expect_ok "the pins reach gh" --source-digest $COMMIT "$d" $REF
for pin in "--signer-workflow $SIGNER" "--source-ref $REF" "--source-digest $COMMIT" "--deny-self-hosted-runners" "--repo $REPO"; do
  if [ "$(grep -c -- "$pin" "$tmp/gh.log")" -eq 4 ]; then pass "  $pin, on all 4 calls"; else fail "$pin is not on every gh call:"; cat "$tmp/gh.log" >&2; fi
done
expect_fail "a source digest that is not a commit SHA fails" 'must be a 40-hex commit SHA' --source-digest main "$d"
expect_fail "an unknown option fails" '^usage:' --nope "$d"

[ "$fails" -eq 0 ] || { echo "$fails failed" >&2; exit 1; }
echo "all passed"
