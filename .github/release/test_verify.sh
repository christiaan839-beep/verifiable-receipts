#!/usr/bin/env bash
# Tests for verify.sh, the check every publish job runs before it uploads.
# Offline: a stand-in for `gh attestation verify` accepts a file only if its
# SHA-256 is the one its bundle names, as the real check accepts only a file
# whose digest an attestation signs. The real gh runs in the dry run's
# publish-guard job (release-dry-run.yml) against real attestations.
#
#   .github/release/test_verify.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/vr-test-verify.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok   $*"; }
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'; }

mkdir "$tmp/bin"
cat >"$tmp/bin/gh" <<'GH'
#!/usr/bin/env bash
# gh attestation verify FILE --bundle BUNDLE ...: the bundle holds the
# attested digest; an SBOM bundle check prints the SBOM as the predicate.
echo "$*" >>"$VR_TEST_GH_LOG"
[ "$1 $2" = "attestation verify" ] || exit 99
file=$3 bundle=
shift 3
while [ $# -gt 0 ]; do case "$1" in --bundle) bundle=$2; shift 2 ;; *) shift ;; esac; done
have=$(if command -v sha256sum >/dev/null; then sha256sum "$file"; else shasum -a 256 "$file"; fi | awk '{print $1}')
[ "$have" = "$(cat "$bundle")" ] || { echo "no attestation for $file" >&2; exit 1; }
case "$bundle" in *.sbom.sigstore.json) cat "$file.cdx.json" ;; esac
GH
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" VR_TEST_GH_LOG="$tmp/gh.log"

# A directory of release files as the attest job leaves it.
make_dir() {
  local d=$tmp/$1
  mkdir -p "$d"
  printf 'wheel bytes' >"$d/pkg-1.0.0-py3-none-any.whl"
  printf 'sdist bytes' >"$d/pkg-1.0.0.tar.gz"
  for f in "$d"/*.whl "$d"/*.tar.gz; do
    echo '{"bomFormat":"CycloneDX"}' >"$f.cdx.json"
    sha "$f" >"$f.provenance.sigstore.json"
    sha "$f" >"$f.sbom.sigstore.json"
  done
  (cd "$d" && for f in *.whl *.tar.gz *.cdx.json; do printf '%s  %s\n' "$(sha "$f")" "$f"; done) >"$tmp/$1.sums"
  echo "$d"
}

expect_ok() { # name, args...
  local name=$1; shift
  if "$here/verify.sh" "$@" >"$tmp/log" 2>&1; then pass "$name"; else fail "$name:"; cat "$tmp/log" >&2; fi
}
expect_fail() { # name, args...
  local name=$1; shift
  if "$here/verify.sh" "$@" >"$tmp/log" 2>&1; then fail "$name: verify.sh accepted it"; cat "$tmp/log" >&2; else pass "$name"; fi
}

d=$(make_dir good)
expect_ok "genuine files and digests pass" --expect "$tmp/good.sums" "$d" refs/tags/py-v1.0.0
expect_ok "genuine files pass without --expect" "$d"

d=$(make_dir tampered)
printf 'x' >>"$d/pkg-1.0.0.tar.gz"
expect_fail "a tampered file fails against the build's digests" --expect "$tmp/tampered.sums" "$d"
if grep -q 'pkg-1.0.0.tar.gz' "$tmp/log"; then pass "  and the error names the file"; else fail "the error does not name the file"; fi
expect_fail "a tampered file fails the attestation check" "$d"

d=$(make_dir wrongdigest)
sed -i.bak '1s/^./0/; 1s/^00/11/' "$tmp/wrongdigest.sums"
expect_fail "a digest that differs from the build's fails" --expect "$tmp/wrongdigest.sums" "$d"

d=$(make_dir missing)
grep -v '\.whl$' "$tmp/missing.sums" >"$tmp/missing.sums.2"
expect_fail "a release file the build did not list fails" --expect "$tmp/missing.sums.2" "$d"

d=$(make_dir extra)
printf '%s  %s\n' "$(printf x | if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi | awk '{print $1}')" other-1.0.0.zip >>"$tmp/extra.sums"
expect_fail "a listed file that is not there fails" --expect "$tmp/extra.sums" "$d"

d=$(make_dir traversal)
printf '%s  %s\n' "$(sha "$d/pkg-1.0.0.tar.gz")" ../traversal/pkg-1.0.0.tar.gz >>"$tmp/traversal.sums"
expect_fail "a path in the digest list fails" --expect "$tmp/traversal.sums" "$d"

d=$(make_dir empty)
: >"$tmp/empty.sums"
expect_fail "an empty digest list fails" --expect "$tmp/empty.sums" "$d"
expect_fail "a missing digest list fails" --expect "$tmp/no-such-file" "$d"

d=$(make_dir sbom)
echo '{"bomFormat":"CycloneDX","x":1}' >"$d/pkg-1.0.0.tar.gz.cdx.json"
expect_fail "an SBOM that differs from the build's fails" --expect "$tmp/sbom.sums" "$d"

d=$(make_dir pinned)
: >"$tmp/gh.log"
expect_ok "a source digest is passed to gh" --source-digest 0123456789abcdef0123456789abcdef01234567 "$d" refs/tags/py-v1.0.0
if grep -q -- '--source-digest 0123456789abcdef0123456789abcdef01234567' "$tmp/gh.log" &&
  grep -q -- '--source-ref refs/tags/py-v1.0.0' "$tmp/gh.log" &&
  grep -q -- '--signer-workflow christiaan839-beep/verifiable-receipts/.github/workflows/build.yml' "$tmp/gh.log"; then
  pass "  with the signer workflow and the source ref"
else fail "gh was not given the pins:"; cat "$tmp/gh.log" >&2; fi
expect_fail "a source digest that is not a commit SHA fails" --source-digest main "$d"

[ "$fails" -eq 0 ] || { echo "$fails failed" >&2; exit 1; }
echo "all passed"
