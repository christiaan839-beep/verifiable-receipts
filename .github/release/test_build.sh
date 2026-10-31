#!/usr/bin/env bash
# Tests for build.sh's checks before it builds: the clean-tree check and
# the file-mode reset. Needs no toolchain: each case stops at the toolchain
# check (a Go that is not the release's), after the parts under test.
#
#   .github/release/test_build.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/vr-test-build.XXXXXX")
trap 'chmod -R u+rwX "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok   $*"; }

mode() { # the permission bits of a file, not following a symlink
  if stat -c %a "$1" >/dev/null 2>&1; then stat -c %a "$1"; else stat -f %Lp "$1"; fi
}

# A repository shaped like this one: build.sh and the files it reads, and a
# Go package with awkward file names, a symlink and an executable.
new_repo() {
  local r=$tmp/repo$1
  mkdir -p "$r/.github/release" "$r/.github/tools/python-sbom" "$r/packages/verifiable-receipts-go"
  cp "$here/build.sh" "$here/normalize_sbom.py" "$r/.github/release/"
  echo 0.0.0-not-a-go > "$r/.github/release/go-version"
  echo x > "$r/.github/tools/python-sbom/runtime.txt"
  cd "$r/packages/verifiable-receipts-go"
  echo a > 'with space.go'
  echo b > $'new\nline.go'
  echo c > '-leading-dash.go'
  echo d > 'quote"and\backslash.go'
  echo e > target.txt
  ln -s target.txt link.txt
  echo '#!/bin/sh' > run.sh
  chmod 0755 run.sh
  cd "$r"
  git init -q
  git -c user.name=t -c user.email=t@example.com add -A
  git -c user.name=t -c user.email=t@example.com commit -q -m init
  echo "$r"
}

run_build() { # repo; output in $tmp/log
  (cd "$1" && .github/release/build.sh go "$tmp/out") >"$tmp/log" 2>&1
}

# 1. A clone made under umask 077: build.sh restores the modes git records,
#    for every name, and leaves the symlink (and so its target) alone.
r=$(new_repo 1)
d=$r/packages/verifiable-receipts-go
chmod 0600 "$d/with space.go" "$d/"$'new\nline.go' "$d/-leading-dash.go" "$d/"'quote"and\backslash.go' "$d/target.txt"
chmod 0700 "$d/run.sh"
run_build "$r" || true
grep -q 'release toolchain' "$tmp/log" || { fail "build.sh did not reach the toolchain check:"; cat "$tmp/log" >&2; }
for f in 'with space.go' $'new\nline.go' '-leading-dash.go' 'quote"and\backslash.go'; do
  m=$(mode "$d/$f")
  if [ "$m" = 644 ]; then pass "mode reset: $(printf %q "$f") is 0644"; else fail "$(printf %q "$f") is 0$m, not 0644"; fi
done
if [ "$(mode "$d/run.sh")" = 755 ]; then pass "mode reset: run.sh is 0755"; else fail "run.sh is 0$(mode "$d/run.sh")"; fi
# chmod through the symlink would have made the target 0644; it must stay
# 0600, untouched, because the link is skipped.
if [ "$(mode "$d/target.txt")" = 644 ]; then pass "mode reset: target.txt is 0644 (its own entry)"; else fail "target.txt is 0$(mode "$d/target.txt")"; fi
if [ -L "$d/link.txt" ]; then pass "symlink kept"; else fail "link.txt is no longer a symlink"; fi

# 1b. A symlink to a file outside the package must not have its target's
#     mode changed.
r=$(new_repo 1b)
d=$r/packages/verifiable-receipts-go
echo secret > "$tmp/outside"
chmod 0600 "$tmp/outside"
rm "$d/link.txt"
ln -s "$tmp/outside" "$d/link.txt"
(cd "$r" && git -c user.name=t -c user.email=t@example.com commit -q -am relink)
run_build "$r" || true
if [ "$(mode "$tmp/outside")" = 600 ]; then pass "a symlink's target is not chmod-ed"; else fail "the symlink's target became 0$(mode "$tmp/outside")"; fi

# 2. Untracked or modified files in .github/release or .github/tools make
#    the build refuse, as they do in the package.
for f in .github/release/extra.py .github/tools/python-sbom/extra.txt packages/verifiable-receipts-go/extra.go; do
  r=$(new_repo "2-${f//\//-}")
  echo x > "$r/$f"
  if run_build "$r"; then fail "built with untracked $f"
  elif grep -q 'uncommitted or untracked' "$tmp/log"; then pass "refuses untracked $f"
  else fail "untracked $f: wrong error:"; cat "$tmp/log" >&2; fi
done
r=$(new_repo 2m)
echo changed >> "$r/.github/tools/python-sbom/runtime.txt"
if run_build "$r"; then fail "built with a modified runtime.txt"
elif grep -q 'uncommitted or untracked' "$tmp/log"; then pass "refuses a modified .github/tools file"
else fail "modified runtime.txt: wrong error"; cat "$tmp/log" >&2; fi

[ "$fails" -eq 0 ] || { echo "$fails failed" >&2; exit 1; }
echo "all passed"
