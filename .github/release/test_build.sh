#!/usr/bin/env bash
# Tests for what build.sh does before it builds: the clean-tree check, the
# file-mode reset, and a dry run's version marking (VR_DRY_RUN=1) and the
# restore of the manifest afterwards, on an error and on a signal. Needs no
# toolchain: each case stops at the toolchain check, after the parts under
# test. Stand-ins for node and python3's version query record the manifests
# at that point (and can hang there, to be sent a signal).
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
  mkdir -p "$r/.github/release" "$r/.github/tools/python-sbom" "$r/packages/verifiable-receipts-go" \
    "$r/packages/verifiable-receipts" "$r/packages/verifiable-receipts-py"
  cp "${VR_TEST_BUILD:-$here/build.sh}" "$r/.github/release/build.sh"
  cp "$here/normalize_sbom.py" "$r/.github/release/"
  echo 0.0.0-not-a-go > "$r/.github/release/go-version"
  echo 99.0.0 > "$r/.github/release/node-version"
  echo 3.99.0 > "$r/.github/release/python-version"
  printf '{\n  "name": "@sovereignos/verifiable-receipts",\n  "version": "0.5.1"\n}\n' \
    > "$r/packages/verifiable-receipts/package.json"
  printf '{\n  "name": "@sovereignos/verifiable-receipts",\n  "version": "0.5.1",\n  "lockfileVersion": 3,\n  "packages": {\n    "": {\n      "version": "0.5.1"\n    },\n    "node_modules/x": {\n      "version": "1.0.0"\n    }\n  }\n}\n' \
    > "$r/packages/verifiable-receipts/package-lock.json"
  printf '[project]\nname = "sovereign-matrix-verifiable-receipts"\nversion = "0.3.0"\ndependencies = ["cryptography>=42.0.0"]\n\n[tool.x]\nversion = "9.9.9"\n' \
    > "$r/packages/verifiable-receipts-py/pyproject.toml"
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

# 3. Dry runs. Stand-ins: `node --version` and python3's version query
#    copy the package's manifests to $VR_TEST_CAPTURE and report a version
#    that is not the release's, so build.sh stops there; with VR_TEST_HANG
#    they hang until killed, after writing $VR_TEST_CAPTURE/ready.
real_python=$(command -v python3)
mkdir -p "$tmp/bin"
cat >"$tmp/bin/capture" <<'SH'
#!/usr/bin/env bash
mkdir -p "$VR_TEST_CAPTURE"
cp packages/verifiable-receipts/package.json packages/verifiable-receipts/package-lock.json \
  packages/verifiable-receipts-py/pyproject.toml "$VR_TEST_CAPTURE/" 2>/dev/null || true
if [ -n "${VR_TEST_HANG:-}" ]; then
  echo $$ >"$VR_TEST_CAPTURE/ready"
  exec sleep 60
fi
echo 0.0.0
SH
# shellcheck disable=SC2016 # the stand-ins' own $1 and $*, not this script's
{
  printf '#!/usr/bin/env bash\n[ "${1:-}" = --version ] && exec %q\nexit 97\n' "$tmp/bin/capture" >"$tmp/bin/node"
  printf '#!/usr/bin/env bash\ncase "$*" in *platform*) exec %q ;; esac\nexec %q "$@"\n' "$tmp/bin/capture" "$real_python" >"$tmp/bin/python3"
}
chmod +x "$tmp/bin/capture" "$tmp/bin/node" "$tmp/bin/python3"

dry_build() { # repo, package; captures into $tmp/cap
  rm -rf "$tmp/cap"
  (cd "$1" && PATH="$tmp/bin:$PATH" VR_TEST_CAPTURE="$tmp/cap" VR_DRY_RUN=1 \
    .github/release/build.sh "$2" "$tmp/out") >"$tmp/log" 2>&1
}
clean() { [ -z "$(git -C "$1" status --porcelain --untracked-files=all)" ]; }
json() { "$real_python" -I -c 'import json, sys; d = json.load(open(sys.argv[1])); print(eval(sys.argv[2], {"d": d}))' "$@"; }

r=$(new_repo 3)
c=$(git -C "$r" rev-parse HEAD)
mark="dryrun.g${c:0:12}"
if dry_build "$r" js; then fail "js dry run: build.sh went past the toolchain check"; fi
if [ ! -f "$tmp/cap/package.json" ]; then fail "js dry run: the toolchain check never ran:"; cat "$tmp/log" >&2
else
  v=$(json "$tmp/cap/package.json" 'd["version"]')
  if [ "$v" = "0.5.1-$mark" ]; then pass "js dry run: package.json is $v"; else fail "js dry run: package.json is $v"; fi
  v=$(json "$tmp/cap/package-lock.json" 'd["version"], d["packages"][""]["version"], d["packages"]["node_modules/x"]["version"]')
  if [ "$v" = "('0.5.1-$mark', '0.5.1-$mark', '1.0.0')" ]; then pass "js dry run: package-lock.json root versions marked, dependencies untouched"
  else fail "js dry run: package-lock.json versions are $v"; fi
fi
if clean "$r"; then pass "js dry run: manifests restored after the error"; else fail "js dry run left changes:"; git -C "$r" status --short >&2; fi

if dry_build "$r" py; then fail "py dry run: build.sh went past the toolchain check"; fi
if [ ! -f "$tmp/cap/pyproject.toml" ]; then fail "py dry run: the toolchain check never ran:"; cat "$tmp/log" >&2
else
  if grep -qx "version = \"0.3.0+$mark\"" "$tmp/cap/pyproject.toml" && grep -qx 'version = "9.9.9"' "$tmp/cap/pyproject.toml"; then
    pass "py dry run: pyproject.toml is 0.3.0+$mark (and only [project]'s version changed)"
  else fail "py dry run: pyproject.toml is:"; cat "$tmp/cap/pyproject.toml" >&2; fi
fi
if clean "$r"; then pass "py dry run: pyproject.toml restored after the error"; else fail "py dry run left changes:"; git -C "$r" status --short >&2; fi

# Without VR_DRY_RUN nothing is marked.
rm -rf "$tmp/cap"
(cd "$r" && PATH="$tmp/bin:$PATH" VR_TEST_CAPTURE="$tmp/cap" .github/release/build.sh js "$tmp/out") >"$tmp/log" 2>&1 || true
if [ "$(json "$tmp/cap/package.json" 'd["version"]' 2>/dev/null)" = 0.5.1 ]; then pass "a release build does not mark the version"; else fail "a release build changed the version"; fi

# A signal while the manifest is marked: build.sh restores it and exits.
# Job control (set -m), so the background build does not start with SIGINT
# ignored, as a non-interactive shell's background jobs otherwise do.
set -m
for sig in TERM:143 INT:130 HUP:129; do
  want=${sig#*:} sig=${sig%:*}
  for p in js py; do
    rm -rf "$tmp/cap"
    (cd "$r" && PATH="$tmp/bin:$PATH" VR_TEST_CAPTURE="$tmp/cap" VR_TEST_HANG=1 VR_DRY_RUN=1 \
      exec .github/release/build.sh "$p" "$tmp/out") >"$tmp/log" 2>&1 &
    pid=$!
    for _ in $(seq 100); do [ -f "$tmp/cap/ready" ] && break; sleep 0.1; done
    if [ ! -f "$tmp/cap/ready" ]; then fail "$p SIG$sig: never reached the toolchain check"; kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true; continue; fi
    kill -"$sig" "$pid"
    kill "$(cat "$tmp/cap/ready")" 2>/dev/null || true # the stand-in, as a terminal's signal would
    status=0; { wait "$pid"; } 2>/dev/null || status=$?
    if [ "$status" -ne "$want" ]; then fail "$p SIG$sig: build.sh exited $status, not $want (128 + the signal)"; git -C "$r" checkout -q -- .
    elif clean "$r"; then pass "$p SIG$sig: manifest restored (exit $status)"
    else fail "$p SIG$sig: manifest left marked (exit $status):"; git -C "$r" status --short >&2; git -C "$r" checkout -q -- .; fi
  done
done

set +m

# Refused combinations.
for v in 2 yes true " 1"; do
  if (cd "$r" && VR_DRY_RUN=$v .github/release/build.sh js "$tmp/out") >"$tmp/log" 2>&1; then fail "VR_DRY_RUN='$v' was accepted"
  elif grep -q 'VR_DRY_RUN must be 1 or unset' "$tmp/log"; then pass "VR_DRY_RUN='$v' is refused"
  else fail "VR_DRY_RUN='$v': wrong error:"; cat "$tmp/log" >&2; fi
done
if (cd "$r" && VR_DRY_RUN=1 VR_GO_VERSION=v0.2.0 .github/release/build.sh go "$tmp/out") >"$tmp/log" 2>&1; then fail "VR_DRY_RUN=1 with VR_GO_VERSION was accepted"
elif grep -q 'a dry run uses the pseudo-version' "$tmp/log"; then pass "VR_DRY_RUN=1 with VR_GO_VERSION is refused"
else fail "VR_DRY_RUN=1 with VR_GO_VERSION: wrong error:"; cat "$tmp/log" >&2; fi

[ "$fails" -eq 0 ] || { echo "$fails failed" >&2; exit 1; }
echo "all passed"
