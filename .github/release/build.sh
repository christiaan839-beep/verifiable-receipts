#!/usr/bin/env bash
# Builds one package's release files, byte for byte reproducibly, with a
# CycloneDX SBOM for each:
#
#   .github/release/build.sh js|py|go OUTDIR
#
#   js  sovereignos-verifiable-receipts-X.Y.Z.tgz              (npm pack)
#   py  sovereign_matrix_verifiable_receipts-X.Y.Z.tar.gz and
#       sovereign_matrix_verifiable_receipts-X.Y.Z-py3-none-any.whl
#   go  verifiable-receipts-go-vX.Y.Z.zip   (the module zip: the same bytes
#       proxy.golang.org serves, and the zip the go.sum hash is taken over;
#       made by .github/release/gomodzip)
#
# and OUTDIR/<file>.cdx.json next to each. The release workflow
# (.github/workflows/build.yml) runs this, so does the reproducibility check
# (.github/workflows/reproducible.yml), and anyone can run it on a clean
# clone to rebuild a release (RELEASING.md).
#
# What makes the output reproducible:
#   - SOURCE_DATE_EPOCH is the commit time; TZ=UTC, LC_ALL=C, umask 022;
#   - file modes are reset from the git index (a clone made under umask 077
#     otherwise packs as 0600/0700), and build output is 0644;
#   - the package, .github/release and .github/tools must be clean (no
#     uncommitted or untracked files);
#   - the toolchain is the exact version in .github/release/*-version (the
#     gzip and deflate bytes depend on the Node, Python and Go version; the
#     files inside do not), and the build tools are installed by hash;
#   - SBOM serial numbers and timestamps come from the file and the commit,
#     not from the clock (normalize_sbom.py).
#
# VR_ALLOW_TOOLCHAIN_MISMATCH=1 builds with another toolchain anyway (the
# compressed bytes will usually differ). VR_GO_VERSION=vX.Y.Z builds the Go
# module zip for that tag, which must name the commit; without it the zip
# is for the commit's pseudo-version.
#
# VR_DRY_RUN=1 builds a dry run's files (release-dry-run.yml): the same
# build, with the version marked so that no dry-run file, and so no dry-run
# attestation, can match a release file. The bytes differ, not just the
# names (attestations are looked up by digest):
#   js  X.Y.Z-dryrun.g<commit>   (a semver pre-release)
#   py  X.Y.Z+dryrun.g<commit>   (a PEP 440 local version, which PyPI refuses)
#   go  the commit's pseudo-version, as without VR_GO_VERSION
# <commit> is the first 12 hex digits of the commit. The manifest is edited
# for the build and restored afterwards.
set -euo pipefail

usage() { echo "usage: $0 js|py|go OUTDIR" >&2; exit 2; }
[ $# -eq 2 ] || usage
pkg=$1
case "$pkg" in js | py | go) ;; *) usage ;; esac

umask 022
export TZ=UTC LC_ALL=C LANG=C

here=$(cd "$(dirname "$0")" && pwd)
root=$(git -C "$here" rev-parse --show-toplevel)
mkdir -p "$2"
out=$(cd "$2" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/vr-build.XXXXXX")
restore=()
cleanup() {
  if [ ${#restore[@]} -gt 0 ]; then git -C "$root" checkout --quiet -- "${restore[@]}"; fi
  rm -rf "$work"
}
trap cleanup EXIT
dry_run=${VR_DRY_RUN:-}
case "$dry_run" in "" | 0) dry_run= ;; 1) ;; *) echo "error: VR_DRY_RUN must be 1 or unset" >&2; exit 2 ;; esac
if [ -n "$dry_run" ] && [ -n "${VR_GO_VERSION:-}" ]; then
  echo "error: VR_GO_VERSION builds a release; a dry run uses the pseudo-version" >&2
  exit 2
fi

case "$pkg" in
  js) dir=packages/verifiable-receipts ;;
  py) dir=packages/verifiable-receipts-py ;;
  go) dir=packages/verifiable-receipts-go ;;
esac

cd "$root"
# An untracked file would end up in the sdist, and a changed build script,
# lockfile or tool list would build something the commit does not name;
# refuse a tree with either.
checked=("$dir" .github/release .github/tools)
if [ -n "$(git status --porcelain --untracked-files=all -- "${checked[@]}")" ]; then
  echo "error: ${checked[*]} have uncommitted or untracked files:" >&2
  git status --short --untracked-files=all -- "${checked[@]}" >&2
  exit 1
fi
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export SOURCE_DATE_EPOCH
commit=$(git rev-parse HEAD)
echo "building $pkg from $commit, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH${dry_run:+ (dry run)}"

# Modes as git records them: 0755 for executables, 0644 for the rest.
# NUL-separated, so any file name works; symlinks (120000) and submodules
# (160000) are skipped (chmod would follow a link to its target).
while IFS= read -r -d '' entry; do
  meta=${entry%%$'\t'*}
  file=${entry#*$'\t'}
  case "${meta%% *}" in
    100755) chmod -- 0755 "$file" ;;
    100644) chmod -- 0644 "$file" ;;
    120000 | 160000) ;;
    *) echo "error: unexpected git mode for $file: $meta" >&2; exit 1 ;;
  esac
done < <(git ls-files -s -z -- "$dir")

# A dry run marks the version in the manifest (restored on exit).
if [ -n "$dry_run" ]; then
  mark="dryrun.g${commit:0:12}"
  case "$pkg" in
    js)
      restore=("$dir/package.json" "$dir/package-lock.json")
      python3 -I - "$dir/package.json" "$dir/package-lock.json" "-$mark" <<'PY'
import json, sys
pkg, lock, suffix = sys.argv[1:]
for path in (pkg, lock):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    data["version"] = data["version"] + suffix
    if path == lock:
        data["packages"][""]["version"] = data["version"]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
PY
      ;;
    py)
      restore=("$dir/pyproject.toml")
      python3 -I - "$dir/pyproject.toml" "+$mark" <<'PY'
import re, sys
path, suffix = sys.argv[1:]
with open(path, encoding="utf-8") as f:
    text = f.read()
text, n = re.subn(r'(?m)^(version = "[^"]+)"', lambda m: m.group(1) + suffix + '"', text, count=1)
if n != 1:
    raise SystemExit(f"{path}: no version line")
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PY
      ;;
    go) ;;
  esac
fi

check_version() { # tool, wanted, have
  [ "$2" = "$3" ] && return 0
  if [ "${VR_ALLOW_TOOLCHAIN_MISMATCH:-}" = 1 ]; then
    echo "warning: $1 is $3, the release toolchain is $2; the bytes may differ" >&2
  else
    echo "error: $1 is $3, the release toolchain is $2 (.github/release/$1-version);" \
      "set VR_ALLOW_TOOLCHAIN_MISMATCH=1 to build anyway" >&2
    exit 1
  fi
}

normalize() { # sbom, artifact, purl
  python3 -I "$here/normalize_sbom.py" --sbom "$1" --artifact "$2" --purl "$3" \
    --epoch "$SOURCE_DATE_EPOCH" --out "$2.cdx.json"
}

case "$pkg" in
  js)
    check_version node "v$(cat "$here/node-version")" "$(node --version)"
    cd "$dir"
    npm ci --ignore-scripts --no-audit --no-fund
    rm -rf dist
    npm run build
    find dist -type d -exec chmod 0755 {} +
    find dist -type f -exec chmod 0644 {} +
    npm pack --ignore-scripts --pack-destination "$work" >/dev/null
    tgz=("$work"/*.tgz)
    [ ${#tgz[@]} -eq 1 ] || { echo "error: expected one tarball" >&2; exit 1; }
    name=$(basename "${tgz[0]}")
    cp "${tgz[0]}" "$out/$name"
    version=$(node -p "require('./package.json').version")
    npm sbom --sbom-format cyclonedx --sbom-type library --omit dev >"$work/sbom.json"
    normalize "$work/sbom.json" "$out/$name" "pkg:npm/%40sovereignos/verifiable-receipts@$version"
    ;;

  py)
    check_version python "$(cat "$here/python-version")" \
      "$(python3 -c 'import platform; print(platform.python_version())')"
    python3 -m venv "$work/build-venv"
    "$work/build-venv/bin/python" -m pip install --quiet --disable-pip-version-check \
      --require-hashes --no-deps -r .github/tools/python-build/requirements.txt
    python3 -m venv "$work/sbom-venv"
    "$work/sbom-venv/bin/python" -m pip install --quiet --disable-pip-version-check \
      --require-hashes --no-deps -r .github/tools/python-sbom/requirements.txt
    "$work/build-venv/bin/python" -m build --no-isolation --outdir "$work/dist" "$dir"
    version=$(python3 -c "import tomllib, sys; print(tomllib.load(open(sys.argv[1], 'rb'))['project']['version'])" "$dir/pyproject.toml")
    # The runtime dependencies as locked, by hash, in runtime.txt (compiled
    # from pyproject.toml; the npm SBOM reads package-lock.json the same way).
    "$work/sbom-venv/bin/cyclonedx-py" requirements --pyproject "$dir/pyproject.toml" \
      --mc-type library --sv 1.5 --of JSON --output-reproducible \
      -o "$work/sbom.json" .github/tools/python-sbom/runtime.txt
    for f in "$work"/dist/*; do
      cp "$f" "$out/"
      normalize "$work/sbom.json" "$out/$(basename "$f")" \
        "pkg:pypi/sovereign-matrix-verifiable-receipts@${version//+/%2B}"
    done
    ;;

  go)
    check_version go "go$(cat "$here/go-version")" "$(go env GOVERSION)"
    module=github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go
    export GOWORK=off GOFLAGS=-modcacherw GOMODCACHE="$work/modcache" GOTOOLCHAIN=local
    # The module zip, made from `git archive` of the commit by the code the
    # go command and the module proxy use (gomodzip). A plain clone, so this
    # works from a git worktree too; nothing is fetched from GitHub.
    git clone --quiet --no-checkout "$root" "$work/repo"
    line=$(cd "$here/gomodzip" && go run . -repo "$work/repo" -rev "$commit" \
      -version "${VR_GO_VERSION:-pseudo}" -out "$work/module.zip")
    version=$(awk '{print $2}' <<<"$line")
    echo "go.sum line: $line"
    # The zip holds exactly this commit's files for the module.
    mkdir "$work/unzipped"
    (cd "$work/unzipped" && unzip -q "$work/module.zip")
    git ls-files -- "$dir" | sed "s#^$dir/##" | sort >"$work/tracked"
    (cd "$work/unzipped/$module@$version" && find . -type f | sed 's#^\./##' | sort) >"$work/zipped"
    diff -u "$work/tracked" "$work/zipped"
    while read -r f; do cmp "$dir/$f" "$work/unzipped/$module@$version/$f"; done <"$work/tracked"
    name="verifiable-receipts-go-$version.zip"
    cp "$work/module.zip" "$out/$name"
    (cd "$dir" && go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0 \
      mod -json -type library -output-version 1.5 -noserial -notimestamp -output "$work/sbom.json" .)
    normalize "$work/sbom.json" "$out/$name" "pkg:golang/$module@$version?type=module"
    ;;
esac

cd "$out"
if command -v sha256sum >/dev/null; then sha256sum -- *; else shasum -a 256 -- *; fi
