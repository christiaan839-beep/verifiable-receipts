# Releasing

Each package is released on its own tag. The tag must match the version in
the package's manifest and point at a commit on `main`.

| Package | Version in | Tag |
|---|---|---|
| npm `@sovereignos/verifiable-receipts` | `packages/verifiable-receipts/package.json` | `js-vX.Y.Z` |
| PyPI `sovereign-matrix-verifiable-receipts` | `packages/verifiable-receipts-py/pyproject.toml` | `py-vX.Y.Z` |
| Go `github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go` | the tag | `packages/verifiable-receipts-go/vX.Y.Z` |

Pushing the tag starts `.github/workflows/release.yml`. It checks the tag,
runs the test workflow, then the reusable release build,
`.github/workflows/build.yml`. Its `build` job builds the package's files
reproducibly and writes a CycloneDX SBOM for each, with a read-only token;
its `attest` job, once a maintainer approves the `release` environment,
checks the files against the build job's digests and signs a SLSA build
provenance attestation and an SBOM attestation for each. Then each publish
job, again after approval, checks the exact files it is about to upload
against those attestations and digests (`.github/release/verify.sh`), stops
if anything does not match, and publishes through trusted publishing, with
no stored token. Last, the GitHub release is created with the files, after
the same check.

## What a release contains

| File | What it is |
|---|---|
| `sovereignos-verifiable-receipts-X.Y.Z.tgz` | the npm tarball (`js-v*`) |
| `sovereign_matrix_verifiable_receipts-X.Y.Z.tar.gz`, `…-py3-none-any.whl` | the Python sdist and wheel (`py-v*`) |
| `verifiable-receipts-go-vX.Y.Z.zip` | the Go module zip: the same bytes `proxy.golang.org` serves, and the zip the `go.sum` hash covers |
| `FILE.cdx.json` | the file's SBOM, CycloneDX 1.5 JSON |
| `FILE.provenance.sigstore.json` | the Sigstore bundle of the file's SLSA v1 provenance |
| `FILE.sbom.sigstore.json` | the Sigstore bundle of the file's SBOM attestation |
| `SHA256SUMS` | SHA-256 of every other file in the release |

The files on npm and PyPI and from the Go proxy are byte-identical to the
release's (the npm job checks the tarball it stages; the Go job checks the
proxy's zip), so everything below works on a file from any of them.

## SLSA Build Level 3

What holds, and what it rests on:

- **Provenance is generated and signed by the build platform.**
  `actions/attest` makes the SLSA v1 provenance from the job's OIDC token
  (repository, ref, commit, workflow, run), and Sigstore's Fulcio issues the
  signing certificate for that token. The steps of the build do not write
  the provenance.
- **The build cannot reach the signing identity.** `build.yml` has two
  jobs. `build` runs everything that comes from the repository or a
  registry (`build.sh`, npm and `tsc`, pip and hatchling, `cyclonedx-py`,
  `go run cyclonedx-gomod`) with `contents: read` and no `id-token`
  permission, so nothing it runs can get an OIDC token or sign. `attest`
  has `id-token: write` and `attestations: write`, checks nothing out and
  runs only pinned actions (`download-artifact`, `attest`,
  `upload-artifact`) and the shell written in `build.yml`. It re-checks
  every file against the SHA-256 digests the build job output before it
  signs. The jobs run on separate, fresh runners.
- **The signer is isolated from the caller.** The certificate names
  `build.yml` as the workflow that signed (its Build Signer URI). The
  caller, `release.yml`, chooses only the package and, for Go, the version,
  and `build.yml` checks both against the tag; it cannot add steps to
  `build.yml`'s jobs. A verifier that pins `--signer-workflow` to
  `build.yml` rejects anything else this repository signs, the npm and PyPI
  provenance from the publish jobs included.
- **Hosted, ephemeral runners.** Every job runs on a fresh GitHub-hosted
  runner; `--deny-self-hosted-runners` checks it.

This is GitHub's documented way to reach Build L3 with artifact attestations
([GitHub Docs](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating));
`slsa-framework/slsa-github-generator` would reach the same level with a
second toolchain and a second verifier (`slsa-verifier`).

What it does not cover:

- **GitHub is trusted.** The runners, the Actions service that hands the
  build job's outputs and artifact to the attest job, the OIDC issuer and
  the attestation store are GitHub's. A compromise of GitHub-hosted runners
  or of Actions defeats the isolation above; SLSA L3 assumes the platform is
  honest.
- **The build job's output is what the provenance vouches for, not that
  the source is benign.** Code at the tagged commit runs in the build job
  and decides the bytes; the provenance records that commit. Anyone with
  write access can change `build.yml` and `build.sh` themselves; review,
  branch protection on `main`, the tag ruleset and the `release` approval
  protect against that, not the build.
- **Not hermetic.** The build fetches its dependencies from npm, PyPI, the
  Go proxy and GitHub, pinned by lockfile and hash, and the second
  reproducible build does too.

## SBOMs

Each release file has a CycloneDX 1.5 SBOM, `FILE.cdx.json`. Its root
component is the file (its purl, version and SHA-256); its components are
the package's runtime dependencies.

The versions in an SBOM are the exact set the release was built and tested
against, as locked in the repository, not the range a user's installer may
pick:

- npm: `package-lock.json` (`npm sbom --omit dev`). A user's `npm install`
  resolves the `dependencies` ranges in `package.json` and may get newer
  versions.
- Python: `.github/tools/python-sbom/runtime.txt`, which `uv pip compile`
  makes from `pyproject.toml`'s dependencies (Python 3.12, Linux x86-64).
  `pyproject.toml` states minimums (`cryptography>=42.0.0`); the SBOM
  lists the version runtime.txt locks (cryptography 50.0.2, and its
  dependencies). CI (`test.yml`, Release tools) compiles `pyproject.toml`
  again with the date in runtime.txt's header and fails if runtime.txt
  differs, so the SBOM cannot drift from `pyproject.toml`. After a
  dependency change, regenerate it from the repository root with the
  command in its header, with a new `--exclude-newer` date (14 days ago).
- Go: `go.mod` (`cyclonedx-gomod mod`). The Go command uses exactly these
  versions unless the user's module requires newer ones.

## Verifying a release

The commands below run in bash or zsh, from an empty directory. They need
`gh` (logged in), `jq` and `git`. The example is `js-v0.5.1`; for the other
packages change the tag and the file names (table at the end of this
section).

Download the release and check the checksums:

```
gh release download js-v0.5.1 --repo christiaan839-beep/verifiable-receipts --dir release
(cd release && sha256sum --check SHA256SUMS)   # macOS: shasum -a 256 --check SHA256SUMS
```

Check that the tag names a commit on `main` (the ruleset on release tags
does not check this; `release.yml` refuses to build otherwise, but check
it yourself):

```
git clone --quiet https://github.com/christiaan839-beep/verifiable-receipts src
commit=$(git -C src rev-parse 'js-v0.5.1^{commit}')
git -C src merge-base --is-ancestor "$commit" origin/main && echo "$commit is on main"
```

Verify the provenance: built by `build.yml`, from the tag and that commit,
on a GitHub-hosted runner:

```
gh attestation verify release/sovereignos-verifiable-receipts-0.5.1.tgz \
  --repo christiaan839-beep/verifiable-receipts \
  --signer-workflow christiaan839-beep/verifiable-receipts/.github/workflows/build.yml \
  --source-ref refs/tags/js-v0.5.1 \
  --source-digest "$commit" \
  --deny-self-hosted-runners
```

Verify the SBOM attestation, and that it is the published SBOM:

```
gh attestation verify release/sovereignos-verifiable-receipts-0.5.1.tgz \
  --repo christiaan839-beep/verifiable-receipts \
  --signer-workflow christiaan839-beep/verifiable-receipts/.github/workflows/build.yml \
  --source-ref refs/tags/js-v0.5.1 \
  --source-digest "$commit" \
  --deny-self-hosted-runners \
  --predicate-type https://cyclonedx.org/bom \
  --format json --jq '.[0].verificationResult.statement.predicate' \
  | jq -S . | diff - <(jq -S . release/sovereignos-verifiable-receipts-0.5.1.tgz.cdx.json) && echo "SBOM matches"
```

These fetch the attestations from GitHub. Offline, or to check the bundles
attached to the release, add `--bundle release/FILE.provenance.sigstore.json`
(or `release/FILE.sbom.sigstore.json`). `.github/release/verify.sh` runs all
of these checks on every file in a directory (the commit check excepted):

```
src/.github/release/verify.sh --source-digest "$commit" release refs/tags/js-v0.5.1
```

Every publish job in `release.yml` runs it on the files it uploads, with
`--expect` set to the digests `build.yml` output, before it uploads.

| Package | Tag | Files |
|---|---|---|
| npm | `js-v0.5.1` | `sovereignos-verifiable-receipts-0.5.1.tgz` |
| PyPI | `py-v0.3.0` | `sovereign_matrix_verifiable_receipts-0.3.0.tar.gz`, `sovereign_matrix_verifiable_receipts-0.3.0-py3-none-any.whl` |
| Go | `packages/verifiable-receipts-go/v0.2.0` | `verifiable-receipts-go-v0.2.0.zip` |

The same checks work on a file from a registry, which is byte-identical to
the release's (the npm job checks the tarball it stages; the Go job checks
the proxy's zip):

```
npm pack @sovereignos/verifiable-receipts@0.5.1
pip download --no-deps --only-binary :all: sovereign-matrix-verifiable-receipts==0.3.0
curl -fsSL -o verifiable-receipts-go-v0.2.0.zip \
  https://proxy.golang.org/github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go/@v/v0.2.0.zip
```

Always pin `--signer-workflow`, `--source-ref` and `--source-digest`.
Without `--signer-workflow` a file signed by any workflow of the repository
passes (SLSA Build L2). `--source-ref` and `--source-digest` tie the file to
the release tag and its commit. A dry run's files (below) carry a marked
version, so their digests never equal a release file's and their
attestations never verify one; the pins are there regardless.

## Rebuilding a release

The build is reproducible: the same commit and toolchain give the same
bytes. To rebuild a release yourself you need the toolchain in
`.github/release/` at the tag (Node `node-version`, Python `python-version`,
Go `go-version`; `build.sh` refuses another version, because the gzip and
deflate bytes depend on it, though the files inside do not;
`VR_ALLOW_TOOLCHAIN_MISMATCH=1` builds anyway). In the directory from
"Verifying a release" (with `release/` and the clone `src/`):

```
git -C src checkout --quiet js-v0.5.1
src/.github/release/build.sh js rebuild
(cd rebuild && sha256sum --check --ignore-missing ../release/SHA256SUMS)   # macOS: shasum -a 256 --check --ignore-missing
```

For Python, `build.sh py rebuild`. For Go, the module zip's version comes
from the tag, which `build.sh` takes from `VR_GO_VERSION` (without it, it
builds the commit's pseudo-version):

```
git -C src checkout --quiet packages/verifiable-receipts-go/v0.2.0
VR_GO_VERSION=v0.2.0 src/.github/release/build.sh go rebuild
```

Every file and SBOM must print `OK`. The attestation bundles are not
rebuilt (each signature is new). The Go build does not fetch the module
from GitHub: it makes the zip from a local clone of the checkout (`git
clone --no-checkout` of `src`), from the tagged commit, with the code the go
command and the proxy use. `build.sh` makes the bytes stable by taking
`SOURCE_DATE_EPOCH` from the commit, setting `TZ=UTC`, `LC_ALL=C` and umask
022, resetting the package's file modes from the git index, refusing
uncommitted or untracked files in the package, `.github/release` and
`.github/tools`, installing the Python build tools by hash, and deriving
the SBOM serial numbers and timestamps from the file and the commit.

CI checks this on every pull request and on `main`:
`.github/workflows/reproducible.yml` builds each package twice and fails if
a byte differs. The second build runs on another runner image
(ubuntu-22.04, not 24.04), two minutes later, from a deeper path, as
another user (another uid and gid) with an empty HOME (no shared npm, pip
or Go cache), reading the checkout through disorderfs so every directory
lists its files in a shuffled order, with the files' group and other mode
bits cleared and every mtime under `packages/` changed, and calls `build.sh`
under umask 077, another time zone and another locale. `build.sh` resets
the umask, time zone, locale and the package's file modes itself, so those
check that reset. The toolchain, the CPU architecture and the kernel are
not varied.

### Updating the toolchain

Dependabot does not update `.github/release/node-version`,
`python-version` or `go-version`. To move to a newer patch release (do it
on its own, not in a release's pull request):

1. Put the new version in the file (`24.22.3`, `3.12.17`, `1.27.4`: exact,
   no `v` or `go` prefix). The Go major.minor in `test.yml`'s matrix stays
   as it is unless it changes too.
2. Open a pull request. `reproducible.yml` builds with the new version
   twice and must pass.
3. Release files built afterwards differ in their compressed bytes from
   those built before; each release rebuilds with the toolchain recorded at
   its own tag.

## Dry run

`.github/workflows/release-dry-run.yml` runs the release build, the SBOMs,
the attestations, the publish jobs' check (on the real files, then on
tampered files and digests, which it must refuse), `SHA256SUMS` and the
verification for all three packages, and uploads the would-be release files
as the artifact `release-assets`. It publishes nothing, uses no environment
and makes no tag. Start it from the Actions tab (Run workflow, on a branch)
or push a branch named `release-dry-run/<name>`. Pull requests do not run
it: attestations need an OIDC token, and a pull request from a fork gets
none.

`build.yml` builds any ref that is not a tag as a dry run (`VR_DRY_RUN=1`):
the version is marked, `X.Y.Z-dryrun.g<commit>` for npm,
`X.Y.Z+dryrun.g<commit>` for Python (a local version, which PyPI refuses),
and the commit's pseudo-version for Go, so the files' bytes differ from any
release's. Its attestations are real and public, and record the branch as
their source ref; since attestations are looked up by a file's digest, they
never verify a release file.

## A release

1. Update the version and the changelog in a pull request, and merge it.
2. Tag the merge commit, signed, and push the tag:

   ```
   git tag -s js-v0.5.1 -m "js-v0.5.1"
   git push origin js-v0.5.1
   ```

3. Approve the `release` deployments in the Actions run: the attest job
   (nothing is signed before this), then the publish job, then the GitHub
   release job.
4. npm only: the package arrives staged. Review it and approve it with 2FA,
   on npmjs.com (Staged Packages) or with `npm stage approve <stage-id>`.

Before tagging, a dry run (above) shows the release would build, attest
and verify. npm and PyPI also show their own provenance for each version
published by the workflow (signed by `release.yml`, SLSA Build L2); the L3
provenance is the one from `build.yml`.

## One-time setup

### PyPI

On pypi.org, under Your account → Publishing, add a pending trusted publisher
for the project `sovereign-matrix-verifiable-receipts`: owner
`christiaan839-beep`, repository `verifiable-receipts`, workflow
`release.yml`, environment `release`. The first `py-v*` release creates the
project.

### npm

npm adds a trusted publisher only to a package that already exists, so the
first version goes up by hand:

1. The package publishes under the npm organisation `sovereignos`. Make
   sure you are an owner of it and that 2FA is on for your npm account.
2. Push `js-v0.5.1`. With `NPM_TRUSTED_PUBLISHING` unset the workflow skips
   the npm job and still attaches the attested tarball to the GitHub release.
3. Download that tarball, check it as in "Verifying a release", and publish
   it: `npm publish sovereignos-verifiable-receipts-0.5.1.tgz --access public`.
4. In the package's settings on npmjs.com, add a trusted publisher: GitHub
   Actions, `christiaan839-beep` / `verifiable-receipts`, workflow
   `release.yml`, environment `release`, allowed action: stage publish only.
   The next release must use it within two days of adding it, or the
   configuration expires.
5. Under Publishing access, choose "Require two-factor authentication and
   disallow tokens".
6. Set the repository variable `NPM_TRUSTED_PUBLISHING` to `true`
   (Settings → Secrets and variables → Actions → Variables).

### Go

Nothing to configure. The release job fetches the version through
`proxy.golang.org` and `sum.golang.org` so it is cached and its checksum is
recorded.
