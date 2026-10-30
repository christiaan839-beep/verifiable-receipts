# Releasing

Each package is released on its own tag. The tag must match the version in
the package's manifest and point at a commit on `main`.

| Package | Version in | Tag |
|---|---|---|
| npm `@sovereignos/verifiable-receipts` | `packages/verifiable-receipts/package.json` | `js-vX.Y.Z` |
| PyPI `sovereign-matrix-verifiable-receipts` | `packages/verifiable-receipts-py/pyproject.toml` | `py-vX.Y.Z` |
| Go `github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go` | the tag | `packages/verifiable-receipts-go/vX.Y.Z` |

Pushing the tag starts `.github/workflows/release.yml`. It runs the test
workflow, then the reusable release build, `.github/workflows/build.yml`,
which builds the package's files reproducibly, writes a CycloneDX SBOM for
each, and signs a SLSA build provenance attestation and an SBOM attestation
for each file. Then it waits for a maintainer to approve the `release`
environment. After approval it publishes through trusted publishing, with no
stored token, verifies the files as a user would, and creates the GitHub
release with them.

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

The provenance meets [SLSA v1.0 Build L3](https://slsa.dev/spec/v1.0/levels#build-l3):
GitHub-hosted, ephemeral runners; provenance generated and signed by the
platform (a Sigstore certificate bound to the job's OIDC token); and the
build and signing isolated from the calling workflow. That isolation is why
the build is a reusable workflow: the certificate names `build.yml` as the
workflow that signed, and `release.yml` cannot add steps to its job, only
pick the package. A verifier that pins `--signer-workflow` to `build.yml`
therefore rejects anything another workflow of this repository signed, the
publish jobs' tokens included. This is GitHub's documented way to reach
Build L3 with artifact attestations
([GitHub Docs](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating));
`slsa-framework/slsa-github-generator` would reach the same level with a
second toolchain and a second verifier (`slsa-verifier`).

Limits: the build platform is GitHub Actions, so L3 trusts GitHub, and
anyone with write access to the repository can change `build.yml` itself
(source control, not build, protects against that: review, branch
protection, signed tags). The build fetches its dependencies from npm,
PyPI, the Go proxy and GitHub; they are pinned by lockfile and hash, but the
build is not hermetic.

## Verifying a release

Download the release and check the checksums:

```
gh release download js-v0.5.1 --repo christiaan839-beep/verifiable-receipts --dir vr-js-0.5.1
cd vr-js-0.5.1
sha256sum --check SHA256SUMS          # macOS: shasum -a 256 --check SHA256SUMS
```

Verify the provenance: built by `build.yml`, from the tag, on a
GitHub-hosted runner:

```
gh attestation verify sovereignos-verifiable-receipts-0.5.1.tgz \
  --repo christiaan839-beep/verifiable-receipts \
  --signer-workflow christiaan839-beep/verifiable-receipts/.github/workflows/build.yml \
  --source-ref refs/tags/js-v0.5.1 \
  --deny-self-hosted-runners
```

Verify the SBOM attestation, and that it is the published SBOM:

```
gh attestation verify sovereignos-verifiable-receipts-0.5.1.tgz \
  --repo christiaan839-beep/verifiable-receipts \
  --signer-workflow christiaan839-beep/verifiable-receipts/.github/workflows/build.yml \
  --source-ref refs/tags/js-v0.5.1 \
  --predicate-type https://cyclonedx.org/bom \
  --format json --jq '.[0].verificationResult.statement.predicate' \
  | jq -S . | diff - <(jq -S . sovereignos-verifiable-receipts-0.5.1.tgz.cdx.json) && echo SBOM matches
```

These fetch the attestations from GitHub. Offline, or to check the bundles
attached to the release, add `--bundle FILE.provenance.sigstore.json` (or
`FILE.sbom.sigstore.json`). `.github/release/verify.sh DIR refs/tags/TAG`
runs all of these checks on every file in a directory; the release workflow
runs it before it creates the release.

The same commands work for the other packages; change the file and the tag:
`sovereign_matrix_verifiable_receipts-0.3.0-py3-none-any.whl` (or the
`.tar.gz`) with `refs/tags/py-v0.3.0`, and `verifiable-receipts-go-v0.2.0.zip`
with `refs/tags/packages/verifiable-receipts-go/v0.2.0`. For a file from a
registry:

```
npm pack @sovereignos/verifiable-receipts@0.5.1
pip download --no-deps --only-binary :all: sovereign-matrix-verifiable-receipts==0.3.0
curl -LO https://proxy.golang.org/github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go/@v/v0.2.0.zip
```

Always pin `--signer-workflow` and `--source-ref`. Without
`--signer-workflow` a file signed by any workflow of the repository passes
(SLSA Build L2); without `--source-ref` so does a file built by a dry run
(below) from a branch.

## Rebuilding a release

The build is reproducible: the same commit and toolchain give the same
bytes. To check a release yourself, with the toolchain in
`.github/release/` (Node `node-version`, Python `python-version`, Go
`go-version`):

```
git clone https://github.com/christiaan839-beep/verifiable-receipts
cd verifiable-receipts
git checkout js-v0.5.1
.github/release/build.sh js ../rebuild      # or py, or go with VR_GO_VERSION=v0.2.0
cd ../rebuild
sha256sum --check --ignore-missing ../vr-js-0.5.1/SHA256SUMS
```

Every file and SBOM must print `OK`. The attestation bundles are not
rebuilt (each signature is new). The Go build fetches the tagged commit
from GitHub, as the Go proxy does. `build.sh` refuses another toolchain
version, because the gzip and deflate bytes depend on it (the files inside
do not); `VR_ALLOW_TOOLCHAIN_MISMATCH=1` builds anyway. It makes the bytes
stable by taking `SOURCE_DATE_EPOCH` from the commit, setting `TZ=UTC`,
`LC_ALL=C` and umask 022, resetting file modes from the git index, refusing
untracked files, installing the Python build tools by hash, and deriving
the SBOM serial numbers and timestamps from the file and the commit.

CI checks this on every pull request and on `main`:
`.github/workflows/reproducible.yml` builds each package twice, the second
time on another runner image, two minutes later, under umask 077, another
time zone and a deeper checkout path, and fails if a byte differs.

## Dry run

`.github/workflows/release-dry-run.yml` runs the release build, the SBOMs,
the attestations, `SHA256SUMS` and the verification for all three packages,
and uploads the would-be release files as the artifact `release-assets`. It
publishes nothing, uses no environment and makes no tag. Start it from the
Actions tab (Run workflow) or push a branch named `release-dry-run/<name>`.
Pull requests do not run it: attestations need an OIDC token, and a pull
request from a fork gets none. Its attestations are real and public, and
record the branch as their source ref, which is why the commands above pin
`--source-ref` to the tag.

## A release

1. Update the version and the changelog in a pull request, and merge it.
2. Tag the merge commit, signed, and push the tag:

   ```
   git tag -s js-v0.5.1 -m "js-v0.5.1"
   git push origin js-v0.5.1
   ```

3. Approve the `release` deployment in the Actions run.
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
