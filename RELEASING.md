# Releasing

Each package is released on its own tag. The tag must match the version in
the package's manifest and point at a commit on `main`.

| Package | Version in | Tag |
|---|---|---|
| npm `@sovereignos/verifiable-receipts` | `packages/verifiable-receipts/package.json` | `js-vX.Y.Z` |
| PyPI `sovereign-matrix-verifiable-receipts` | `packages/verifiable-receipts-py/pyproject.toml` | `py-vX.Y.Z` |
| Go `github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go` | the tag | `packages/verifiable-receipts-go/vX.Y.Z` |

Pushing the tag starts `.github/workflows/release.yml`. It runs the test
workflow, builds the package, records a signed build-provenance attestation
for every file it built, and waits for a maintainer to approve the `release`
environment. After approval it publishes through trusted publishing, with no
stored token, and creates the GitHub release with the built files and the
attestation bundle (`attestation.sigstore.json`).

## A release

1. Update the version and the changelog in a pull request, and merge it.
2. Tag the merge commit, signed, and push the tag:

   ```
   git tag -s js-v0.5.0 -m "js-v0.5.0"
   git push origin js-v0.5.0
   ```

3. Approve the `release` deployment in the Actions run.
4. npm only: the package arrives staged. Review it and approve it with 2FA,
   on npmjs.com (Staged Packages) or with `npm stage approve <stage-id>`.

Anyone can check a downloaded file against its attestation:

```
gh attestation verify <file> --repo christiaan839-beep/verifiable-receipts
```

npm and PyPI also show their own provenance for each version published by
the workflow.

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
2. Push `js-v0.5.0`. With `NPM_TRUSTED_PUBLISHING` unset the workflow skips
   the npm job and still attaches the attested tarball to the GitHub release.
3. Download that tarball, check it with `gh attestation verify`, and publish
   it: `npm publish sovereignos-verifiable-receipts-0.5.0.tgz --access public`.
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
