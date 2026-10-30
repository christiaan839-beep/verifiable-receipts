# Security

## Reporting a vulnerability

Report a suspected flaw in the signing, verification, proof or log code
privately, through a GitHub security advisory:
<https://github.com/christiaan839-beep/verifiable-receipts/security/advisories/new>
(the repository's **Security** tab, then **Report a vulnerability**).
Don't open a public issue for it.

If you cannot use GitHub, email `sovereign.systems007@gmail.com` with
`[security]` at the start of the subject.

Please include:

- the package and version (TypeScript, Python or Go, and the commit if
  you work from a clone);
- what you expected and what happened;
- a receipt, key pair, proof or script that shows it, using test keys
  only, never a key in real use.

You should get a first reply within seven days. A fix is developed in
the private advisory, and the advisory is published with the release
that fixes it, crediting you unless you ask otherwise.

## Scope

In scope: anything that makes a verifier in this repository accept
what it should reject (a forged or altered receipt, an envelope field
not covered by `canonical`, a proof for a leaf not in the tree, a
threshold envelope without enough signatures), a crash or hang on
attacker-supplied input, a disagreement between the TypeScript, Python
and Go verifiers, and a flaw in an argument in `packages/verifiable-receipts/proofs/`.

Out of scope: the limits the root README lists under "Security model"
(for example, `v3=` downgrade when a verifier accepts `v2=`, or trust in
the issuer's own claims), and vulnerabilities in dependencies that do
not affect this code (report those upstream).

## Supported versions

Fixes go into `main` and the latest release of each package (npm,
PyPI and the Go module); older versions are not patched.

## Verifying a release

Releases are built and published from CI, never from a maintainer's
machine. Each release file has:

- SLSA v1.0 Build Level 3 provenance, signed (Sigstore, through GitHub
  artifact attestations) by the reusable workflow
  `.github/workflows/build.yml`;
- a CycloneDX SBOM, `FILE.cdx.json`, attested by the same workflow;
- a reproducible build: rebuilding the tagged commit with
  `.github/release/build.sh` gives the same bytes, and CI checks that on
  every pull request.

Verify a file (here the npm tarball; RELEASING.md has the other packages):

```
gh attestation verify sovereignos-verifiable-receipts-0.5.1.tgz \
  --repo christiaan839-beep/verifiable-receipts \
  --signer-workflow christiaan839-beep/verifiable-receipts/.github/workflows/build.yml \
  --source-ref refs/tags/js-v0.5.1 --deny-self-hosted-runners
gh attestation verify sovereignos-verifiable-receipts-0.5.1.tgz \
  --repo christiaan839-beep/verifiable-receipts \
  --signer-workflow christiaan839-beep/verifiable-receipts/.github/workflows/build.yml \
  --source-ref refs/tags/js-v0.5.1 --deny-self-hosted-runners \
  --predicate-type https://cyclonedx.org/bom
```

and rebuild it:

```
git checkout js-v0.5.1
.github/release/build.sh js ../rebuild
(cd ../rebuild && sha256sum --check --ignore-missing /path/to/release/SHA256SUMS)
```

Pin both `--signer-workflow` and `--source-ref`: without the first, a
file signed by any workflow of this repository passes; without the
second, so does a dry-run build from a branch. A file that fails any of
these checks did not come from a release; please report it as above.
