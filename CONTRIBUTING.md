# Contributing

Thank you for helping. This repository holds three verifiers for one
receipt format (TypeScript, Python and Go), so most changes touch all
three, and the shared fixtures decide whether they agree.

## Reporting

- **A security flaw**: report it privately, as `SECURITY.md` says. Don't
  open a public issue.
- **A bug**: open an issue with the package and version, what you
  expected, what happened, and a receipt, proof or script that shows it
  (test keys only).
- **A proposal**: open an issue first for anything that changes the wire
  format, a spec in `docs/specs/`, or what a verifier accepts.

## Changing code

1. Fork, branch from `main`, and open a pull request. CI must pass and
   every review conversation must be resolved before it merges; `main`
   takes merge commits only.
2. A change to what a verifier accepts goes into all three verifiers, the
   spec, a fixture in `packages/verifiable-receipts/conformance/fixtures/`
   (see the README there), and the changelog.
3. Add tests with the change. New behaviour without a test is not merged.

## The checks CI runs

```bash
# TypeScript
(cd packages/verifiable-receipts && npm ci && npm run typecheck && npm run lint && npm run build && npm test)
# Python
pip install --require-hashes --no-deps -r .github/tools/python-ci/requirements.txt
ruff check .
PYTHONPATH=packages/verifiable-receipts-py python -m pytest packages/verifiable-receipts-py/tests packages/verifiable-receipts/conformance/conformance.py packages/verifiable-receipts/conformance/differential schemas
# Go
(cd packages/verifiable-receipts-go && test -z "$(gofmt -l .)" && go vet ./... && go test ./...)
# All three together
bash packages/verifiable-receipts/conformance/roundtrip/run.sh
bash packages/verifiable-receipts/conformance/differential/run.sh 20000 1
```

The `fuzz` workflow also runs the Go fuzz targets and, nightly, longer
property and differential runs. CodeQL, zizmor and OpenSSF Scorecard
report to code scanning.

## Style

- Plain, declarative prose in docs and comments; each fact once; no
  claim the code does not back.
- Commit messages: a subject line under 72 characters, a blank line, then
  what changed and why.
- Workflow actions are pinned to full commit SHAs, and every job declares
  the permissions it uses.

By contributing you agree that your contribution is licensed under the
Apache License 2.0 (`LICENSE`).
