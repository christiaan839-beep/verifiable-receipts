# verifiable-receipts

Signed receipts for AI calls: a record of what an AI agent was asked,
what it answered and which checks ran, signed so that anyone with the
issuer's public key can verify it later.

This repository is the landing page. The code lives in
[sovereign-v2](https://github.com/christiaan839-beep/sovereign-v2):

| Language   | Path                                                                                                                         | Role                                   |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| TypeScript | [`packages/verifiable-receipts`](https://github.com/christiaan839-beep/sovereign-v2/tree/main/packages/verifiable-receipts)       | Signs and verifies (source of truth)   |
| Python     | [`packages/verifiable-receipts-py`](https://github.com/christiaan839-beep/sovereign-v2/tree/main/packages/verifiable-receipts-py) | Verifies                               |
| Go         | [`packages/verifiable-receipts-go`](https://github.com/christiaan839-beep/sovereign-v2/tree/main/packages/verifiable-receipts-go) | Verifies                               |

## What a signed receipt is

A v2 receipt looks like this (values shortened):

```json
{
  "verdictId": "v_…",
  "overall": "pass",
  "issuedAt": "2026-…",
  "canonical": "{…}",
  "contentHash": "sha256:…",
  "signature": "v2=…"
}
```

- `canonical` is the exact UTF-8 JSON string that was signed.
- `contentHash` is `sha256:` followed by the hex SHA-256 of `canonical`.
- `signature` is `v2=` followed by the base64 Ed25519 signature over
  `canonical`.

To verify, check the hash against `canonical`, then check the Ed25519
signature over `canonical` with the issuer's public key. The TypeScript
library can also add a post-quantum signature, ML-DSA-65 (FIPS 204), in a
`v3=` receipt, and it checks RFC 9162 transparency-log inclusion proofs.
The Python and Go verifiers handle v2 receipts and inclusion proofs; they
do not verify ML-DSA-65 yet.

## Get the verifiers

None of these are on npm or PyPI yet. Install them from the repository:

```bash
git clone https://github.com/christiaan839-beep/sovereign-v2
cd sovereign-v2
```

**Python** (3.10 or later):

```bash
pip install ./packages/verifiable-receipts-py
```

```python
from sovereign_matrix.verifiable_receipts import verify_v2_receipt

result = verify_v2_receipt(receipt, open("ed25519.pem", "rb").read())
print(result.ok)
```

**Go** (1.22 or later):

```bash
go get github.com/christiaan839-beep/sovereign-v2/packages/verifiable-receipts-go@latest
```

**TypeScript** (Node 18 or later), from your own project:

```bash
npm install --install-links /path/to/sovereign-v2/packages/verifiable-receipts
```

## Run the tests

```bash
# Python
pip install pytest
python -m pytest packages/verifiable-receipts-py/tests

# Go
(cd packages/verifiable-receipts-go && go test ./...)

# TypeScript: copy the package out of the npm workspace first
cp -r packages/verifiable-receipts /tmp/verifiable-receipts
(cd /tmp/verifiable-receipts && npm install --ignore-scripts && npx --yes vitest@3 run)
```

Measured on 16 October 2026:

| Verifier   | Result                 |
| ---------- | ---------------------- |
| TypeScript | 681 passed, 4 skipped  |
| Python     | 22 passed              |
| Go         | `go test ./...` passes |

All three run against the same 11 conformance fixtures in
`packages/verifiable-receipts/conformance/fixtures/` (valid and tampered
receipts, wrong keys, inclusion proofs) and must agree on each.

## Status

The library is at version 0.3.0 (TypeScript) and 0.1.0 (Python). It is
tested but not yet published to a package registry. The wire format is
written down in
[`SPEC.md`](https://github.com/christiaan839-beep/sovereign-v2/blob/main/packages/verifiable-receipts/SPEC.md).

## License

This repository is Apache-2.0; see [LICENSE](./LICENSE). The code in
sovereign-v2 is licensed per package: the TypeScript library is
Apache-2.0, the Python verifier declares Apache-2.0 in `pyproject.toml`,
and the Go module has no licence file of its own yet.
