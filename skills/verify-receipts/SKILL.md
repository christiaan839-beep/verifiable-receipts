---
name: verify-receipts
description: Checks verifiable receipts (signed records of what an AI agent did) against the issuer's Ed25519 public key and reports, for each receipt, whether it is intact and genuinely signed or why it fails. Use when someone hands over agent receipts, an audit trail or a receipt log with a public key and asks whether they are authentic, tampered with, forged or complete.
license: Apache-2.0
compatibility: Requires Python 3.10+ and the sovereign-matrix-verifiable-receipts package. Runs offline.
metadata:
  author: christiaan839-beep
  homepage: https://github.com/christiaan839-beep/verifiable-receipts
---

# Verify receipts

A receipt is a JSON object whose `canonical` field holds the exact text the issuer signed, with a
`signature` (`v2=` and base64 Ed25519) and usually a `contentHash` (`sha256:` and hex). Verifying
it proves that the holder of the issuer's private key signed exactly that text, and that every
other field in the receipt agrees with it. The format is in
[SPEC.md](https://github.com/christiaan839-beep/verifiable-receipts/blob/main/packages/verifiable-receipts/SPEC.md).

## Steps

1. Get the issuer's public key as a PEM file (`-----BEGIN PUBLIC KEY-----`). Get it from the
   issuer through a channel other than the one the receipts came by. A key that arrives with the
   receipts proves nothing.
2. Install the verifier, once:

   ```bash
   pip install sovereign-matrix-verifiable-receipts
   ```

   If that version is not on PyPI yet, install it from the repository:

   ```bash
   pip install "sovereign-matrix-verifiable-receipts @ git+https://github.com/christiaan839-beep/verifiable-receipts@main#subdirectory=packages/verifiable-receipts-py"
   ```

3. Run the script on the receipt files. Each file holds one receipt as a JSON object, or one
   receipt per line (`.jsonl`):

   ```bash
   python scripts/verify_receipts.py --pubkey issuer.pem receipts/*.json
   ```

4. Read the result. The script prints one JSON line per receipt (`file`, `line`, `ok`, `reason`)
   and a summary on stderr. Exit code 0: every receipt verifies. 1: at least one fails. 2: a
   usage, file or install error, and nothing was judged.
5. Report each failing receipt by file, line and reason, and say what the reasons mean (below).
   Never describe a failing receipt as probably fine.

## Reasons

| Reason contains | Meaning |
|---|---|
| `contentHash mismatch` | The canonical text was changed after the hash was taken: tampered. |
| `signature` | The signature does not match this key and text: forged, tampered or a different issuer. |
| `envelope field ... disagrees` / `is not in the signed canonical` | A field outside the signed text was added or edited. Only the canonical is signed. |
| `base64` | The signature is not canonical padded base64. |
| `v2` | Not a v2 signature (`v3=` receipts need the TypeScript verifier). |
| `nesting deeper than 64` | Rejected as hostile input. |
| `public key is a small-order point` / `not a canonical encoding` | The key is unsafe: every signature or many would verify. Do not trust it. |

## What a pass does not show

- That the content is true. A receipt proves who signed it, not that the agent's work was right.
- That the set is complete. Missing receipts leave no trace in the others; checking that the
  issuer published every receipt needs the transparency log and its inclusion proofs
  (`verify_inclusion_proof` in the same package).
- That the key belongs to whom you think. That depends on step 1.
