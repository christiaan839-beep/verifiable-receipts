"""
Python signer and verifier for VAOS 2.0 receipts (Ed25519), and a
verifier for RFC 9162 transparency-log inclusion proofs.

The verifier checks the receipt's ``canonical`` string as given: its
``contentHash``, its Ed25519 signature, and that every other top-level
field of the receipt equals the same field in the parsed canonical. It
does not re-derive ``canonical`` from the other fields. The signer
builds ``canonical`` with keys sorted at every depth and refuses floats.

Public API:
    canonicalize(body) -> str
    sign_v2_receipt(body, private_key) -> dict
    verify_v2_receipt(receipt, public_key_pem) -> VerifyResult
    verify_guardian_attestation(attestation, public_key_pem) -> VerifyResult
    parse_receipt(text) -> dict
    verify_inclusion_proof(proof, leaf_hash_hex, root_hash_hex) -> bool
    leaf_hash(data) -> bytes, inner_hash(left, right) -> bytes
"""

from .sign import (
    canonicalize,
    sign_v2_receipt,
)
from .transparency import (
    inner_hash,
    leaf_hash,
    verify_inclusion_proof,
)
from .verify import (
    VerifyResult,
    parse_receipt,
    verify_guardian_attestation,
    verify_v2_receipt,
)

__all__ = [
    "VerifyResult",
    "canonicalize",
    "sign_v2_receipt",
    "verify_v2_receipt",
    "parse_receipt",
    "verify_guardian_attestation",
    "verify_inclusion_proof",
    "leaf_hash",
    "inner_hash",
]

__version__ = "0.2.1"
