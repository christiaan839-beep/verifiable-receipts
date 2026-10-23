"""
RFC 9162 transparency-log inclusion-proof verifier (Python port).

Mirror of `verifyInclusionProof()` from the TypeScript package's
transparency.ts. The math is the contract — Python re-derives the
Merkle path by hashing leaf → audit-path → root and compares to the
published Signed Tree Head's rootHash.

Hash domain separation per RFC 9162 §2:
    leaf_hash(data) = SHA-256(0x00 || data)
    inner_hash(left, right) = SHA-256(0x01 || left || right)

Every hash input is 32 bytes written as exactly 64 lowercase hex digits;
anything else (uppercase, a 0x or sha256: prefix, another length) is
rejected, so a hash has one spelling.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping

_LEAF_PREFIX = b"\x00"
_INNER_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    """RFC 9162 leaf-hash: SHA-256(0x00 || data)."""
    h = hashlib.sha256()
    h.update(_LEAF_PREFIX)
    h.update(data)
    return h.digest()


def inner_hash(left: bytes, right: bytes) -> bytes:
    """RFC 9162 inner-hash: SHA-256(0x01 || left || right)."""
    h = hashlib.sha256()
    h.update(_INNER_PREFIX)
    h.update(left)
    h.update(right)
    return h.digest()


_HASH_HEX = re.compile(r"[0-9a-f]{64}")
# The largest leaf index or tree size accepted, 2**53 - 1: the integers a
# double holds exactly, so every verifier (JavaScript's too) reads the same.
_MAX_COUNT = 2**53 - 1


def _count(x: object) -> int | None:
    """A leaf index or tree size: an integer value (1 and 1.0 alike), or None.

    JSON numbers are values, so 284.0 is the integer 284; a fraction, a
    bool, a string or an infinity is not a count.
    """
    if type(x) is int:
        return x
    if type(x) is float and x.is_integer():
        return int(x)
    return None


def _hash_bytes(hex_str: object) -> bytes | None:
    """Decode a wire hash (64 lowercase hex digits) to 32 bytes, or None."""
    if not isinstance(hex_str, str) or _HASH_HEX.fullmatch(hex_str) is None:
        return None
    return bytes.fromhex(hex_str)


def verify_inclusion_proof(
    proof: Mapping[str, object],
    leaf_hash_hex: str,
    root_hash_hex: str,
) -> bool:
    """Verify an RFC 9162-style inclusion proof.

    Args:
        proof: A dict-like with:
            - ``leafIndex`` (int): 0-based index of the leaf in the tree
            - ``treeSize`` (int): total number of leaves in the tree
            - ``auditPath`` (list[str]): hex-encoded sibling hashes, leaf→root order
        leaf_hash_hex: SHA-256(0x00 || leaf_data) for the leaf you're proving.
        root_hash_hex: The Signed Tree Head's rootHash, hex-encoded.

    Returns:
        True iff hashing leaf_hash with the audit-path siblings in
        the algorithm RFC 9162 §2.1.1 yields exactly root_hash_hex.

    Notes:
        - leafIndex and treeSize must be integer values (1 and 1.0 alike;
          not fractions, bools or strings), with 0 <= leafIndex < treeSize
          <= 2**53 - 1
        - every hash must be 64 lowercase hex digits
        - The number of audit-path siblings is determined by the path
          from the leaf to the root; mismatches return False rather
          than raising.
    """
    leaf_index = _count(proof.get("leafIndex"))
    tree_size = _count(proof.get("treeSize"))
    if leaf_index is None or tree_size is None:
        return False

    audit_path = proof.get("auditPath")
    if not isinstance(audit_path, list):
        return False

    if tree_size <= 0 or tree_size > _MAX_COUNT:
        return False
    if leaf_index < 0 or leaf_index >= tree_size:
        return False

    current = _hash_bytes(leaf_hash_hex)
    expected_root = _hash_bytes(root_hash_hex)
    if current is None or expected_root is None:
        return False

    # Single-leaf tree: root equals leaf, no audit path.
    if tree_size == 1:
        return len(audit_path) == 0 and current == expected_root

    # RFC 9162 / RFC 6962 §2.1.1 inner/border decomposition. The
    # simpler index%2 walk fails on right-edge carry-up cases (e.g.
    # idx=6 in a 7-leaf tree); the bit-decomposition handles every
    # tree shape correctly. Matches the TypeScript canonical verifier.
    inner = (leaf_index ^ (tree_size - 1)).bit_length()
    border = bin(leaf_index >> inner).count("1")
    if len(audit_path) != inner + border:
        return False

    # Pre-decode every audit-path entry; reject any malformed entry.
    siblings: list[bytes] = []
    for sibling_hex in audit_path:
        sibling = _hash_bytes(sibling_hex)
        if sibling is None:
            return False
        siblings.append(sibling)

    # Inner segment: walk the bits of leaf_index. Bit=0 → sibling on
    # the right; bit=1 → sibling on the left.
    for i in range(inner):
        sib = siblings[i]
        if (leaf_index >> i) & 1 == 0:
            current = inner_hash(current, sib)
        else:
            current = inner_hash(sib, current)

    # Border segment: every remaining sibling combines on the LEFT
    # (these are left-children we skipped while walking up the right
    # edge).
    for i in range(border):
        current = inner_hash(siblings[inner + i], current)

    return current == expected_root
