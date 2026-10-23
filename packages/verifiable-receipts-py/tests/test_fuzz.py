"""
Property tests for the v2 receipt verifier and the inclusion-proof
verifier, run with Hypothesis. See conftest.py for the profiles.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from hypothesis import assume, given
from hypothesis import strategies as st
from sovereign_matrix.verifiable_receipts import (
    inner_hash,
    leaf_hash,
    verify_guardian_attestation,
    verify_inclusion_proof,
    verify_v2_receipt,
)

_CONFORMANCE = Path(__file__).resolve().parents[2] / "verifiable-receipts" / "conformance"
_FIXTURE_PEM = (_CONFORMANCE / "public-key.pem").read_bytes()
_FIXTURE_RECEIPTS = [
    json.loads(path.read_text("utf-8"))["receipt"]
    for path in sorted((_CONFORMANCE / "fixtures").glob("v2-*.json"))
]

# A key from a fixed seed, so a failing example replays.
_PRIV = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"verifiable-receipts fuzz key").digest()
)
_PEM = _PRIV.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
_OTHER_PEM = (
    Ed25519PrivateKey.generate()
    .public_key()
    .public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
)

_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _raw_sig(canonical: str) -> bytes:
    return _PRIV.sign(canonical.encode("utf-8"))


def _sign_v2(canonical: str) -> str:
    return "v2=" + base64.b64encode(_raw_sig(canonical)).decode("ascii")


def _content_hash(canonical: str) -> str:
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _signed_receipt(body: str, with_hash: bool) -> dict[str, Any]:
    canonical = json.dumps({"body": body}, separators=(",", ":"))
    receipt: dict[str, Any] = {"canonical": canonical, "signature": _sign_v2(canonical)}
    if with_hash:
        receipt["contentHash"] = _content_hash(canonical)
    return receipt


def _replace_at(s: str, i: int, c: str) -> str:
    return s[:i] + c + s[i + 1 :]


def _accepted(receipt: Any, pem: bytes) -> bool:
    result = verify_v2_receipt(receipt, pem)
    if not result.ok:
        assert isinstance(result.reason, str) and result.reason
    return result.ok


_json = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(), children, max_size=4)
    ),
    max_leaves=12,
)
_canonical = (
    st.text()
    | _json.map(json.dumps)
    | st.dictionaries(st.text(), _json, max_size=4).map(json.dumps)
)
_pem = st.sampled_from([_PEM, _FIXTURE_PEM, _OTHER_PEM])


@st.composite
def _receipts(draw: st.DrawFn) -> dict[str, Any]:
    receipt: dict[str, Any] = draw(st.dictionaries(st.text(), _json, max_size=3))
    canonical = draw(_canonical | _json)
    receipt["canonical"] = canonical
    signer = draw(st.sampled_from(["none", "fuzz", "garbage"]))
    if signer == "fuzz" and isinstance(canonical, str):
        try:
            receipt["signature"] = _sign_v2(canonical)
        except UnicodeEncodeError:
            pass
    elif signer == "garbage":
        receipt["signature"] = draw(st.text() | _json)
    hash_kind = draw(st.sampled_from(["none", "real", "garbage"]))
    if hash_kind == "real" and isinstance(canonical, str):
        try:
            receipt["contentHash"] = _content_hash(canonical)
        except UnicodeEncodeError:
            pass
    elif hash_kind == "garbage":
        receipt["contentHash"] = draw(st.text() | _json)
    return receipt


class TestVerifyV2ReceiptArbitraryInput:
    @given(receipt=_json | _receipts(), pem=_pem | st.binary())
    def test_never_raises(self, receipt: Any, pem: bytes) -> None:
        _accepted(receipt, pem)
        assert isinstance(verify_guardian_attestation(receipt, pem).ok, bool)

    @given(receipt=_receipts() | st.sampled_from(_FIXTURE_RECEIPTS), pem=_pem)
    def test_accepts_only_the_exact_signature(self, receipt: dict[str, Any], pem: bytes) -> None:
        if not _accepted(receipt, pem):
            return
        if pem == _PEM:
            assert receipt["signature"] == _sign_v2(receipt["canonical"])
        else:
            assert pem == _FIXTURE_PEM
            assert any(r["signature"] == receipt["signature"] for r in _FIXTURE_RECEIPTS)


class TestVerifyV2ReceiptMutations:
    @given(
        body=st.text(),
        with_hash=st.booleans(),
        pos=st.integers(min_value=0),
        c=st.sampled_from(_B64 + "=-_ .\n\r\t"),
    )
    def test_rejects_a_changed_signature_character(
        self, body: str, with_hash: bool, pos: int, c: str
    ) -> None:
        receipt = _signed_receipt(body, with_hash)
        assert _accepted(receipt, _PEM)
        sig = receipt["signature"]
        i = pos % len(sig)
        assume(sig[i] != c)
        assert not _accepted({**receipt, "signature": _replace_at(sig, i, c)}, _PEM)

    @given(
        body=st.text(),
        with_hash=st.booleans(),
        pos=st.integers(min_value=0, max_value=63),
        flip=st.integers(min_value=1, max_value=255),
    )
    def test_rejects_a_changed_signature_byte(
        self, body: str, with_hash: bool, pos: int, flip: int
    ) -> None:
        receipt = _signed_receipt(body, with_hash)
        sig = bytearray(_raw_sig(receipt["canonical"]))
        sig[pos] ^= flip
        signature = "v2=" + base64.b64encode(bytes(sig)).decode("ascii")
        assert not _accepted({**receipt, "signature": signature}, _PEM)

    @given(
        body=st.text(),
        with_hash=st.booleans(),
        pos=st.integers(min_value=0),
        c=st.characters(),
    )
    def test_rejects_a_changed_canonical_character(
        self, body: str, with_hash: bool, pos: int, c: str
    ) -> None:
        receipt = _signed_receipt(body, with_hash)
        canonical = receipt["canonical"]
        i = pos % len(canonical)
        assume(canonical[i] != c)
        assert not _accepted({**receipt, "canonical": _replace_at(canonical, i, c)}, _PEM)

    @given(
        body=st.text(),
        pad_bits=st.integers(min_value=1, max_value=15),
        pos=st.integers(min_value=0),
        junk=st.sampled_from([" ", "\n", "\r\n", "\t", "="]),
    )
    def test_rejects_non_canonical_base64_spellings(
        self, body: str, pad_bits: int, pos: int, junk: str
    ) -> None:
        receipt = _signed_receipt(body, True)
        b64 = receipt["signature"][3:]
        # 64 bytes: the last group is two characters and "==".
        last = len(b64) - 3
        i = pos % len(b64)
        spellings = [
            _replace_at(b64, last, _B64[_B64.index(b64[last]) | pad_bits]),
            b64[:-1],
            b64[:-2],
            b64 + "=",
            b64.replace("+", "-").replace("/", "_"),
            b64[:i] + junk + b64[i:],
            junk + b64,
            b64 + junk,
        ]
        for s in spellings:
            if s != b64:
                assert not _accepted({**receipt, "signature": "v2=" + s}, _PEM)
        assert not _accepted({**receipt, "signature": "V2=" + b64}, _PEM)


def _tree_root(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return inner_hash(_tree_root(leaves[:k]), _tree_root(leaves[k:]))


def _audit_path(idx: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) == 1:
        return []
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    if idx < k:
        return _audit_path(idx, leaves[:k]) + [_tree_root(leaves[k:])]
    return _audit_path(idx - k, leaves[k:]) + [_tree_root(leaves[:k])]


_hex32 = st.binary(min_size=32, max_size=32).map(bytes.hex)
_size = (
    st.integers(min_value=-4, max_value=70)
    | st.integers()
    | st.floats()
    | st.text()
    | st.none()
    | st.booleans()
)


class TestVerifyInclusionProof:
    @given(
        leaf=_hex32 | st.text(),
        leaf_index=_size,
        tree_size=_size,
        audit_path=st.lists(_hex32 | st.text() | _json, max_size=40) | _json,
        root=_hex32 | st.text(),
    )
    def test_never_raises(
        self, leaf: str, leaf_index: Any, tree_size: Any, audit_path: Any, root: str
    ) -> None:
        proof = {"leafIndex": leaf_index, "treeSize": tree_size, "auditPath": audit_path}
        ok = verify_inclusion_proof(proof, leaf, root)
        assert isinstance(ok, bool)
        if ok:
            assert not verify_inclusion_proof(proof, leaf, root + "00")
            # What passes is integer values and 64 lowercase hex digits.
            for n in (leaf_index, tree_size):
                assert type(n) in (int, float) and float(n).is_integer()
            for h in [leaf, root, *audit_path]:
                assert isinstance(h, str) and re.fullmatch(r"[0-9a-f]{64}", h)

    @given(
        n=st.integers(min_value=1, max_value=64),
        salt=st.binary(max_size=8),
        pick=st.integers(min_value=0),
        wrong_root=_hex32,
        entry=st.integers(min_value=0),
    )
    def test_verifies_a_real_proof_and_rejects_a_wrong_root(
        self, n: int, salt: bytes, pick: int, wrong_root: str, entry: int
    ) -> None:
        leaves = [leaf_hash(salt + i.to_bytes(2, "big")) for i in range(n)]
        idx = pick % n
        root = _tree_root(leaves).hex()
        path = [h.hex() for h in _audit_path(idx, leaves)]
        proof = {"leafIndex": idx, "treeSize": n, "auditPath": path}
        assert verify_inclusion_proof(proof, leaves[idx].hex(), root)
        if wrong_root != root:
            assert not verify_inclusion_proof(proof, leaves[idx].hex(), wrong_root)
        if path:
            j = entry % len(path)
            assume(path[j] != wrong_root)
            tampered = {**proof, "auditPath": [*path[:j], wrong_root, *path[j + 1 :]]}
            assert not verify_inclusion_proof(tampered, leaves[idx].hex(), root)
