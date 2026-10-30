"""
VAOS 2.0 section 7.3, the strict profile: before the signature reaches
``cryptography``, R must be a canonical encoding of a point of order L
(not of small order, the identity included, and in the prime-order
subgroup), S must be below L, and the key must be a point of order L.
Each rejection has its reason, the same in the TypeScript and Go
verifiers.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sovereign_matrix.verifiable_receipts import (
    ed25519_public_key_problem,
    ed25519_signature_problem,
    verify_ed25519,
    verify_v2_receipt,
)
from sovereign_matrix.verifiable_receipts import edwards25519 as ed
from sovereign_matrix.verifiable_receipts.verify import _load_ed25519_public_key

GENERIC = "signature does not verify under the supplied public key"
T8 = ed.decode(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))[0]
T2 = ed.decode(bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))[0]
assert T8 is not None and T2 is not None
A_SCALAR = 0x1234567890ABCDEF1234567890ABCDEF % ed.L
R_SCALAR = 0xFEDCBA0987654321FEDCBA0987654321 % ed.L
PUB = ed.encode(ed.scalar_mult(A_SCALAR, ed.BASE))
MIXED_PUB = ed.encode(ed.point_add(ed.scalar_mult(A_SCALAR, ed.BASE), T8))


def le32(n: int) -> bytes:
    return n.to_bytes(32, "little")


def k_of(r: bytes, pub: bytes, msg: bytes) -> int:
    return int.from_bytes(hashlib.sha512(r + pub + msg).digest(), "little") % ed.L


def pem_of(raw: bytes) -> bytes:
    return Ed25519PublicKey.from_public_bytes(raw).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def receipt(msg: bytes, sig: bytes) -> dict[str, str]:
    return {"canonical": msg.decode(), "signature": "v2=" + base64.b64encode(sig).decode()}


def sig_with_r(r_point: ed.Point, msg: bytes, pub: bytes = PUB, r: int = 0) -> bytes:
    """(R, S = r + k*a) for a chosen R."""
    r_enc = ed.encode(r_point)
    return r_enc + le32((r + k_of(r_enc, pub, msg) * A_SCALAR) % ed.L)


MSG = b'{"a":1}'


def test_an_honest_signature_verifies() -> None:
    sig = sig_with_r(ed.scalar_mult(R_SCALAR, ed.BASE), MSG, r=R_SCALAR)
    assert verify_ed25519(PUB, MSG, sig).ok
    assert verify_v2_receipt(receipt(MSG, sig), pem_of(PUB)).ok


@pytest.mark.parametrize(
    ("name", "r_point", "reason"),
    [
        ("identity", ed.IDENTITY, "signature R is a small-order point"),
        ("order 2", T2, "signature R is a small-order point"),
        ("order 8", T8, "signature R is a small-order point"),
        (
            "mixed order",
            ed.point_add(ed.scalar_mult(R_SCALAR, ed.BASE), T8),
            "signature R is not in the prime-order subgroup",
        ),
    ],
)
def test_r_of_small_or_mixed_order_is_rejected(name: str, r_point: ed.Point, reason: str) -> None:
    r = R_SCALAR if name == "mixed order" else 0
    sig = sig_with_r(r_point, MSG, r=r)
    assert ed25519_signature_problem(sig) == reason
    assert verify_ed25519(PUB, MSG, sig).reason == reason
    assert verify_v2_receipt(receipt(MSG, sig), pem_of(PUB)).reason == reason


def test_r_identity_with_the_cofactorless_equation_holding_is_rejected() -> None:
    # [S]B = R + [k]A with R = O and S = k*a: valid under RFC 8032's
    # cofactorless check, which cryptography accepts.
    sig = sig_with_r(ed.IDENTITY, MSG)
    pub_key = Ed25519PublicKey.from_public_bytes(PUB)
    pub_key.verify(sig, MSG)  # the library alone accepts it
    assert verify_ed25519(PUB, MSG, sig).reason == "signature R is a small-order point"


def test_r_encoding_problems() -> None:
    k = k_of(le32(ed.P + 1), PUB, MSG)
    noncanonical = le32(ed.P + 1) + le32(k * A_SCALAR % ed.L)
    reason = verify_ed25519(PUB, MSG, noncanonical).reason
    assert reason == "signature R is not a canonical encoding"
    sign_bit = bytearray(ed.encode(ed.IDENTITY))
    sign_bit[31] |= 0x80
    assert (
        ed25519_signature_problem(bytes(sign_bit) + bytes(32))
        == "signature R is not a canonical encoding"
    )
    off_curve = le32(2) + le32(R_SCALAR)
    assert verify_ed25519(PUB, MSG, off_curve).reason == "signature R is not a point on the curve"


def test_s_of_l_or_more_is_rejected_before_the_library() -> None:
    sig = sig_with_r(ed.scalar_mult(R_SCALAR, ed.BASE), MSG, r=R_SCALAR)
    s = int.from_bytes(sig[32:], "little")
    for bad in (s + ed.L, ed.L, 2**256 - 1):
        assert ed25519_signature_problem(sig[:32] + bad.to_bytes(32, "little")) == GENERIC
    assert ed25519_signature_problem(sig) is None


@pytest.mark.parametrize("length", [0, 63, 65])
def test_a_signature_that_is_not_64_bytes_is_rejected(length: int) -> None:
    assert ed25519_signature_problem(bytes(length)) == GENERIC
    assert verify_ed25519(PUB, MSG, bytes(length)).reason == GENERIC


def test_r_mixed_order_with_the_cofactorless_equation_holding() -> None:
    # A = [a]B + T8 and R = [r]B + [t]T8 with t + k = 0 mod 8: the
    # cofactorless equation holds. The key rule refuses A first; R alone
    # is refused too.
    for nonce in range(400):
        msg = b'{"n":%d}' % nonce
        for t in range(1, 8):
            r_point = ed.point_add(ed.scalar_mult(R_SCALAR, ed.BASE), ed.scalar_mult(t, T8))
            r_enc = ed.encode(r_point)
            k = k_of(r_enc, MIXED_PUB, msg)
            if (t + k) % 8 == 0:
                sig = r_enc + le32((R_SCALAR + k * A_SCALAR) % ed.L)
                Ed25519PublicKey.from_public_bytes(MIXED_PUB).verify(sig, msg)
                assert verify_ed25519(MIXED_PUB, msg, sig).reason == (
                    "public key is not in the prime-order subgroup"
                )
                assert ed25519_signature_problem(sig) == (
                    "signature R is not in the prime-order subgroup"
                )
                return
    raise AssertionError("no message found")


def test_keys_of_mixed_order_or_off_the_curve_are_refused_when_loaded_and_used() -> None:
    off_curve = le32(2)
    t2_mixed = ed.encode(ed.point_add(ed.scalar_mult(A_SCALAR, ed.BASE), T2))
    for raw, reason in (
        (MIXED_PUB, "public key is not in the prime-order subgroup"),
        (t2_mixed, "public key is not in the prime-order subgroup"),
        (off_curve, "public key is not a point on the curve"),
    ):
        assert ed25519_public_key_problem(raw) == reason
        with pytest.raises(ValueError, match=reason):
            _load_ed25519_public_key(pem_of(raw))
        sig = sig_with_r(ed.scalar_mult(R_SCALAR, ed.BASE), MSG, pub=raw, r=R_SCALAR)
        assert verify_ed25519(raw, MSG, sig).reason == reason
        assert verify_v2_receipt(receipt(MSG, sig), pem_of(raw)).reason == reason


def test_the_existing_key_reasons_stay() -> None:
    assert ed25519_public_key_problem(le32(1)) == "public key is a small-order point"
    assert ed25519_public_key_problem(le32(ed.P + 1)) == "public key is a small-order point"
    assert ed25519_public_key_problem(le32(ed.P + 3)) == "public key is not a canonical encoding"
    assert ed25519_public_key_problem(ed.encode(T8)) == "public key is a small-order point"
    assert ed25519_public_key_problem(PUB) is None
    assert verify_ed25519(PUB[:31], MSG, bytes(64)).reason == "public key is not 32 bytes"


@pytest.mark.parametrize("bad", [32, 64, -1, "not bytes", None, [1, 2], 1.5])
def test_verify_ed25519_refuses_inputs_that_are_not_bytes(bad: object) -> None:
    # bytes(32) would be 32 zero bytes, bytes(-1) and bytes("x") raise: none
    # of them is the caller's key, message or signature.
    sig = sig_with_r(ed.scalar_mult(R_SCALAR, ed.BASE), MSG, r=R_SCALAR)
    for args in ((bad, MSG, sig), (PUB, bad, sig), (PUB, MSG, bad)):
        result = verify_ed25519(*args)  # type: ignore[arg-type]
        assert not result.ok
        assert result.reason == GENERIC


def test_verify_ed25519_takes_bytearray_and_memoryview() -> None:
    sig = sig_with_r(ed.scalar_mult(R_SCALAR, ed.BASE), MSG, r=R_SCALAR)
    assert verify_ed25519(bytearray(PUB), bytearray(MSG), bytearray(sig)).ok
    assert verify_ed25519(memoryview(PUB), memoryview(MSG), memoryview(sig)).ok


# The shared corpus: conformance/fixtures/ed25519-*.json, checked through
# the two public pre-checks. A fixture that fails on its key expects the
# key's reason; any other expects no key problem and, when it fails, the
# signature's reason. The TypeScript and Go tests check the same, and the
# round trip (conformance/roundtrip/) checks that all three languages give
# the same pair of answers on every fixture.
FIXTURES = Path(__file__).resolve().parents[2] / "verifiable-receipts" / "conformance" / "fixtures"
ED25519_FIXTURES = sorted(FIXTURES.glob("ed25519-*.json"))


def key_and_signature(fixture: dict) -> tuple[bytes, bytes]:
    if "ed25519" in fixture:
        vector = fixture["ed25519"]
        return bytes.fromhex(vector["publicKey"]), bytes.fromhex(vector["signature"])
    body = "".join(
        line for line in fixture["publicKeyPem"].splitlines() if not line.startswith("-----")
    )
    raw = base64.b64decode(body)[-32:]  # SPKI: a 12-byte prefix, then the key
    return raw, base64.b64decode(fixture["receipt"]["signature"].removeprefix("v2="))


def test_there_are_20_ed25519_fixtures() -> None:
    assert len(ED25519_FIXTURES) == 20


@pytest.mark.parametrize("path", ED25519_FIXTURES, ids=lambda p: p.stem)
def test_the_public_pre_checks_give_each_fixtures_reason(path: Path) -> None:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    raw, sig = key_and_signature(fixture)
    expected = fixture["expected"].get("reasonContains")
    assert fixture["expected"]["ok"] is (expected is None)
    if expected is not None and expected.startswith("public key "):
        assert ed25519_public_key_problem(raw) == expected
    else:
        assert ed25519_public_key_problem(raw) is None
        assert ed25519_signature_problem(sig) == expected
    # The same answers as verify_ed25519, which calls them.
    first = ed25519_public_key_problem(raw) or ed25519_signature_problem(sig)
    if first is not None:
        assert verify_ed25519(raw, b"", sig).reason == first


@pytest.mark.parametrize(
    "bad", [32, 64, -1, "x" * 32, "x" * 64, None, [1, 2], 1.5, {"key": b"x"}]
)
def test_the_public_pre_checks_refuse_inputs_that_are_not_bytes(bad: object) -> None:
    # As verify_ed25519 does: the generic reason, never an exception.
    assert ed25519_public_key_problem(bad) == GENERIC  # type: ignore[arg-type]
    assert ed25519_signature_problem(bad) == GENERIC  # type: ignore[arg-type]


def test_the_public_pre_checks_take_bytearray_and_memoryview() -> None:
    sig = sig_with_r(ed.scalar_mult(R_SCALAR, ed.BASE), MSG, r=R_SCALAR)
    small = ed.encode(T8)
    for wrap in (bytes, bytearray, memoryview):
        assert ed25519_public_key_problem(wrap(PUB)) is None
        assert ed25519_public_key_problem(wrap(small)) == "public key is a small-order point"
        assert ed25519_public_key_problem(wrap(PUB[:31])) == "public key is not 32 bytes"
        assert ed25519_signature_problem(wrap(sig)) is None
        assert ed25519_signature_problem(wrap(small + sig[32:])) == (
            "signature R is a small-order point"
        )
        assert ed25519_signature_problem(wrap(sig[:63])) == GENERIC
