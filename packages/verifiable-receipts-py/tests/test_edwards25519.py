"""
The pure edwards25519 arithmetic behind the strict Ed25519 checks of
VAOS 2.0 section 7.3: its constants against RFC 8032, decoding and
encoding, and the order of points.
"""

from __future__ import annotations

import hashlib
import random

import pytest
from sovereign_matrix.verifiable_receipts import edwards25519 as ed

# RFC 8032 section 5.1: the encoding of the base point B, and L.
BASE_HEX = "5866666666666666666666666666666666666666666666666666666666666666"
L_DECIMAL = 7237005577332262213973186563042994240857116359379907606001950938285454250989
# The encodings of the points of small order (sign bit clear), with their order.
TORSION = {
    "0100000000000000000000000000000000000000000000000000000000000000": 1,
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": 2,
    "0000000000000000000000000000000000000000000000000000000000000000": 4,
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05": 8,
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a": 8,
}
T8_HEX = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"


def order(point: ed.Point) -> int:
    """The order of a point of small order (1, 2, 4 or 8)."""
    for n in (1, 2, 4, 8):
        if ed.is_identity(ed.scalar_mult(n, point)):
            return n
    raise AssertionError("not of small order")


def from_y(y: int, sign: int = 0) -> bytes:
    return (y | (sign << 255)).to_bytes(32, "little")


def test_constants_match_rfc_8032() -> None:
    assert ed.P == 2**255 - 19
    assert ed.L == L_DECIMAL == 2**252 + 27742317777372353535851937790883648493
    assert ed.D == (-121665 * pow(121666, -1, ed.P)) % ed.P
    assert ed.D == 37095705934669439343138083508754565189542113879843219016388785533085940283555
    assert ed.SQRT_M1 * ed.SQRT_M1 % ed.P == ed.P - 1
    assert ed.BASE_Y == 4 * pow(5, -1, ed.P) % ed.P
    assert ed.encode(ed.BASE).hex() == BASE_HEX


def test_base_point_has_order_l() -> None:
    assert ed.is_on_curve(ed.BASE)
    assert not ed.is_identity(ed.BASE)
    assert ed.is_identity(ed.scalar_mult(ed.L, ed.BASE))
    assert not ed.is_identity(ed.scalar_mult(ed.L - 1, ed.BASE))
    assert ed.encode(ed.scalar_mult(ed.L + 1, ed.BASE)) == ed.encode(ed.BASE)


@pytest.mark.parametrize("hex_", sorted(TORSION))
def test_torsion_points_have_small_order(hex_: str) -> None:
    point, problem = ed.decode(bytes.fromhex(hex_))
    assert problem is None and point is not None
    assert order(point) == TORSION[hex_]
    assert ed.is_identity(ed.scalar_mult(8, point))
    assert ed.has_small_order(point)
    assert ed.in_prime_order_subgroup(point) == (TORSION[hex_] == 1)


def test_rfc_8032_test_1_public_key() -> None:
    # RFC 8032 section 7.1, TEST 1: the secret key and its public key.
    secret = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    public = ed.encode(ed.scalar_mult(a, ed.BASE))
    assert public.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def test_encode_decode_round_trip() -> None:
    rng = random.Random(25519)
    for _ in range(64):
        point = ed.scalar_mult(rng.randrange(1, ed.L), ed.BASE)
        data = ed.encode(point)
        decoded, problem = ed.decode(data)
        assert problem is None and decoded is not None
        assert ed.encode(decoded) == data
        assert ed.points_equal(decoded, point)
        assert ed.in_prime_order_subgroup(decoded)
        assert not ed.has_small_order(decoded)


def test_mixed_order_points_are_not_in_the_subgroup() -> None:
    t8, _ = ed.decode(bytes.fromhex(T8_HEX))
    assert t8 is not None
    mixed = ed.point_add(ed.scalar_mult(12345, ed.BASE), t8)
    assert not ed.has_small_order(mixed)
    assert not ed.in_prime_order_subgroup(mixed)
    # [8] clears the small-order component.
    assert ed.in_prime_order_subgroup(ed.scalar_mult(8, mixed))


def test_decode_refuses_non_canonical_encodings() -> None:
    # y = p and y = p + 1: the non-canonical encodings of y = 0 and y = 1.
    assert ed.decode(from_y(ed.P)) == (None, ed.NOT_CANONICAL)
    assert ed.decode(from_y(ed.P + 1)) == (None, ed.NOT_CANONICAL)
    assert ed.decode(from_y(2**255 - 1)) == (None, ed.NOT_CANONICAL)
    # x = 0 with the sign bit set: y = 1 and y = p - 1.
    assert ed.decode(from_y(1, 1)) == (None, ed.NOT_CANONICAL)
    assert ed.decode(from_y(ed.P - 1, 1)) == (None, ed.NOT_CANONICAL)
    # The same y with the sign bit clear decodes.
    assert ed.decode(from_y(1))[1] is None
    assert ed.decode(from_y(ed.P - 1))[1] is None


def test_decode_refuses_points_off_the_curve() -> None:
    # y = 2 has no x on the curve; neither do about half of all y.
    assert ed.decode(from_y(2)) == (None, ed.NOT_ON_CURVE)
    rng = random.Random(7)
    off = 0
    for _ in range(200):
        point, problem = ed.decode(from_y(rng.randrange(ed.P)))
        if problem == ed.NOT_ON_CURVE:
            off += 1
        else:
            assert problem is None and point is not None and ed.is_on_curve(point)
    assert 60 < off < 140


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_decode_refuses_wrong_lengths(length: int) -> None:
    assert ed.decode(bytes(length)) == (None, ed.NOT_CANONICAL)


def test_point_problem() -> None:
    assert ed.point_problem(bytes.fromhex(BASE_HEX)) is None
    for hex_ in TORSION:
        assert ed.point_problem(bytes.fromhex(hex_)) == ed.SMALL_ORDER
    t8, _ = ed.decode(bytes.fromhex(T8_HEX))
    assert t8 is not None
    assert ed.point_problem(ed.encode(ed.point_add(ed.BASE, t8))) == ed.NOT_IN_SUBGROUP
    assert ed.point_problem(from_y(2)) == ed.NOT_ON_CURVE
    assert ed.point_problem(from_y(ed.P + 1)) == ed.NOT_CANONICAL
