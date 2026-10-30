"""
Point arithmetic on edwards25519 (RFC 8032), for the strict Ed25519
checks of VAOS 2.0 section 7.3.

Pure Python integers, written for correctness, not speed or constant
time: every input it sees (a public key, a signature's R) is public.
The TypeScript (``src/edwards25519.ts``, ``conformance/verify-v2.mjs``)
and Go (``edwards25519.go``) verifiers carry the same code with the same
constants.

Points are in extended coordinates (X, Y, Z, T), with x = X/Z, y = Y/Z
and x*y = T/Z, and are added with the formulas of RFC 8032 section
5.1.4, which are complete on this curve: they also double, and they
take the identity and points of small order.
"""

from __future__ import annotations

from typing import NamedTuple

# The field prime, the group order L and the curve constant d (RFC 8032 5.1).
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
# A square root of -1 mod p.
SQRT_M1 = pow(2, (P - 1) // 4, P)

# Why an encoding is refused; the verifiers prefix "public key is " or
# "signature R is ".
NOT_CANONICAL = "not a canonical encoding"
NOT_ON_CURVE = "not a point on the curve"
SMALL_ORDER = "a small-order point"
NOT_IN_SUBGROUP = "not in the prime-order subgroup"


class Point(NamedTuple):
    """A point in extended coordinates."""

    X: int
    Y: int
    Z: int
    T: int


IDENTITY = Point(0, 1, 1, 0)


def point_add(p: Point, q: Point) -> Point:
    """p + q (RFC 8032 section 5.1.4); also p + p."""
    a = (p.Y - p.X) * (q.Y - q.X) % P
    b = (p.Y + p.X) * (q.Y + q.X) % P
    c = 2 * p.T * q.T * D % P
    d = 2 * p.Z * q.Z % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return Point(e * f % P, g * h % P, f * g % P, e * h % P)


def scalar_mult(k: int, p: Point) -> Point:
    """[k]p for k >= 0, by double-and-add from the top bit."""
    q = IDENTITY
    for bit in bin(k)[2:] if k > 0 else "":
        q = point_add(q, q)
        if bit == "1":
            q = point_add(q, p)
    return q


def is_identity(p: Point) -> bool:
    """Whether p is the identity (0, 1)."""
    return p.X % P == 0 and (p.Y - p.Z) % P == 0


def points_equal(p: Point, q: Point) -> bool:
    """Whether p and q are the same point (x1/z1 = x2/z2 and y1/z1 = y2/z2)."""
    return (p.X * q.Z - q.X * p.Z) % P == 0 and (p.Y * q.Z - q.Y * p.Z) % P == 0


def is_on_curve(p: Point) -> bool:
    """Whether p satisfies -x^2 + y^2 = 1 + d x^2 y^2, with x*y = T/Z."""
    x2, y2, z2 = p.X * p.X % P, p.Y * p.Y % P, p.Z * p.Z % P
    return (y2 - x2 - z2 - D * p.T * p.T) % P == 0 and (p.X * p.Y - p.Z * p.T) % P == 0


def _x_squared(y: int) -> int:
    """x^2 = (y^2 - 1) / (d y^2 + 1) for a point with this y."""
    return (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P


def _recover_x(x2: int, sign: int) -> int | None:
    """The x with x^2 = x2 and this sign (RFC 8032 section 5.1.3), or None."""
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    return P - x if x & 1 != sign else x


BASE_Y = 4 * pow(5, P - 2, P) % P
_BASE_X = _recover_x(_x_squared(BASE_Y), 0)
assert _BASE_X is not None
BASE = Point(_BASE_X, BASE_Y, 1, _BASE_X * BASE_Y % P)


def decode(data: bytes) -> tuple[Point | None, str | None]:
    """Decode a 32-byte encoding (RFC 8032 section 5.1.3).

    Returns (point, None), or (None, NOT_CANONICAL) for a y of p or
    more, x = 0 with the sign bit set or a length other than 32, or
    (None, NOT_ON_CURVE) for a y with no x on the curve.
    """
    if len(data) != 32:
        return None, NOT_CANONICAL
    n = int.from_bytes(data, "little")
    y, sign = n & ((1 << 255) - 1), n >> 255
    if y >= P:
        return None, NOT_CANONICAL
    x2 = _x_squared(y)
    if x2 == 0 and sign:
        return None, NOT_CANONICAL
    x = _recover_x(x2, sign)
    if x is None:
        return None, NOT_ON_CURVE
    return Point(x, y, 1, x * y % P), None


def encode(p: Point) -> bytes:
    """The canonical 32-byte encoding of p (RFC 8032 section 5.1.2)."""
    zi = pow(p.Z, P - 2, P)
    x, y = p.X * zi % P, p.Y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def has_small_order(p: Point) -> bool:
    """Whether [8]p is the identity: p is one of the 8 points of small order."""
    return is_identity(scalar_mult(8, p))


def in_prime_order_subgroup(p: Point) -> bool:
    """Whether [L]p is the identity: p has no small-order component."""
    return is_identity(scalar_mult(L, p))


def point_problem(data: bytes) -> str | None:
    """Why an encoding is not a point of order L, or None.

    In order: NOT_CANONICAL, NOT_ON_CURVE, SMALL_ORDER (the identity
    included), NOT_IN_SUBGROUP (a mixed-order point).
    """
    point, problem = decode(data)
    if point is None:
        return problem
    if has_small_order(point):
        return SMALL_ORDER
    if not in_prime_order_subgroup(point):
        return NOT_IN_SUBGROUP
    return None
