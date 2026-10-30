"""
Writes the Ed25519 edge fixtures of VAOS 2.0 section 7.3 (the strict
profile): fixtures/ed25519-*.json.

Usage (from the root of a clone):
    PYTHONPATH=packages/verifiable-receipts-py \
        python packages/verifiable-receipts/conformance/generate-ed25519-fixtures.py

Each edge fixture is a v2 receipt fixture with its own key
(``publicKeyPem``), whose ``canonical`` is a small JSON object and whose
signature (R, S) is built point by point with the pure edwards25519
arithmetic the Python verifier uses
(``sovereign_matrix/verifiable_receipts/edwards25519.py``): small-order
and mixed-order R and A, non-canonical R, points off the curve, S + L.
Where a fixture needs the hash k = SHA-512(R || A || M) mod L to fall in
a residue class mod 8 (so that the cofactorless equation holds, or only
the cofactored one), the canonical carries a ``nonce`` that is counted
up until it does.

The three RFC 8032 test vectors (section 7.1, TEST 1 to 3), whose
messages are not JSON objects (TEST 1's is empty, TEST 3's is not
UTF-8), are fixtures of their own kind: ``ed25519`` holds the public
key, message and signature as hex, and each harness checks them with
its language's strict Ed25519 verification (TypeScript
``verifyEd25519Strict`` in verify-v2.mjs, Python ``verify_ed25519``, Go
``VerifyEd25519``). The generator also signs those three messages with
its own arithmetic and checks it gets RFC 8032's signatures.

The secrets are derived from fixed labels, so a run rewrites the same
bytes. Each fixture's description says what it is and what the
verifiers did before the strict profile (30 October 2026).
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SDK_DIR = HERE.parent.parent / "verifiable-receipts-py"
if str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from sovereign_matrix.verifiable_receipts import edwards25519 as ed  # noqa: E402

FIXTURES = HERE / "fixtures"
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
GENERIC = "signature does not verify under the supplied public key"

T2 = ed.decode(bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))[0]
T4 = ed.decode(bytes(32))[0]
T8 = ed.decode(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))[0]
assert T2 is not None and T4 is not None and T8 is not None


def scalar(label: str) -> int:
    """A secret scalar in [1, L) derived from a label."""
    h = hashlib.sha512(f"verifiable-receipts ed25519 fixture {label}".encode()).digest()
    return int.from_bytes(h, "little") % (ed.L - 1) + 1


def le32(n: int) -> bytes:
    return n.to_bytes(32, "little")


def challenge(r: bytes, a: bytes, msg: bytes) -> int:
    """k = SHA-512(R || A || M) as a little-endian integer, mod L."""
    return int.from_bytes(hashlib.sha512(r + a + msg).digest(), "little") % ed.L


def pem(raw: bytes) -> str:
    b64 = base64.b64encode(SPKI_PREFIX + raw).decode()
    return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----\n"


def canonical(name: str, nonce: int) -> str:
    return json.dumps({"nonce": nonce, "vector": name}, separators=(",", ":"), sort_keys=True)


def search(name: str, a: bytes, r_of: object, want: object) -> tuple[str, bytes, int]:
    """The first nonce whose canonical gives k with want(k, R) true.

    r_of(nonce) gives R's encoding; returns the canonical, R and k.
    """
    for nonce in range(10_000):
        text = canonical(name, nonce)
        r = r_of(nonce)  # type: ignore[operator]
        k = challenge(r, a, text.encode())
        if want(k, r):  # type: ignore[operator]
            return text, r, k
    raise AssertionError(f"{name}: no nonce found")


def write(
    name: str, description: str, pub: bytes, text: str, sig: bytes, reason: str | None
) -> None:
    expected: dict[str, object] = {"ok": reason is None}
    if reason is not None:
        expected["reasonContains"] = reason
    fixture = {
        "description": description,
        "publicKeyPem": pem(pub),
        "receipt": {
            "canonical": text,
            "contentHash": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
            "signature": "v2=" + base64.b64encode(sig).decode(),
        },
        "expected": expected,
    }
    (FIXTURES / f"ed25519-{name}.json").write_text(json.dumps(fixture, indent=2) + "\n")


def cofactorless(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """[S]B = R + [k]A, with R and A as given (for the descriptions' claims)."""
    a_pt, _ = ed.decode(pub)
    r_pt, _ = ed.decode(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if a_pt is None or r_pt is None or s >= ed.L:
        return False
    k = challenge(sig[:32], pub, msg)
    return ed.points_equal(ed.scalar_mult(s, ed.BASE), ed.point_add(r_pt, ed.scalar_mult(k, a_pt)))


def cofactored(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """[8][S]B = [8]R + [8][k]A."""
    a_pt, _ = ed.decode(pub)
    r_pt, _ = ed.decode(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if a_pt is None or r_pt is None or s >= ed.L:
        return False
    k = challenge(sig[:32], pub, msg)
    lhs = ed.scalar_mult(8 * s, ed.BASE)
    rhs = ed.scalar_mult(8, ed.point_add(r_pt, ed.scalar_mult(k, a_pt)))
    return ed.points_equal(lhs, rhs)


def edge(
    name: str,
    what: str,
    before: str,
    pub: bytes,
    text: str,
    sig: bytes,
    reason: str | None,
    equations: tuple[bool, bool],
) -> None:
    """Write one edge fixture, checking which equations hold as claimed."""
    msg = text.encode()
    assert (cofactorless(pub, msg, sig), cofactored(pub, msg, sig)) == equations, name
    holds = {
        (True, True): "the cofactorless and cofactored equations both hold",
        (False, True): "only the cofactored equation holds",
        (False, False): "neither equation holds",
    }[equations]
    verdict = "valid" if reason is None else "invalid"
    write(
        name,
        f"v2 {verdict} (strict Ed25519) — {what}; {holds}. Before: {before}",
        pub,
        text,
        sig,
        reason,
    )


def rfc8032() -> None:
    """RFC 8032 section 7.1, TEST 1 to 3, as ed25519 fixtures."""
    tests = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ]
    for i, (secret, public, message, signature) in enumerate(tests, start=1):
        h = hashlib.sha512(bytes.fromhex(secret)).digest()
        a = int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | (1 << 254)
        pub = ed.encode(ed.scalar_mult(a, ed.BASE))
        assert pub.hex() == public, f"TEST {i}: public key"
        msg = bytes.fromhex(message)
        r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % ed.L
        big_r = ed.encode(ed.scalar_mult(r, ed.BASE))
        s = (r + challenge(big_r, pub, msg) * a) % ed.L
        assert (big_r + le32(s)).hex() == signature, f"TEST {i}: signature"
        fixture = {
            "description": f"ed25519 valid — RFC 8032 section 7.1, TEST {i}",
            "ed25519": {"publicKey": public, "message": message, "signature": signature},
            "expected": {"ok": True},
        }
        (FIXTURES / f"ed25519-rfc8032-test-{i}.json").write_text(
            json.dumps(fixture, indent=2) + "\n"
        )


def main() -> int:
    # An ordinary key A = [a]B and an ordinary nonce point.
    a = scalar("a")
    pub = ed.encode(ed.scalar_mult(a, ed.BASE))
    r = scalar("r")
    big_r = ed.encode(ed.scalar_mult(r, ed.BASE))

    text = canonical("honest", 0)
    k = challenge(big_r, pub, text.encode())
    s = (r + k * a) % ed.L
    edge(
        "honest",
        "an honest signature under an ordinary key",
        "valid everywhere",
        pub,
        text,
        big_r + le32(s),
        None,
        (True, True),
    )

    text = canonical("s-plus-l", 0)
    k = challenge(big_r, pub, text.encode())
    s = (r + k * a) % ed.L
    sig = big_r + le32(s + ed.L)
    assert int.from_bytes(sig[32:], "little") >= ed.L
    write(
        "s-plus-l",
        "v2 invalid (strict Ed25519) — S + L, which satisfies the same equation, is "
        "rejected because S >= L. Before: rejected the same way",
        pub,
        text,
        sig,
        GENERIC,
    )

    # R of small order, S = k*a: [S]B = [k]A, so the cofactorless equation
    # holds only for R = identity.
    for order, point in ((1, ed.IDENTITY), (2, T2), (4, T4), (8, T8)):
        name = "r-identity" if order == 1 else f"r-order-{order}"
        text = canonical(name, 0)
        r_enc = ed.encode(point)
        k = challenge(r_enc, pub, text.encode())
        what = "R is the identity (order 1)" if order == 1 else f"R is a point of order {order}"
        before = (
            "valid under Node.js 22, Python cryptography and Go; invalid under Node.js 24.22.1 "
            "(OpenSSL 3.5.9) and 26.10 (OpenSSL 3.6.5)"
            if order == 1
            else "rejected, signature does not verify"
        )
        edge(
            name,
            f"{what}, S = k*a, ordinary key",
            before,
            pub,
            text,
            r_enc + le32(k * a % ed.L),
            "signature R is a small-order point",
            (order == 1, True),
        )

    # R of mixed order, ordinary key: only the cofactored equation holds.
    text = canonical("r-mixed-order", 0)
    r_enc = ed.encode(ed.point_add(ed.scalar_mult(r, ed.BASE), T8))
    k = challenge(r_enc, pub, text.encode())
    edge(
        "r-mixed-order",
        "R = [r]B + T8 (mixed order), S = r + k*a, ordinary key",
        "rejected, signature does not verify",
        pub,
        text,
        r_enc + le32((r + k * a) % ed.L),
        "signature R is not in the prime-order subgroup",
        (False, True),
    )

    # R of mixed order with the cofactorless equation holding: that needs a
    # key with a small-order component too, R = [r]B + [t]T8 with t + k = 0
    # mod 8 and A = [a]B + T8. The key rule refuses it first.
    mixed_pub = ed.encode(ed.point_add(ed.scalar_mult(a, ed.BASE), T8))

    def r_with(t: int) -> bytes:
        return ed.encode(ed.point_add(ed.scalar_mult(r, ed.BASE), ed.scalar_mult(t, T8)))

    found = None
    for t in range(1, 8):
        try:
            found = (
                t,
                *search(
                    "r-mixed-order-cofactorless",
                    mixed_pub,
                    lambda _n, t=t: r_with(t),
                    lambda k, _r, t=t: (t + k) % 8 == 0,
                ),
            )
            break
        except AssertionError:
            continue
    assert found is not None
    t, text, r_enc, k = found
    edge(
        "r-mixed-order-cofactorless",
        f"R = [r]B + [{t}]T8 and A = [a]B + T8 (both mixed order), S = r + k*a, "
        "with t + k = 0 mod 8; "
        "the key is refused before R is looked at",
        "valid under Node.js, Python cryptography and Go",
        mixed_pub,
        text,
        r_enc + le32((r + k * a) % ed.L),
        "public key is not in the prime-order subgroup",
        (True, True),
    )

    # R non-canonical: the identity spelt y = p + 1, S = k*a.
    text = canonical("r-noncanonical", 0)
    r_enc = le32(ed.P + 1)
    k = challenge(r_enc, pub, text.encode())
    write(
        "r-noncanonical",
        "v2 invalid (strict Ed25519) — R is the identity spelt y = p + 1, a "
        "non-canonical encoding, S = k*a; the cofactorless equation holds once R is reduced. "
        f"Before: rejected, {GENERIC}",
        pub,
        text,
        r_enc + le32(k * a % ed.L),
        "signature R is not a canonical encoding",
    )

    # R off the curve: y = 2 has no x.
    text = canonical("r-off-curve", 0)
    write(
        "r-off-curve",
        "v2 invalid (strict Ed25519) — R encodes y = 2, which has no x on the "
        f"curve. Before: rejected, {GENERIC}",
        pub,
        text,
        le32(2) + le32(r),
        "signature R is not a point on the curve",
    )

    # Keys of mixed order: A = [a]B + T, R = [r]B, S = r + k*a. The
    # cofactorless equation holds iff [k]T = O.
    for label, torsion, n, holds in (
        ("key-mixed-order-8-k0", T8, 8, True),
        ("key-mixed-order-8", T8, 8, False),
        ("key-mixed-order-2-k0", T2, 2, True),
        ("key-mixed-order-4", T4, 4, False),
    ):
        key = ed.encode(ed.point_add(ed.scalar_mult(a, ed.BASE), torsion))
        text, _, k = search(
            label, key, lambda _n: big_r, lambda k, _r, n=n, h=holds: (k % n == 0) == h
        )
        cls = f"k = 0 mod {n}" if holds else f"k != 0 mod {n}"
        before = (
            "valid under Node.js, Python cryptography, Go and Chromium; "
            "invalid under WebKit on Linux"
            if label == "key-mixed-order-8-k0"
            else "valid under Node.js, Python cryptography and Go"
            if holds
            else f"rejected, {GENERIC}"
        )
        edge(
            label,
            f"A = [a]B + T{n} (mixed order), R = [r]B, S = r + k*a, {cls}",
            before,
            key,
            text,
            big_r + le32((r + k * a) % ed.L),
            "public key is not in the prime-order subgroup",
            (holds, True),
        )

    # Keys of small order, R = identity, S = 0: [0]B = O + [k]A iff [k]A = O.
    t8_enc = ed.encode(T8)
    text, _, _ = search(
        "key-small-order-8-k0", t8_enc, lambda _n: ed.encode(ed.IDENTITY), lambda k, _r: k % 8 == 0
    )
    edge(
        "key-small-order-8-k0",
        "A = T8 (order 8), R = identity, S = 0, k = 0 mod 8",
        "refused as a small-order key (the blocklist)",
        t8_enc,
        text,
        ed.encode(ed.IDENTITY) + bytes(32),
        "public key is a small-order point",
        (True, True),
    )
    sign_bit = bytearray(ed.encode(ed.IDENTITY))
    sign_bit[31] |= 0x80
    text = canonical("key-identity-sign-bit", 0)
    write(
        "key-identity-sign-bit",
        "v2 invalid (strict Ed25519) — A is the identity with the sign "
        "bit set (x = 0, a non-canonical encoding), R = identity, S = 0. Before: refused as a "
        "small-order key (the blocklist)",
        bytes(sign_bit),
        text,
        ed.encode(ed.IDENTITY) + bytes(32),
        "public key is a small-order point",
    )

    # A key off the curve.
    text = canonical("key-off-curve", 0)
    write(
        "key-off-curve",
        "v2 invalid (strict Ed25519) — A encodes y = 2, which has no x on the "
        f"curve. Before: rejected, {GENERIC}",
        le32(2),
        text,
        big_r + le32(r),
        "public key is not a point on the curve",
    )

    rfc8032()
    print("wrote", len(list(FIXTURES.glob("ed25519-*.json"))), "ed25519 fixtures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
