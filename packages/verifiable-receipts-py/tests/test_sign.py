"""
Python signer tests: canonicalize() and sign_v2_receipt().

Keys are generated at test time; none is stored in the repository.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from sovereign_matrix.verifiable_receipts import (
    canonicalize,
    sign_v2_receipt,
    verify_v2_receipt,
)


def _make_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


BODY = {
    "verdictId": "v_py_001",
    "overall": "pass",
    "issuedAt": "2026-10-16T00:00:00Z",
    "rules": [{"verdict": "pass", "ruleId": "r1", "durationMs": 2}],
    "tokenId": None,
    "attempts": 3,
    "escalated": False,
}


class TestCanonicalize:
    def test_sorts_keys_at_every_depth(self) -> None:
        body = {"b": {"d": 1, "c": [{"z": 1, "y": {"x": 2, "w": 3}}]}, "a": 0}
        assert canonicalize(body) == (
            '{"a":0,"b":{"c":[{"y":{"w":3,"x":2},"z":1}],"d":1}}'
        )

    def test_is_compact_and_keeps_array_order(self) -> None:
        assert canonicalize({"k": [3, 1, 2], "s": "a b"}) == '{"k":[3,1,2],"s":"a b"}'

    def test_writes_non_ascii_text_as_utf8(self) -> None:
        body = {"name": "Zoë", "city": "東京", "note": "naïve ☃"}
        out = canonicalize(body)
        assert out == '{"city":"東京","name":"Zoë","note":"naïve ☃"}'
        assert "\\u" not in out

    def test_escapes_quotes_backslashes_and_control_characters(self) -> None:
        assert canonicalize({"s": 'a"b\\c\nd\x01'}) == '{"s":"a\\"b\\\\c\\nd\\u0001"}'

    def test_sorts_keys_by_utf16_code_units(self) -> None:
        # U+1F600 is the surrogate pair D83D DE00, which sorts before
        # U+FFFF in UTF-16 (JavaScript's order) but after it by code point.
        body = {"￿": 1, "\U0001f600": 2, "a": 3}
        assert canonicalize(body) == '{"a":3,"\U0001f600":2,"￿":1}'

    def test_matches_json_dumps_sort_keys_for_plain_bodies(self) -> None:
        expected = json.dumps(BODY, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert canonicalize(BODY) == expected

    def test_accepts_ints_bools_and_none(self) -> None:
        assert canonicalize({"i": -12, "big": 2**70, "t": True, "f": False, "n": None}) == (
            '{"big":1180591620717411303424,"f":false,"i":-12,"n":null,"t":true}'
        )

    @pytest.mark.parametrize(
        "value",
        [1.0, 0.5, float("nan"), float("inf"), float("-inf")],
    )
    def test_refuses_floats(self, value: float) -> None:
        with pytest.raises(TypeError, match="float"):
            canonicalize({"x": value})

    def test_refuses_a_float_nested_in_a_list(self) -> None:
        with pytest.raises(TypeError, match=r"body\.a\[1\]"):
            canonicalize({"a": [1, 2.5]})

    @pytest.mark.parametrize("value", [(1, 2), {1, 2}, b"bytes", object()])
    def test_refuses_non_json_types(self, value: object) -> None:
        with pytest.raises(TypeError):
            canonicalize({"x": value})

    def test_refuses_non_string_keys(self) -> None:
        with pytest.raises(TypeError, match="non-string key"):
            canonicalize({1: "a"})

    def test_refuses_a_lone_surrogate(self) -> None:
        with pytest.raises(ValueError, match="surrogate"):
            canonicalize({"s": "\ud800"})


class TestSignV2Receipt:
    def test_round_trip_verifies(self) -> None:
        priv, pub_pem = _make_keypair()
        receipt = sign_v2_receipt(BODY, priv)
        for key, value in BODY.items():
            assert receipt[key] == value
        assert receipt["canonical"] == canonicalize(BODY)
        assert receipt["contentHash"] == (
            "sha256:" + hashlib.sha256(receipt["canonical"].encode("utf-8")).hexdigest()
        )
        assert receipt["signature"].startswith("v2=")
        assert len(base64.b64decode(receipt["signature"][3:], validate=True)) == 64
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is True, result.reason

    def test_round_trip_survives_json_serialization(self) -> None:
        priv, pub_pem = _make_keypair()
        wire = json.dumps(sign_v2_receipt(BODY, priv), ensure_ascii=False)
        assert verify_v2_receipt(json.loads(wire), pub_pem).ok is True

    def test_non_ascii_text_round_trips(self) -> None:
        priv, pub_pem = _make_keypair()
        receipt = sign_v2_receipt({"agent": "Zoë", "reply": "東京 ☃"}, priv)
        assert receipt["canonical"] == '{"agent":"Zoë","reply":"東京 ☃"}'
        assert verify_v2_receipt(receipt, pub_pem).ok is True

    def test_detects_a_tampered_envelope_field(self) -> None:
        priv, pub_pem = _make_keypair()
        receipt = sign_v2_receipt(BODY, priv)
        receipt["overall"] = "fail"
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is False
        assert result.reason == 'envelope field "overall" disagrees with the signed canonical'

    def test_detects_an_added_envelope_field(self) -> None:
        priv, pub_pem = _make_keypair()
        receipt = sign_v2_receipt(BODY, priv)
        receipt["approvedBy"] = "someone"
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is False
        assert "not in the signed canonical" in (result.reason or "")

    def test_detects_a_tampered_canonical(self) -> None:
        priv, pub_pem = _make_keypair()
        receipt = sign_v2_receipt(BODY, priv)
        receipt["canonical"] = receipt["canonical"].replace('"pass"', '"fail"')
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is False
        assert "contentHash" in (result.reason or "")

    def test_detects_another_key(self) -> None:
        priv, _ = _make_keypair()
        _, other_pub_pem = _make_keypair()
        result = verify_v2_receipt(sign_v2_receipt(BODY, priv), other_pub_pem)
        assert result.ok is False
        assert "signature" in (result.reason or "")

    def test_signing_a_signed_receipt_again_gives_the_same_canonical(self) -> None:
        priv, pub_pem = _make_keypair()
        first = sign_v2_receipt(BODY, priv)
        second = sign_v2_receipt(first, priv)
        assert second["canonical"] == first["canonical"]
        assert second["signature"] == first["signature"]  # Ed25519 is deterministic
        assert verify_v2_receipt(second, pub_pem).ok is True

    def test_refuses_floats(self) -> None:
        priv, _ = _make_keypair()
        with pytest.raises(TypeError, match="float"):
            sign_v2_receipt({"score": 0.97}, priv)

    def test_refuses_a_non_mapping_body(self) -> None:
        priv, _ = _make_keypair()
        with pytest.raises(TypeError, match="mapping"):
            sign_v2_receipt(["not", "a", "mapping"], priv)  # type: ignore[arg-type]

    def test_refuses_a_key_that_is_not_ed25519(self) -> None:
        with pytest.raises(TypeError, match="Ed25519PrivateKey"):
            sign_v2_receipt(BODY, b"not a key")  # type: ignore[arg-type]
