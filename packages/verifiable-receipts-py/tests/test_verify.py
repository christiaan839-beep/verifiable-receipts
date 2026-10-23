"""
Python verifier tests — symmetric with the TypeScript suite.

These tests use Python-side keys (Ed25519 generated in cryptography)
to prove the verifier correctly accepts/rejects without needing
cross-language fixtures. The cross-language interop test lives
separately and exercises the wire format end-to-end.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from sovereign_matrix.verifiable_receipts import (
    VerifyResult,
    inner_hash,
    leaf_hash,
    verify_guardian_attestation,
    verify_inclusion_proof,
    verify_v2_receipt,
)


def _make_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Returns (private_key, public_key_pem)."""
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def _sign_v2(priv: Ed25519PrivateKey, canonical: str) -> str:
    """Mint a v2= wire-format signature over the canonical UTF-8 bytes."""
    sig = priv.sign(canonical.encode("utf-8"))
    return "v2=" + base64.b64encode(sig).decode("ascii")


def _content_hash(canonical: str) -> str:
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class TestVerifyV2Receipt:
    def test_verifies_a_well_formed_receipt(self) -> None:
        priv, pub_pem = _make_keypair()
        canonical = '{"verdictId":"v_test","overall":"pass"}'
        receipt = {
            "canonical": canonical,
            "signature": _sign_v2(priv, canonical),
            "contentHash": _content_hash(canonical),
        }
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is True
        assert result.reason is None

    def test_rejects_when_signature_is_under_wrong_key(self) -> None:
        priv_a, _ = _make_keypair()
        _, pub_b_pem = _make_keypair()
        canonical = '{"verdictId":"v_test"}'
        receipt = {
            "canonical": canonical,
            "signature": _sign_v2(priv_a, canonical),
        }
        result = verify_v2_receipt(receipt, pub_b_pem)
        assert result.ok is False
        assert "signature" in (result.reason or "")

    def test_rejects_when_canonical_was_tampered(self) -> None:
        priv, pub_pem = _make_keypair()
        canonical = '{"verdictId":"v_test"}'
        sig = _sign_v2(priv, canonical)
        # Now tamper.
        receipt = {
            "canonical": '{"verdictId":"v_tampered"}',
            "signature": sig,
        }
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is False

    def test_rejects_when_content_hash_does_not_match(self) -> None:
        priv, pub_pem = _make_keypair()
        canonical = '{"verdictId":"v_test"}'
        receipt = {
            "canonical": canonical,
            "signature": _sign_v2(priv, canonical),
            "contentHash": "sha256:" + "0" * 64,
        }
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is False
        assert "contentHash" in (result.reason or "")

    def test_rejects_a_content_hash_that_is_not_a_string(self) -> None:
        priv, pub_pem = _make_keypair()
        canonical = '{"verdictId":"v_test"}'
        receipt = {
            "canonical": canonical,
            "signature": _sign_v2(priv, canonical),
            "contentHash": 5,
        }
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is False
        assert result.reason == "contentHash must be a string"
        receipt["contentHash"] = None
        assert verify_v2_receipt(receipt, pub_pem).ok is True

    def test_rejects_non_v2_signature_prefix(self) -> None:
        _, pub_pem = _make_keypair()
        receipt = {
            "canonical": '{"x":1}',
            "signature": "v1=hmacstuff",
        }
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is False

    def test_rejects_malformed_base64(self) -> None:
        _, pub_pem = _make_keypair()
        receipt = {
            "canonical": '{"x":1}',
            "signature": "v2=!!!notbase64!!!",
        }
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is False

    def test_rejects_missing_canonical_or_signature(self) -> None:
        _, pub_pem = _make_keypair()
        assert verify_v2_receipt({"signature": "v2=x"}, pub_pem).ok is False
        assert verify_v2_receipt({"canonical": "x"}, pub_pem).ok is False
        assert verify_v2_receipt({}, pub_pem).ok is False

    def test_rejects_non_mapping_receipt(self) -> None:
        _, pub_pem = _make_keypair()
        assert verify_v2_receipt("not a dict", pub_pem).ok is False  # type: ignore[arg-type]
        assert verify_v2_receipt(None, pub_pem).ok is False  # type: ignore[arg-type]

    def test_guardian_attestation_accepts_a_matching_envelope(self) -> None:
        priv, pub_pem = _make_keypair()
        canonical = '{"verdictId":"g_test","overall":"pass","rules":[]}'
        att = {
            "canonical": canonical,
            "signature": _sign_v2(priv, canonical),
            "verdictId": "g_test",
            "overall": "pass",
            "rules": [],
        }
        assert verify_guardian_attestation(att, pub_pem).ok is True


class TestEnvelopeConsistency:
    """Fields beside ``canonical`` must match the signed canonical."""

    CANONICAL = (
        '{"agentSlug":"loan-underwriter","overall":"pass",'
        '"rules":[{"ruleId":"r1","verdict":"pass","durationMs":2}],"n":1}'
    )

    def _receipt(self, priv: Ed25519PrivateKey, **fields: object) -> dict:
        return {
            **fields,
            "canonical": self.CANONICAL,
            "contentHash": _content_hash(self.CANONICAL),
            "signature": _sign_v2(priv, self.CANONICAL),
        }

    def test_accepts_fields_that_agree_in_any_key_order(self) -> None:
        priv, pub_pem = _make_keypair()
        receipt = self._receipt(
            priv,
            overall="pass",
            rules=[{"durationMs": 2, "verdict": "pass", "ruleId": "r1"}],
            n=1.0,  # numerically equal to the canonical's 1
        )
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is True, result.reason

    def test_rejects_a_field_that_disagrees(self) -> None:
        priv, pub_pem = _make_keypair()
        result = verify_v2_receipt(self._receipt(priv, overall="fail"), pub_pem)
        assert result.ok is False
        assert result.reason == (
            'envelope field "overall" disagrees with the signed canonical'
        )

    def test_rejects_a_nested_difference(self) -> None:
        priv, pub_pem = _make_keypair()
        receipt = self._receipt(
            priv, rules=[{"ruleId": "r1", "verdict": "block", "durationMs": 2}]
        )
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is False
        assert '"rules" disagrees' in (result.reason or "")

    def test_rejects_a_field_absent_from_the_canonical(self) -> None:
        priv, pub_pem = _make_keypair()
        result = verify_v2_receipt(
            self._receipt(priv, approvedBy="compliance"), pub_pem
        )
        assert result.ok is False
        assert result.reason == (
            'envelope field "approvedBy" is not in the signed canonical'
        )

    def test_a_boolean_never_equals_a_number(self) -> None:
        priv, pub_pem = _make_keypair()
        result = verify_v2_receipt(self._receipt(priv, n=True), pub_pem)
        assert result.ok is False
        assert '"n" disagrees' in (result.reason or "")

    def test_rejects_a_signed_canonical_that_is_not_an_object(self) -> None:
        priv, pub_pem = _make_keypair()
        canonical = '["not","an","object"]'
        receipt = {"canonical": canonical, "signature": _sign_v2(priv, canonical)}
        result = verify_v2_receipt(receipt, pub_pem)
        assert result.ok is False
        assert result.reason == "canonical is not a JSON object"

    def test_rejects_a_signed_canonical_that_is_not_json(self) -> None:
        priv, pub_pem = _make_keypair()
        for canonical in ("not json", '{"x":NaN}', '{"x":1} trailing'):
            receipt = {"canonical": canonical, "signature": _sign_v2(priv, canonical)}
            result = verify_v2_receipt(receipt, pub_pem)
            assert result.ok is False
            assert result.reason == "canonical is not valid JSON"


class TestGuardianAttestation:
    """The envelope ``runGuardian`` (TypeScript) returns."""

    # Rules sorted by ruleId, projected to ruleId/verdict/reason, as
    # guardian.ts canonicalize() writes them.
    CANONICAL = (
        '{"v":1,"type":"guardian-verdict","verdictId":"g_1","runId":"r1",'
        '"agentSlug":"a","tokenId":"t","overall":"warn","rules":['
        '{"ruleId":"hipaa-no-mrn","verdict":"warn","reason":"MRN found"},'
        '{"ruleId":"hipaa-no-raw-ssn","verdict":"pass","reason":null}],'
        '"issuedAt":"2026-10-16T00:00:00.000Z"}'
    )

    def _attestation(self, priv: Ed25519PrivateKey) -> dict:
        return {
            "verdictId": "g_1",
            "overall": "warn",
            # Evaluation order, with the unsigned durationMs and evidence.
            "rules": [
                {"ruleId": "hipaa-no-raw-ssn", "verdict": "pass", "durationMs": 0},
                {
                    "ruleId": "hipaa-no-mrn",
                    "verdict": "warn",
                    "reason": "MRN found",
                    "evidence": {"offset": 4},
                    "durationMs": 1,
                },
            ],
            "totalMs": 1,
            "issuedAt": "2026-10-16T00:00:00.000Z",
            "canonical": self.CANONICAL,
            "contentHash": hashlib.sha256(self.CANONICAL.encode("utf-8")).hexdigest(),
            "signature": _sign_v2(priv, self.CANONICAL),
        }

    def test_accepts_a_run_guardian_envelope(self) -> None:
        priv, pub_pem = _make_keypair()
        result = verify_guardian_attestation(self._attestation(priv), pub_pem)
        assert result.ok is True, result.reason

    def test_the_generic_check_rejects_the_unsigned_fields(self) -> None:
        priv, pub_pem = _make_keypair()
        result = verify_v2_receipt(self._attestation(priv), pub_pem)
        assert result.ok is False

    def test_rejects_a_changed_verdict(self) -> None:
        priv, pub_pem = _make_keypair()
        att = self._attestation(priv)
        att["rules"][1]["verdict"] = "pass"
        result = verify_guardian_attestation(att, pub_pem)
        assert result.ok is False
        assert '"rules" disagrees' in (result.reason or "")

    def test_rejects_a_dropped_rule(self) -> None:
        priv, pub_pem = _make_keypair()
        att = self._attestation(priv)
        att["rules"] = att["rules"][:1]
        assert verify_guardian_attestation(att, pub_pem).ok is False

    def test_rejects_a_changed_overall(self) -> None:
        priv, pub_pem = _make_keypair()
        att = self._attestation(priv)
        att["overall"] = "pass"
        result = verify_guardian_attestation(att, pub_pem)
        assert result.ok is False
        assert '"overall" disagrees' in (result.reason or "")

    def test_ignores_the_unsigned_timings(self) -> None:
        priv, pub_pem = _make_keypair()
        att = self._attestation(priv)
        att["totalMs"] = 999
        att["rules"][0]["durationMs"] = 999
        assert verify_guardian_attestation(att, pub_pem).ok is True


class TestRfc9162InclusionProof:
    def test_single_leaf_tree(self) -> None:
        leaf = leaf_hash(b"hello")
        proof = {
            "leafIndex": 0,
            "treeSize": 1,
            "auditPath": [],
        }
        # Single-leaf tree: root == leaf hash.
        assert (
            verify_inclusion_proof(proof, leaf.hex(), leaf.hex()) is True
        )

    def test_two_leaf_tree_left(self) -> None:
        a = leaf_hash(b"a")
        b = leaf_hash(b"b")
        root = inner_hash(a, b)
        proof = {
            "leafIndex": 0,
            "treeSize": 2,
            "auditPath": [b.hex()],
        }
        assert verify_inclusion_proof(proof, a.hex(), root.hex()) is True

    def test_two_leaf_tree_right(self) -> None:
        a = leaf_hash(b"a")
        b = leaf_hash(b"b")
        root = inner_hash(a, b)
        proof = {
            "leafIndex": 1,
            "treeSize": 2,
            "auditPath": [a.hex()],
        }
        assert verify_inclusion_proof(proof, b.hex(), root.hex()) is True

    def test_four_leaf_tree(self) -> None:
        # Tree:
        #         root
        #        /    \
        #       AB    CD
        #      / \   / \
        #     a   b c   d
        a = leaf_hash(b"a")
        b = leaf_hash(b"b")
        c = leaf_hash(b"c")
        d = leaf_hash(b"d")
        ab = inner_hash(a, b)
        cd = inner_hash(c, d)
        root = inner_hash(ab, cd)

        proof_for_c = {
            "leafIndex": 2,
            "treeSize": 4,
            "auditPath": [d.hex(), ab.hex()],
        }
        assert (
            verify_inclusion_proof(proof_for_c, c.hex(), root.hex()) is True
        )

    def test_rejects_wrong_root(self) -> None:
        a = leaf_hash(b"a")
        b = leaf_hash(b"b")
        proof = {
            "leafIndex": 0,
            "treeSize": 2,
            "auditPath": [b.hex()],
        }
        # Tamper with root.
        wrong_root = inner_hash(b, a)  # swapped order
        assert (
            verify_inclusion_proof(proof, a.hex(), wrong_root.hex())
            is False
        )

    def test_rejects_wrong_leaf_index(self) -> None:
        a = leaf_hash(b"a")
        b = leaf_hash(b"b")
        root = inner_hash(a, b)
        # Proof claims index 1 (right) but supplies leaf hash of a (left).
        proof = {
            "leafIndex": 1,
            "treeSize": 2,
            "auditPath": [a.hex()],
        }
        # Will compute inner_hash(a, a) which != root.
        assert (
            verify_inclusion_proof(proof, a.hex(), root.hex()) is False
        )

    def test_rejects_out_of_range_leaf_index(self) -> None:
        a = leaf_hash(b"a")
        proof = {
            "leafIndex": 5,
            "treeSize": 2,
            "auditPath": [],
        }
        assert (
            verify_inclusion_proof(proof, a.hex(), a.hex()) is False
        )

    def test_rejects_zero_tree_size(self) -> None:
        a = leaf_hash(b"a")
        proof = {"leafIndex": 0, "treeSize": 0, "auditPath": []}
        assert verify_inclusion_proof(proof, a.hex(), a.hex()) is False

    def test_rejects_malformed_audit_path_entry(self) -> None:
        a = leaf_hash(b"a")
        proof = {
            "leafIndex": 0,
            "treeSize": 2,
            "auditPath": ["not-hex"],
        }
        assert (
            verify_inclusion_proof(proof, a.hex(), a.hex()) is False
        )

    def test_rejects_malformed_proof_fields(self) -> None:
        assert (
            verify_inclusion_proof(
                {"leafIndex": "x", "treeSize": 1, "auditPath": []},
                "00" * 32,
                "00" * 32,
            )
            is False
        )
        assert (
            verify_inclusion_proof(
                {"leafIndex": 0, "treeSize": 1, "auditPath": "string"},
                "00" * 32,
                "00" * 32,
            )
            is False
        )

    def test_hash_helpers_use_rfc9162_domain_separators(self) -> None:
        # RFC 9162 §2: leaf prefix is 0x00, inner prefix is 0x01.
        # Re-derive the expected SHA-256s by hand for empty inputs.
        expected_leaf = hashlib.sha256(b"\x00" + b"hello").digest()
        assert leaf_hash(b"hello") == expected_leaf

        a = leaf_hash(b"a")
        b = leaf_hash(b"b")
        expected_inner = hashlib.sha256(b"\x01" + a + b).digest()
        assert inner_hash(a, b) == expected_inner


class TestVerifyResultDataclass:
    def test_ok_default_no_reason(self) -> None:
        r = VerifyResult(True)
        assert r.ok is True
        assert r.reason is None

    def test_frozen_dataclass(self) -> None:
        r = VerifyResult(False, "reason here")
        with pytest.raises(AttributeError):
            r.ok = True  # type: ignore[misc]
