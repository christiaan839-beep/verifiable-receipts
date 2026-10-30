"""
Verifier for VAOS 2.0 receipts (Ed25519, RFC 8032).

v2 only: v3 (Ed25519 + ML-DSA-65) needs a post-quantum dependency and
is not verified here.

What ``verify_v2_receipt`` checks, in this order:
  0. The receipt nests at most 64 deep (VAOS 2.0 section 7.2): the
     receipt mapping is one level, and each list or mapping in it one
     more.
  1. ``canonical`` and ``signature`` are non-empty strings.
  2. ``signature`` is "v2=<base64>" with standard base64.
  3. ``contentHash``, when present and not null, is a string equal to
     the hex SHA-256 of the UTF-8 bytes of ``canonical`` ("sha256:"
     prefix optional); an empty string is a mismatch, not an absent
     field.
  4. The Ed25519 signature verifies over the UTF-8 bytes of
     ``canonical``, exactly as given, under the strict profile of VAOS
     2.0 section 7.3: R is a canonical encoding of a point of order L
     and S is below L, checked before ``cryptography`` sees the
     signature (the key is checked when it is loaded, after step 2).
  5. ``canonical`` nests at most 64 deep, counted on its text before it
     is parsed, and parses as a JSON object.
  6. Every other top-level field of the receipt (all but
     ``canonical``, ``contentHash`` and ``signature``) is present in
     that object with an equal JSON value. A field that disagrees, or
     that the canonical does not contain, is an unsigned claim and the
     receipt is rejected.

The verifier does not re-derive ``canonical`` from the other fields:
the signed bytes are the ``canonical`` string itself, whatever key
order the issuer used.

With both sides at most 64 deep, the recursive comparison never goes
deeper than 64 frames, so no input reaches Python's recursion limit.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from . import edwards25519

# Top-level fields that carry the signature material rather than
# signed content. Every other field must match the canonical.
_ENVELOPE_ONLY = frozenset({"canonical", "contentHash", "signature"})


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of a receipt verification attempt.

    Attributes:
        ok: True when every check in ``verify_v2_receipt`` passes.
        reason: When ok is False, a short human-readable reason string.
    """

    ok: bool
    reason: str | None = None


_STANDARD_BASE64 = re.compile(
    r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)


def _decode_v2_signature(signature: str) -> bytes:
    """Strip the 'v2=' prefix and base64-decode. Raises ValueError on malformed input."""
    if not isinstance(signature, str):
        raise ValueError("signature must be a string")
    if not signature.startswith("v2="):
        raise ValueError("signature is not v2 (expected 'v2=<base64>')")
    raw = signature[3:]
    # The same two steps, with the same reasons, as the TypeScript and Go
    # verifiers: the shape of padded standard base64, then one spelling.
    if _STANDARD_BASE64.fullmatch(raw) is None:
        raise ValueError("signature base64 invalid")
    decoded = base64.b64decode(raw, validate=True)
    # Reject non-canonical spellings (non-zero padding bits), so one
    # signature has exactly one valid string form.
    if base64.b64encode(decoded).decode("ascii") != raw:
        raise ValueError("signature base64 invalid: not canonical")
    return decoded


# The encodings of the points of small order, with the sign bit cleared:
# the libsodium blocklist ("Taming the many EdDSAs", Chalkias et al.).
# The last two are the non-canonical encodings y = p and y = p + 1.
_SMALL_ORDER_KEYS = frozenset(
    bytes.fromhex(h)
    for h in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )
)
_P = 2**255 - 19


_SIGNATURE_DOES_NOT_VERIFY = "signature does not verify under the supplied public key"
_BYTES_LIKE = (bytes, bytearray, memoryview)


@lru_cache(maxsize=256)
def _cached_key_problem(raw: bytes) -> str | None:
    if len(raw) != 32:
        return "public key is not 32 bytes"
    cleared = raw[:31] + bytes([raw[31] & 0x7F])
    if cleared in _SMALL_ORDER_KEYS:
        return "public key is a small-order point"
    if int.from_bytes(cleared, "little") >= _P:
        return "public key is not a canonical encoding"
    problem = edwards25519.point_problem(raw)
    return None if problem is None else "public key is " + problem


def ed25519_public_key_problem(raw: bytes) -> str | None:
    """Why a raw Ed25519 public key is refused (VAOS 2.0 section 7.3), or None.

    In order: "public key is not 32 bytes"; "public key is a small-order
    point" (the blocklist, sign bit cleared); "public key is not a
    canonical encoding" (y of p or more); "public key is not a point on
    the curve"; "public key is a small-order point"; "public key is not
    in the prime-order subgroup" (mixed order). The same reasons, in the
    same order, as TypeScript ``ed25519PublicKeyProblem`` and Go
    ``Ed25519PublicKeyProblem``. The answer depends only on the key, so
    it is cached.

    Args:
        raw: The raw public key, as bytes, bytearray or memoryview.

    Returns:
        The reason, or None. An argument that is not bytes, bytearray or
        memoryview gets "signature does not verify under the supplied
        public key", as in ``verify_ed25519``; it never raises.
    """
    if not isinstance(raw, _BYTES_LIKE):
        return _SIGNATURE_DOES_NOT_VERIFY
    return _cached_key_problem(bytes(raw))


def ed25519_signature_problem(signature: bytes) -> str | None:
    """Why a signature is rejected before the signature check, or None.

    VAOS 2.0 section 7.3, the strict profile: the signature is 64 bytes,
    R (its first 32) is a canonical encoding of a point on the curve
    that is not of small order (the identity included) and is in the
    prime-order subgroup ("signature R is not a canonical encoding",
    "... is not a point on the curve", "... is a small-order point",
    "... is not in the prime-order subgroup"), and S (its last 32,
    little-endian) is below L. A wrong length or an S of L or more has
    the reason a failed signature check has. The same reasons, in the
    same order, as TypeScript ``ed25519SignatureProblem`` and Go
    ``Ed25519SignatureProblem``. R is never cached.

    Args:
        signature: The raw signature (R || S), as bytes, bytearray or
            memoryview.

    Returns:
        The reason, or None. An argument that is not bytes, bytearray or
        memoryview gets "signature does not verify under the supplied
        public key", as in ``verify_ed25519``; it never raises.
    """
    if not isinstance(signature, _BYTES_LIKE):
        return _SIGNATURE_DOES_NOT_VERIFY
    signature = bytes(signature)
    if len(signature) != 64:
        return _SIGNATURE_DOES_NOT_VERIFY
    problem = edwards25519.point_problem(signature[:32])
    if problem is not None:
        return "signature R is " + problem
    if int.from_bytes(signature[32:], "little") >= edwards25519.L:
        return _SIGNATURE_DOES_NOT_VERIFY
    return None


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> VerifyResult:
    """Verify one Ed25519 signature under the strict profile of VAOS 2.0 section 7.3.

    The key is checked first (``ed25519_public_key_problem``), then R
    and S (``ed25519_signature_problem``), and only then does
    ``cryptography`` run the cofactorless check, over the bytes of R
    and A as given. Under these pre-checks every correct Ed25519
    verifier, cofactored or cofactorless, gives the same verdict.

    Args:
        public_key: The raw 32-byte public key.
        message: The signed bytes.
        signature: The raw 64-byte signature (R || S).

    Returns:
        VerifyResult(ok=True), or VerifyResult(False, reason), with the
        reasons of verify_v2_receipt. An argument that is not bytes,
        bytearray or memoryview fails with "signature does not verify
        under the supplied public key"; it never raises.
    """
    if not all(isinstance(a, _BYTES_LIKE) for a in (public_key, message, signature)):
        return VerifyResult(False, _SIGNATURE_DOES_NOT_VERIFY)
    problem = ed25519_public_key_problem(public_key)
    if problem is None:
        problem = ed25519_signature_problem(signature)
    if problem is not None:
        return VerifyResult(False, problem)
    try:
        Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(
            bytes(signature), bytes(message)
        )
    except InvalidSignature:
        return VerifyResult(False, _SIGNATURE_DOES_NOT_VERIFY)
    return VerifyResult(True)


def _load_ed25519_public_key(pem: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes. Raises ValueError on mismatch.

    Refuses a key that is not a canonical encoding of a point of order
    L: a point of small order, of mixed order, off the curve, or a
    non-canonical encoding (VAOS 2.0 section 7.3).
    """
    key = load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(
            f"expected Ed25519 public key, got {type(key).__name__}",
        )
    problem = ed25519_public_key_problem(key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    if problem is not None:
        raise ValueError(problem)
    return key


# The nesting limit of VAOS 2.0 section 7.2.
_MAX_NESTING = 64


def _nests_too_deep(value: Any) -> bool:
    """Whether ``value`` nests deeper than _MAX_NESTING.

    ``value`` is one level when it is a list, tuple or mapping, and each
    one inside it one more. Walks an explicit stack, not the call stack.
    """
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, level = stack.pop()
        if isinstance(item, Mapping):
            children = item.values()
        elif isinstance(item, (list, tuple)):
            children = item
        else:
            continue
        if level > _MAX_NESTING:
            return True
        stack.extend((child, level + 1) for child in children)
    return False


def _text_nests_too_deep(text: str) -> bool:
    """Whether JSON text opens more than _MAX_NESTING arrays and objects at once.

    Read from the start, valid JSON or not: outside strings ``[`` and
    ``{`` open one and ``]`` and ``}`` close one (when one is open); a
    string runs from ``"`` to the next ``"`` not escaped by a backslash.
    """
    open_ = 0
    in_string = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_string:
            if c == "\\":
                i += 1
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c in "[{":
            open_ += 1
            if open_ > _MAX_NESTING:
                return True
        elif c in "]}" and open_ > 0:
            open_ -= 1
        i += 1
    return False


def _reject_constant(name: str) -> Any:
    # json.loads accepts NaN and Infinity by default; JSON does not.
    raise ValueError(f"{name} is not valid JSON")


def _parse_canonical(canonical: str) -> Any:
    """Parse the canonical string as strict JSON. Raises ValueError."""
    try:
        return json.loads(canonical, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise ValueError("canonical is not valid JSON") from exc


# Numbers this large or larger are not compared (see _json_equal).
_UNSAFE = 2**53


def _json_equal(a: Any, b: Any, depth: int = 1) -> bool:
    """Deep JSON-value equality.

    Same JSON type and same value: numbers by numeric value (1 equals
    1.0), strings by code points, arrays element by element, objects
    key by key regardless of key order. Booleans never equal numbers.
    A number of magnitude 2**53 or more equals nothing: a double, the
    only number type JavaScript's JSON.parse has, cannot tell 2**53 from
    2**53 + 1, so every verifier rejects such a number in a repeated
    field rather than disagree about it.

    Bounded at _MAX_NESTING: ``depth`` is the level of ``a`` and ``b`` (1
    at the top), and lists or mappings deeper than that equal nothing,
    so no input recurses deeper than _MAX_NESTING.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(a) < _UNSAFE and abs(b) < _UNSAFE and a == b
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    if depth > _MAX_NESTING:
        return False
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(
            _json_equal(x, y, depth + 1) for x, y in zip(a, b, strict=True)
        )
    if isinstance(a, Mapping) and isinstance(b, Mapping):
        return set(a.keys()) == set(b.keys()) and all(
            _json_equal(a[k], b[k], depth + 1) for k in a
        )
    return False


def parse_receipt(text: str | bytes) -> dict[str, Any]:
    """Read a receipt from JSON text, counting its depth first.

    Raises:
        ValueError: "receipt nesting deeper than 64" when the text nests
            deeper than 64 (VAOS 2.0 section 7.2), the reason the
            verifiers give, at any depth: ``json.loads`` alone raises
            RecursionError on text nested some thousands deep. Also when
            the text is not JSON, or not a JSON object.
    """
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    if _text_nests_too_deep(text):
        raise ValueError("receipt nesting deeper than 64")
    try:
        value = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise ValueError("receipt is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("receipt is not a JSON object")
    return value


def _check_envelope(receipt: Mapping[str, Any], canonical: str) -> str | None:
    """Return a reason string when the envelope disagrees with canonical."""
    if _text_nests_too_deep(canonical):
        return "canonical nesting deeper than 64"
    try:
        signed = _parse_canonical(canonical)
    except ValueError as exc:
        return str(exc)
    if not isinstance(signed, dict):
        return "canonical is not a JSON object"
    for key in sorted(receipt, key=str):
        if key in _ENVELOPE_ONLY:
            continue
        if key not in signed:
            return f'envelope field "{key}" is not in the signed canonical'
        if not _json_equal(receipt[key], signed[key]):
            return f'envelope field "{key}" disagrees with the signed canonical'
    return None


def verify_v2_receipt(
    receipt: Mapping[str, Any],
    public_key_pem: bytes,
) -> VerifyResult:
    """Verify a VAOS 2.0 receipt.

    Args:
        receipt: A dict-like with ``canonical`` (the string that was
            signed) and ``signature`` ("v2=<base64>"), optionally
            ``contentHash``, and any other fields. Each other field
            must appear in the parsed ``canonical`` with an equal JSON
            value. See the module docstring for the full list of checks.
        public_key_pem: The Ed25519 public key as PEM bytes (the same
            file a TypeScript verifier would load).

    Returns:
        VerifyResult(ok=True) on success; VerifyResult(ok=False, reason=...)
        on any failure. Never raises for routine verification failures.
    """
    if not isinstance(receipt, Mapping):
        return VerifyResult(False, "receipt must be a mapping")
    if _nests_too_deep(receipt):
        return VerifyResult(False, "receipt nesting deeper than 64")

    canonical = receipt.get("canonical")
    signature = receipt.get("signature")
    if not isinstance(canonical, str) or not canonical:
        return VerifyResult(False, "missing canonical projection")
    if not isinstance(signature, str) or not signature:
        return VerifyResult(False, "missing signature")

    try:
        sig_bytes = _decode_v2_signature(signature)
    except ValueError as exc:
        return VerifyResult(False, str(exc))

    try:
        pub = _load_ed25519_public_key(public_key_pem)
    except ValueError as exc:
        return VerifyResult(False, str(exc))

    try:
        canonical_bytes = canonical.encode("utf-8")
    except UnicodeEncodeError:
        return VerifyResult(False, "canonical is not valid UTF-8 text")

    content_hash = receipt.get("contentHash")
    if content_hash is not None and not isinstance(content_hash, str):
        return VerifyResult(False, "contentHash must be a string")
    if content_hash is not None:
        actual = hashlib.sha256(canonical_bytes).hexdigest()
        expected = content_hash.removeprefix("sha256:")
        if actual != expected:
            return VerifyResult(
                False, "contentHash mismatch with canonical bytes"
            )

    # VAOS 2.0 section 7.3: R and S are checked before cryptography sees them.
    problem = ed25519_signature_problem(sig_bytes)
    if problem is not None:
        return VerifyResult(False, problem)
    try:
        pub.verify(sig_bytes, canonical_bytes)
    except InvalidSignature:
        return VerifyResult(False, _SIGNATURE_DOES_NOT_VERIFY)

    # Only now parse the canonical: these bytes are authenticated.
    reason = _check_envelope(receipt, canonical)
    if reason is not None:
        return VerifyResult(False, reason)

    return VerifyResult(True)


# Fields of a TypeScript `runGuardian` attestation that are not part of
# its signed canonical: the envelope's `totalMs`, and each rule's
# `durationMs` and `evidence`.
_GUARDIAN_UNSIGNED = "totalMs"


def _guardian_rule_projection(rule: Any) -> Any:
    """The part of one envelope rule that the Guardian canonical signs."""
    if not isinstance(rule, Mapping):
        return rule
    out: dict[str, Any] = {}
    for key in ("ruleId", "verdict"):
        if key in rule:
            out[key] = rule[key]
    reason = rule.get("reason")
    out["reason"] = reason
    return out


def _guardian_rules_in_canonical_order(rules: list[Any], canonical: Any) -> list[Any]:
    """Project the envelope rules; reorder them to the canonical's order.

    The Guardian canonical sorts its rules by ruleId. When the projected
    envelope rules are the same multiset as the canonical's rules, this
    returns them in the canonical's order, so the generic envelope check
    passes; otherwise it returns them in their own order, and the
    generic check rejects the envelope's ``rules``.
    """
    projected = [_guardian_rule_projection(r) for r in rules]
    if not isinstance(canonical, str) or _text_nests_too_deep(canonical):
        return projected
    try:
        signed = _parse_canonical(canonical)
    except ValueError:
        return projected
    signed_rules = signed.get("rules") if isinstance(signed, dict) else None
    if not isinstance(signed_rules, list) or len(signed_rules) != len(projected):
        return projected
    remaining = list(projected)
    ordered: list[Any] = []
    for want in signed_rules:
        for i, have in enumerate(remaining):
            if _json_equal(have, want):
                ordered.append(remaining.pop(i))
                break
        else:
            return projected
    return ordered


def verify_guardian_attestation(
    attestation: Mapping[str, Any],
    public_key_pem: bytes,
) -> VerifyResult:
    """Verify a signed Guardian attestation from the TypeScript ``runGuardian``.

    The same checks as ``verify_v2_receipt``, applied to the part of the
    attestation that its canonical signs, as the TypeScript
    ``verifyGuardianAttestation`` does:

      - ``totalMs`` is not signed and is not checked.
      - Each rule in ``rules`` is compared as ``{ruleId, verdict,
        reason}`` (a missing ``reason`` reads as null); its
        ``durationMs`` and ``evidence`` are not signed and are not
        checked. The order of ``rules`` does not matter.
      - Every other field must equal the canonical's, as in
        ``verify_v2_receipt``.

    Do not rely on ``totalMs``, ``durationMs`` or ``evidence``: no
    signature covers them.

    Args:
        attestation: The Guardian attestation dict (``verdictId``,
            ``overall``, ``rules``, ``totalMs``, ``issuedAt``,
            ``canonical``, ``contentHash``, ``signature``).
        public_key_pem: The Ed25519 public key as PEM bytes.

    Returns:
        VerifyResult, as from verify_v2_receipt().
    """
    if not isinstance(attestation, Mapping):
        return VerifyResult(False, "receipt must be a mapping")
    # Before the rules are projected and compared: the attestation as
    # given, fields that are not signed included, nests at most 64 deep.
    if _nests_too_deep(attestation):
        return VerifyResult(False, "receipt nesting deeper than 64")
    view = {k: v for k, v in attestation.items() if k != _GUARDIAN_UNSIGNED}
    rules = view.get("rules")
    if isinstance(rules, list):
        view["rules"] = _guardian_rules_in_canonical_order(
            rules, attestation.get("canonical")
        )
    return verify_v2_receipt(view, public_key_pem)
