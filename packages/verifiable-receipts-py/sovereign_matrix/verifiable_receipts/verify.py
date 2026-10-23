"""
Verifier for VAOS 2.0 receipts (Ed25519, RFC 8032).

v2 only: v3 (Ed25519 + ML-DSA-65) needs a post-quantum dependency and
is not verified here.

What ``verify_v2_receipt`` checks, in this order:
  1. ``canonical`` and ``signature`` are non-empty strings.
  2. ``signature`` is "v2=<base64>" with standard base64.
  3. ``contentHash``, when present and not null, is a string; when
     non-empty, it equals the hex SHA-256 of the UTF-8 bytes of
     ``canonical`` ("sha256:" prefix optional).
  4. The Ed25519 signature verifies over the UTF-8 bytes of
     ``canonical``, exactly as given.
  5. ``canonical`` parses as a JSON object.
  6. Every other top-level field of the receipt (all but
     ``canonical``, ``contentHash`` and ``signature``) is present in
     that object with an equal JSON value. A field that disagrees, or
     that the canonical does not contain, is an unsigned claim and the
     receipt is rejected.

The verifier does not re-derive ``canonical`` from the other fields:
the signed bytes are the ``canonical`` string itself, whatever key
order the issuer used.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
)

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


def _decode_v2_signature(signature: str) -> bytes:
    """Strip the 'v2=' prefix and base64-decode. Raises ValueError on malformed input."""
    if not isinstance(signature, str):
        raise ValueError("signature must be a string")
    if not signature.startswith("v2="):
        raise ValueError("signature is not v2 (expected 'v2=<base64>')")
    raw = signature[3:]
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise ValueError(f"signature base64 invalid: {exc}") from exc
    # Reject non-canonical spellings (non-zero padding bits), so one
    # signature has exactly one valid string form.
    if base64.b64encode(decoded).decode("ascii") != raw:
        raise ValueError("signature base64 invalid: not canonical")
    return decoded


def _load_ed25519_public_key(pem: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes. Raises ValueError on mismatch."""
    key = load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(
            f"expected Ed25519 public key, got {type(key).__name__}",
        )
    return key


def _reject_constant(name: str) -> Any:
    # json.loads accepts NaN and Infinity by default; JSON does not.
    raise ValueError(f"{name} is not valid JSON")


def _parse_canonical(canonical: str) -> Any:
    """Parse the canonical string as strict JSON. Raises ValueError."""
    try:
        return json.loads(canonical, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise ValueError("canonical is not valid JSON") from exc


def _json_equal(a: Any, b: Any) -> bool:
    """Deep JSON-value equality.

    Same JSON type and same value: numbers by numeric value (1 equals
    1.0), strings by code points, arrays element by element, objects
    key by key regardless of key order. Booleans never equal numbers.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(
            _json_equal(x, y) for x, y in zip(a, b, strict=True)
        )
    if isinstance(a, Mapping) and isinstance(b, Mapping):
        return set(a.keys()) == set(b.keys()) and all(
            _json_equal(a[k], b[k]) for k in a
        )
    return False


def _check_envelope(receipt: Mapping[str, Any], canonical: str) -> str | None:
    """Return a reason string when the envelope disagrees with canonical."""
    try:
        signed = _parse_canonical(canonical)
    except ValueError as exc:
        return str(exc)
    if not isinstance(signed, dict):
        return "canonical is not a JSON object"
    try:
        for key in sorted(receipt, key=str):
            if key in _ENVELOPE_ONLY:
                continue
            if key not in signed:
                return f'envelope field "{key}" is not in the signed canonical'
            if not _json_equal(receipt[key], signed[key]):
                return f'envelope field "{key}" disagrees with the signed canonical'
    except RecursionError:
        return "envelope is nested too deeply to compare"
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
    if content_hash:
        actual = hashlib.sha256(canonical_bytes).hexdigest()
        expected = content_hash.removeprefix("sha256:")
        if actual != expected:
            return VerifyResult(
                False, "contentHash mismatch with canonical bytes"
            )

    try:
        pub.verify(sig_bytes, canonical_bytes)
    except InvalidSignature:
        return VerifyResult(False, "signature does not verify under the supplied public key")

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
    try:
        signed = _parse_canonical(canonical) if isinstance(canonical, str) else None
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
    view = {k: v for k, v in attestation.items() if k != _GUARDIAN_UNSIGNED}
    rules = view.get("rules")
    if isinstance(rules, list):
        view["rules"] = _guardian_rules_in_canonical_order(
            rules, attestation.get("canonical")
        )
    return verify_v2_receipt(view, public_key_pem)
