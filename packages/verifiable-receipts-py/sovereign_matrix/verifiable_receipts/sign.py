"""
Signer for VAOS 2.0 receipts (Ed25519, RFC 8032).

``canonicalize(body)`` builds the canonical projection: compact JSON
with object keys sorted at every depth, in UTF-16 code-unit order (the
order of JavaScript's ``Array.prototype.sort``, which the TypeScript
``sortKeysDeep`` uses), with non-ASCII text written as UTF-8 rather
than escaped. For bodies without floats or integer-like object keys it
produces the same string as the TypeScript ``verifiable-receipts-sign``
CLI.

It refuses floats (including NaN and the infinities): JavaScript and
Python print them differently (``1.0`` against ``1``), so a float would
make the same body canonicalize differently in each language. It
accepts only dicts with string keys, lists, strings, ints, bools and
None, nested at most 64 deep (VAOS 2.0 section 7.2), since every verifier
rejects a receipt nested deeper.

``sign_v2_receipt(body, private_key)`` signs that projection and
returns the receipt, which ``verify_v2_receipt`` and the Go
``VerifyV2Receipt`` accept.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

# Fields the signer writes; a body's own copies are dropped first.
_SIGNER_FIELDS = ("canonical", "contentHash", "signature")

# The nesting limit of VAOS 2.0 section 7.2.
_MAX_NESTING = 64


def _utf16_key(key: str) -> bytes:
    # Big-endian UTF-16 bytes compare in code-unit order.
    return key.encode("utf-16-be", "surrogatepass")


def _encode(value: Any, path: str, level: int = 1) -> str:
    # ``level`` is the depth ``value`` has when it is a list or dict.
    if isinstance(value, (list, dict)) and level > _MAX_NESTING:
        raise ValueError(f"{path} is nesting deeper than {_MAX_NESTING}, which verifiers reject")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return int.__repr__(value)
    if isinstance(value, float):
        raise TypeError(
            f"{path} is a float ({value!r}); floats canonicalize differently "
            "across languages, so use an int or a string"
        )
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(
            _encode(item, f"{path}[{i}]", level + 1) for i, item in enumerate(value)
        ) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(
                    f"{path} has a non-string key {key!r}; JSON object keys are strings"
                )
        parts = [
            json.dumps(key, ensure_ascii=False)
            + ":"
            + _encode(value[key], f"{path}.{key}", level + 1)
            for key in sorted(value, key=_utf16_key)
        ]
        return "{" + ",".join(parts) + "}"
    raise TypeError(
        f"{path} is a {type(value).__name__}, which is not a JSON type "
        "(use dict, list, str, int, bool or None)"
    )


def canonicalize(body: Any) -> str:
    """Return the canonical projection of a JSON value.

    Keys are sorted at every depth (UTF-16 code-unit order), separators
    are compact (``,`` and ``:``), and non-ASCII text is kept as is.

    Raises:
        TypeError: on a float (NaN and the infinities included), a
            non-string object key, or any value that is not a dict,
            list, str, int, bool or None.
        ValueError: when a string holds a lone surrogate, which has no
            UTF-8 encoding, or ``body`` nests deeper than 64.
    """
    out = _encode(body, "body")
    try:
        out.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("body holds a lone surrogate, which has no UTF-8 encoding") from exc
    return out


def sign_v2_receipt(body: Mapping[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Sign a receipt body and return the v2 receipt.

    Any ``canonical``, ``contentHash`` and ``signature`` fields already in
    ``body`` are dropped first, as the TypeScript CLI does, so signing a
    signed receipt again gives the same canonical.

    Args:
        body: The receipt fields, a mapping of JSON values (see ``canonicalize``).
        private_key: The issuer's Ed25519 private key, from ``cryptography``.

    Returns:
        ``{**body, "canonical": ..., "contentHash": "sha256:<hex>",
        "signature": "v2=<base64>"}``, where ``canonical`` is the exact
        string that was signed and ``contentHash`` is the SHA-256 of its
        UTF-8 bytes.

    Raises:
        TypeError: when ``body`` is not a mapping, holds a value that
            ``canonicalize`` refuses, or ``private_key`` is not an
            Ed25519 private key.
        ValueError: as ``canonicalize``.
    """
    if not isinstance(body, Mapping):
        raise TypeError(f"body must be a mapping, got {type(body).__name__}")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError(
            f"private_key must be an Ed25519PrivateKey, got {type(private_key).__name__}"
        )
    fields = {k: v for k, v in body.items() if k not in _SIGNER_FIELDS}
    canonical = canonicalize(fields)
    canonical_bytes = canonical.encode("utf-8")
    signature = private_key.sign(canonical_bytes)
    return {
        **fields,
        "canonical": canonical,
        "contentHash": "sha256:" + hashlib.sha256(canonical_bytes).hexdigest(),
        "signature": "v2=" + base64.b64encode(signature).decode("ascii"),
    }
