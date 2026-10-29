"""
An MCP server that verifies receipts, for agents.

Three read-only tools over the verifiers in this package, with the same
verdicts and reasons as the TypeScript and Go verifiers:

- ``verify_receipt``: one v2 receipt against the issuer's public key.
- ``verify_receipt_log``: a JSONL log of receipts, one verdict per line.
- ``verify_receipt_in_log``: a receipt's RFC 9162 inclusion proof
  against a tree head's root hash.

The server makes no network request and keeps no state. Run it over
stdio with ``verifiable-receipts-mcp`` (needs the ``mcp`` extra).
"""

from __future__ import annotations

from typing import Any

try:
    from mcp.server.mcpserver import MCPServer
    from mcp.types import ToolAnnotations
except ImportError as err:  # pragma: no cover - depends on the install
    raise SystemExit(
        "verifiable-receipts-mcp needs the mcp extra: "
        "pip install 'sovereign-matrix-verifiable-receipts[mcp]'"
    ) from err

from . import __version__
from .transparency import leaf_hash, verify_inclusion_proof
from .verify import parse_receipt, verify_v2_receipt

MAX_TEXT_BYTES = 4 * 1024 * 1024
"""The largest receipt, log or key text a tool accepts, in UTF-8 bytes."""

MAX_LOG_LINES = 10_000
"""The most receipts ``verify_receipt_log`` checks in one call."""

_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)

server = MCPServer(
    name="verifiable-receipts",
    version=__version__,
    instructions=(
        "Verifies signed receipts of AI agent actions offline. A pass proves the holder of the "
        "issuer's private key signed exactly the receipt's canonical text; it does not prove the "
        "content is true or that the set is complete. Use a public key obtained from the issuer, "
        "never one that arrived with the receipts."
    ),
)


def _too_large(*texts: str) -> str | None:
    for text in texts:
        if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            return f"input larger than {MAX_TEXT_BYTES} bytes"
    return None


def _check(receipt_json: str, pem: bytes) -> dict[str, Any]:
    try:
        receipt = parse_receipt(receipt_json)
    except ValueError as err:
        return {"ok": False, "reason": str(err)}
    result = verify_v2_receipt(receipt, pem)
    return {"ok": result.ok, "reason": result.reason}


@server.tool(title="Verify a receipt", annotations=_READ_ONLY)
def verify_receipt(receipt_json: str, public_key_pem: str) -> dict[str, Any]:
    """Check one v2 receipt against the issuer's Ed25519 public key.

    receipt_json is the receipt's JSON text (an object with canonical, signature and
    usually contentHash). public_key_pem is the issuer's key as PEM. Returns ok and, when
    ok is false, the reason: tampered (contentHash mismatch), a signature that does not
    verify, an envelope field outside the signed canonical, or an unsafe key.
    """
    if problem := _too_large(receipt_json, public_key_pem):
        return {"ok": False, "reason": problem}
    return _check(receipt_json, public_key_pem.encode("utf-8"))


@server.tool(title="Verify a receipt log", annotations=_READ_ONLY)
def verify_receipt_log(receipts_jsonl: str, public_key_pem: str) -> dict[str, Any]:
    """Check every receipt in a JSONL log (one receipt per line) against one public key.

    Blank lines are skipped. Returns the counts and one verdict per receipt with its
    1-based line number. Checking the receipts given says nothing about receipts that
    are missing from the log; use verify_receipt_in_log against a tree head for that.
    """
    if problem := _too_large(receipts_jsonl, public_key_pem):
        return {"ok": False, "reason": problem, "verified": 0, "failed": 0, "results": []}
    lines = [(n, line) for n, line in enumerate(receipts_jsonl.splitlines(), 1) if line.strip()]
    if len(lines) > MAX_LOG_LINES:
        reason = f"more than {MAX_LOG_LINES} receipts in one call"
        return {"ok": False, "reason": reason, "verified": 0, "failed": 0, "results": []}
    pem = public_key_pem.encode("utf-8")
    results = [{"line": n, **_check(line, pem)} for n, line in lines]
    failed = sum(not r["ok"] for r in results)
    return {
        "ok": failed == 0 and bool(results),
        "reason": None if results else "no receipts in the log",
        "verified": len(results) - failed,
        "failed": failed,
        "results": results,
    }


@server.tool(title="Verify a receipt is in a log", annotations=_READ_ONLY)
def verify_receipt_in_log(
    receipt_json: str,
    leaf_index: int,
    tree_size: int,
    audit_path: list[str],
    root_hash_hex: str,
) -> dict[str, Any]:
    """Check an RFC 9162 inclusion proof: that a receipt is leaf leaf_index of the tree
    of tree_size leaves whose root is root_hash_hex.

    The leaf is SHA-256(0x00 || the receipt's canonical text), as the transparency log
    stores it. audit_path holds the sibling hashes from the leaf up, each 64 lowercase hex
    digits. This checks the proof only: verify the receipt's signature with verify_receipt,
    and the tree head's signature with the log's key, separately.
    """
    if problem := _too_large(receipt_json):
        return {"ok": False, "reason": problem}
    try:
        receipt = parse_receipt(receipt_json)
    except ValueError as err:
        return {"ok": False, "reason": str(err)}
    canonical = receipt.get("canonical")
    if not isinstance(canonical, str) or not canonical:
        return {"ok": False, "reason": "missing canonical projection"}
    leaf_hash_hex = leaf_hash(canonical.encode("utf-8")).hex()
    proof = {"leafIndex": leaf_index, "treeSize": tree_size, "auditPath": audit_path}
    ok = verify_inclusion_proof(proof, leaf_hash_hex, root_hash_hex)
    return {
        "ok": ok,
        "reason": None if ok else "inclusion proof does not lead to the root hash",
        "leaf_hash_hex": leaf_hash_hex,
    }


def main() -> None:
    """Run the server over stdio."""
    server.run()


if __name__ == "__main__":
    main()
