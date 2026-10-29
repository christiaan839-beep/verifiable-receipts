"""
The MCP server (mcp_server.py), driven through the MCP SDK's own client:
in process for the tools, and once over stdio as a client would start it.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")

from mcp import Client, StdioServerParameters  # noqa: E402
from sovereign_matrix.verifiable_receipts import inner_hash, leaf_hash  # noqa: E402
from sovereign_matrix.verifiable_receipts.mcp_server import (  # noqa: E402
    MAX_LOG_LINES,
    MAX_TEXT_BYTES,
    server,
)

_PACKAGE = Path(__file__).resolve().parents[1]
_CONFORMANCE = _PACKAGE.parent / "verifiable-receipts" / "conformance"
_PEM = (_CONFORMANCE / "public-key.pem").read_text(encoding="utf-8")


def _fixture(name: str) -> dict[str, Any]:
    return json.loads((_CONFORMANCE / "fixtures" / name).read_text(encoding="utf-8"))


def _call(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    async def go() -> dict[str, Any]:
        async with Client(server) as client:
            result = await client.call_tool(tool, arguments)
        assert not result.is_error, result
        assert result.structured_content is not None
        return result.structured_content

    return asyncio.run(go())


def test_tools_are_read_only_and_closed_world() -> None:
    async def go() -> list[Any]:
        async with Client(server) as client:
            return (await client.list_tools()).tools

    tools = asyncio.run(go())
    assert sorted(t.name for t in tools) == [
        "verify_receipt",
        "verify_receipt_in_log",
        "verify_receipt_log",
    ]
    for tool in tools:
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert tool.annotations.open_world_hint is False


@pytest.mark.parametrize(
    "path",
    sorted((_CONFORMANCE / "fixtures").glob("v2-*.json")),
    ids=lambda p: p.name,
)
def test_verify_receipt_matches_each_fixture(path: Path) -> None:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    text = fixture.get("receiptText") or json.dumps(fixture["receipt"])
    verdict = _call(
        "verify_receipt",
        {"receipt_json": text, "public_key_pem": fixture.get("publicKeyPem", _PEM)},
    )
    assert verdict["ok"] is fixture["expected"]["ok"], verdict
    pattern = fixture["expected"].get("reasonContains")
    if pattern:
        assert pattern.lower() in verdict["reason"].lower(), verdict


def test_verify_receipt_rejects_oversized_input() -> None:
    verdict = _call(
        "verify_receipt",
        {"receipt_json": " " * (MAX_TEXT_BYTES + 1), "public_key_pem": _PEM},
    )
    assert verdict == {"ok": False, "reason": f"input larger than {MAX_TEXT_BYTES} bytes"}


def test_verify_receipt_log_reports_each_line() -> None:
    good = json.dumps(_fixture("v2-valid-001.json")["receipt"])
    bad = json.dumps(_fixture("v2-invalid-tampered.json")["receipt"])
    verdict = _call(
        "verify_receipt_log",
        {"receipts_jsonl": f"{good}\n\n{bad}\nnot json\n", "public_key_pem": _PEM},
    )
    assert (verdict["ok"], verdict["verified"], verdict["failed"]) == (False, 1, 2)
    assert [(r["line"], r["ok"]) for r in verdict["results"]] == [
        (1, True),
        (3, False),
        (4, False),
    ]
    assert verdict["results"][2]["reason"] == "receipt is not valid JSON"


def test_verify_receipt_log_all_valid_and_empty() -> None:
    good = json.dumps(_fixture("v2-valid-001.json")["receipt"])
    verdict = _call("verify_receipt_log", {"receipts_jsonl": good, "public_key_pem": _PEM})
    assert (verdict["ok"], verdict["verified"], verdict["failed"]) == (True, 1, 0)
    empty = _call("verify_receipt_log", {"receipts_jsonl": "\n", "public_key_pem": _PEM})
    assert (empty["ok"], empty["reason"]) == (False, "no receipts in the log")


def test_verify_receipt_log_caps_the_line_count() -> None:
    verdict = _call(
        "verify_receipt_log",
        {"receipts_jsonl": "{}\n" * (MAX_LOG_LINES + 1), "public_key_pem": _PEM},
    )
    assert verdict["ok"] is False
    assert verdict["reason"] == f"more than {MAX_LOG_LINES} receipts in one call"
    assert verdict["results"] == []


def _two_leaf_tree() -> tuple[str, str, str, str]:
    """A receipt at leaf 0 of a two-leaf tree: its JSON, its leaf hash, the sibling, the root."""
    receipt = _fixture("v2-valid-001.json")["receipt"]
    mine = leaf_hash(receipt["canonical"].encode("utf-8"))
    sibling = leaf_hash(b'{"verdictId":"v_other"}')
    return json.dumps(receipt), mine.hex(), sibling.hex(), inner_hash(mine, sibling).hex()


def test_verify_receipt_in_log_accepts_a_valid_proof() -> None:
    receipt, mine, sibling, root = _two_leaf_tree()
    verdict = _call(
        "verify_receipt_in_log",
        {
            "receipt_json": receipt,
            "leaf_index": 0,
            "tree_size": 2,
            "audit_path": [sibling],
            "root_hash_hex": root,
        },
    )
    assert verdict == {"ok": True, "reason": None, "leaf_hash_hex": mine}


def test_verify_receipt_in_log_rejects_a_wrong_position_or_root() -> None:
    receipt, _, sibling, root = _two_leaf_tree()
    base = {"receipt_json": receipt, "tree_size": 2, "audit_path": [sibling]}
    wrong_index = _call("verify_receipt_in_log", {**base, "leaf_index": 1, "root_hash_hex": root})
    wrong_root = _call(
        "verify_receipt_in_log", {**base, "leaf_index": 0, "root_hash_hex": "0" * 64}
    )
    for verdict in (wrong_index, wrong_root):
        assert verdict["ok"] is False
        assert verdict["reason"] == "inclusion proof does not lead to the root hash"


@pytest.mark.parametrize(
    ("receipt_json", "reason"),
    [
        ('{"signature": "v2=AA=="}', "missing canonical projection"),
        ('{"canonical": ""}', "missing canonical projection"),
        ("[" * 100 + "]" * 100, "receipt nesting deeper than 64"),
        ("nope", "receipt is not valid JSON"),
    ],
)
def test_verify_receipt_in_log_rejects_a_bad_receipt(receipt_json: str, reason: str) -> None:
    verdict = _call(
        "verify_receipt_in_log",
        {
            "receipt_json": receipt_json,
            "leaf_index": 0,
            "tree_size": 1,
            "audit_path": [],
            "root_hash_hex": "0" * 64,
        },
    )
    assert verdict == {"ok": False, "reason": reason}


def test_runs_over_stdio() -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "sovereign_matrix.verifiable_receipts.mcp_server"],
        env={**os.environ, "PYTHONPATH": str(_PACKAGE)},
    )

    async def go() -> dict[str, Any]:
        async with Client(params) as client:
            result = await client.call_tool(
                "verify_receipt",
                {
                    "receipt_json": json.dumps(_fixture("v2-valid-001.json")["receipt"]),
                    "public_key_pem": _PEM,
                },
            )
        assert result.structured_content is not None
        return result.structured_content

    assert asyncio.run(go()) == {"ok": True, "reason": None}
