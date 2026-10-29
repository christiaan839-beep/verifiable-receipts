"""
The verify-receipts Agent Skill (skills/verify-receipts): its SKILL.md
frontmatter against the agentskills.io specification, and its script
against every v2 conformance fixture.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_SKILL = _ROOT / "skills" / "verify-receipts"
_SCRIPT = _SKILL / "scripts" / "verify_receipts.py"
_CONFORMANCE = _ROOT / "packages" / "verifiable-receipts" / "conformance"
_PACKAGE = _ROOT / "packages" / "verifiable-receipts-py"


def _frontmatter() -> dict[str, str]:
    text = (_SKILL / "SKILL.md").read_text(encoding="utf-8")
    match = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
    assert match, "SKILL.md must start with YAML frontmatter"
    fields: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if line and not line.startswith(" "):
            key, _, value = line.partition(":")
            fields[key] = value.strip()
    return fields


def test_frontmatter_follows_the_specification() -> None:
    fields = _frontmatter()
    assert set(fields) <= {
        "name",
        "description",
        "license",
        "compatibility",
        "metadata",
        "allowed-tools",
    }
    name = fields["name"]
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name) and len(name) <= 64
    assert name == _SKILL.name
    assert 0 < len(fields["description"]) <= 1024
    assert 0 < len(fields["compatibility"]) <= 500


def _run(*args: str | Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(_PACKAGE)}
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *map(str, args)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _v2_fixtures() -> list[Path]:
    return sorted((_CONFORMANCE / "fixtures").glob("v2-*.json"))


@pytest.mark.parametrize("path", _v2_fixtures(), ids=lambda p: p.name)
def test_script_matches_each_fixture(path: Path, tmp_path: Path) -> None:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    receipt = tmp_path / "receipt.json"
    text = fixture.get("receiptText") or json.dumps(fixture["receipt"])
    receipt.write_text(text, encoding="utf-8")
    key = _CONFORMANCE / "public-key.pem"
    if "publicKeyPem" in fixture:
        key = tmp_path / "key.pem"
        key.write_text(fixture["publicKeyPem"], encoding="utf-8")

    result = _run("--pubkey", key, receipt)

    verdict = json.loads(result.stdout)
    assert verdict["ok"] is fixture["expected"]["ok"], verdict
    assert result.returncode == (0 if verdict["ok"] else 1)
    pattern = fixture["expected"].get("reasonContains")
    if pattern:
        assert re.search(pattern, verdict["reason"], re.IGNORECASE), verdict


def test_jsonl_reports_each_line(tmp_path: Path) -> None:
    good = json.loads((_CONFORMANCE / "fixtures" / "v2-valid-001.json").read_text())["receipt"]
    bad = json.loads((_CONFORMANCE / "fixtures" / "v2-invalid-tampered.json").read_text())
    log = tmp_path / "receipts.jsonl"
    log.write_text(json.dumps(good) + "\n\n" + json.dumps(bad["receipt"]) + "\n", "utf-8")

    result = _run("--pubkey", _CONFORMANCE / "public-key.pem", log)

    verdicts = [json.loads(line) for line in result.stdout.splitlines()]
    assert [(v["line"], v["ok"]) for v in verdicts] == [(1, True), (3, False)]
    assert result.returncode == 1
    assert "1 verified, 1 failed" in result.stderr


def test_non_object_receipt_fails(tmp_path: Path) -> None:
    receipt = tmp_path / "receipt.json"
    receipt.write_text("[1, 2]", encoding="utf-8")
    result = _run("--pubkey", _CONFORMANCE / "public-key.pem", receipt)
    assert result.returncode == 1
    assert json.loads(result.stdout)["ok"] is False


def test_missing_file_is_a_usage_error(tmp_path: Path) -> None:
    result = _run("--pubkey", _CONFORMANCE / "public-key.pem", tmp_path / "absent.json")
    assert result.returncode == 2
    assert result.stdout == ""
