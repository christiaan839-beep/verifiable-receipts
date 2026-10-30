"""
The differential run's Python runner and its comparison stream: memory
stays the same however many cases there are, every case is judged and
compared, and verdicts are compared case by case, in case order.

Run from the repo root:
    PYTHONPATH=packages/verifiable-receipts-py python -m pytest \
        packages/verifiable-receipts/conformance/differential
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tracemalloc
from pathlib import Path
from types import ModuleType

import pytest

HERE = Path(__file__).resolve().parent
PUBLIC_KEY = HERE.parent / "public-key.pem"
# Peak traced allocation allowed while judging or comparing. Runners that
# keep every verdict in memory pass it: at 30,000 cases verify.py held
# about 5 MB and compare.py about 35 MB.
BOUND = 2 * 1024 * 1024


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"differential_{name}", HERE / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_main(
    module: ModuleType, args: list[str], monkeypatch: pytest.MonkeyPatch
) -> tuple[int, int]:
    """Runs module.main() with args; returns its exit code and peak traced bytes."""
    monkeypatch.setattr(sys, "argv", [module.__file__, *args])
    tracemalloc.start()
    try:
        code = module.main()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return code, peak


def inclusion_raw(i: int) -> str:
    # The root is wrong, so every verifier rejects it.
    return json.dumps(
        {
            "leafHashHex": f"{i:064x}",
            "leafIndex": 0,
            "treeSize": 2,
            "auditPath": ["ab" * 32],
            "rootHashHex": "11" * 32,
        }
    )


def write_cases(path: Path, count: int) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for i in range(count):
            fh.write(json.dumps({"id": i, "kind": "inclusion", "raw": inclusion_raw(i)}) + "\n")


def write_verdicts(path: Path, verdicts: list[dict[str, object]] | range) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for v in verdicts:
            if isinstance(v, int):
                v = {"id": v, "ok": False, "reason": None}
            fh.write(json.dumps(v) + "\n")


@pytest.mark.parametrize("count", [3_000, 30_000])
def test_verify_judges_every_case_in_bounded_memory(
    tmp_path: Path, count: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_cases(tmp_path / "cases.jsonl", count)
    out = tmp_path / "py.jsonl"
    module = load("verify")
    code, peak = run_main(
        module, [str(PUBLIC_KEY), str(tmp_path / "cases.jsonl"), str(out)], monkeypatch
    )
    assert code == 0
    assert peak < BOUND, f"peak {peak} bytes for {count} cases"
    with out.open(encoding="utf-8") as fh:
        verdicts = [json.loads(line) for line in fh]
    assert verdicts == [{"id": i, "ok": False, "reason": None} for i in range(count)]


@pytest.mark.parametrize("count", [3_000, 30_000])
def test_compare_agreement_in_bounded_memory(
    tmp_path: Path, count: int, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write_cases(tmp_path / "cases.jsonl", count)
    for name in ("ts", "py", "go"):
        write_verdicts(tmp_path / f"{name}.jsonl", range(count))
    args = [str(tmp_path / f) for f in ("cases.jsonl", "ts.jsonl", "py.jsonl", "go.jsonl")]
    code, peak = run_main(load("compare"), [*args, str(tmp_path / "bad.jsonl")], monkeypatch)
    assert code == 0
    assert peak < BOUND, f"peak {peak} bytes for {count} cases"
    assert f"inclusion rejected by all three: {count}" in capsys.readouterr().out
    assert (tmp_path / "bad.jsonl").read_text() == ""


def test_compare_reports_each_disagreement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    count = 50
    write_cases(tmp_path / "cases.jsonl", count)
    write_verdicts(tmp_path / "ts.jsonl", range(count))
    go = [{"id": i, "ok": i == 7, "reason": None} for i in range(count)]
    go[9] = {"id": 9, "ok": False, "threw": "panic"}
    write_verdicts(tmp_path / "go.jsonl", go)
    write_verdicts(tmp_path / "py.jsonl", range(count))
    args = [str(tmp_path / f) for f in ("cases.jsonl", "ts.jsonl", "py.jsonl", "go.jsonl")]
    code, _ = run_main(load("compare"), [*args, str(tmp_path / "bad.jsonl")], monkeypatch)
    assert code == 1
    bad = [json.loads(line) for line in (tmp_path / "bad.jsonl").read_text().splitlines()]
    assert [b["id"] for b in bad] == [7, 9]
    assert bad[0]["verdicts"] == {"typescript": False, "python": False, "go": True}
    assert bad[0]["raw"] == inclusion_raw(7)
    assert bad[1]["threw"] == {"go": "panic"}


@pytest.mark.parametrize(
    "go",
    [
        list(range(49)),  # a verdict missing at the end
        [*range(10), *range(11, 50)],  # a verdict missing in the middle
        [*range(50), 50],  # a verdict for a case that does not exist
    ],
)
def test_compare_fails_when_verdicts_are_out_of_step(
    tmp_path: Path, go: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    count = 50
    write_cases(tmp_path / "cases.jsonl", count)
    write_verdicts(tmp_path / "ts.jsonl", range(count))
    write_verdicts(tmp_path / "py.jsonl", range(count))
    write_verdicts(tmp_path / "go.jsonl", [{"id": i, "ok": False, "reason": None} for i in go])
    args = [str(tmp_path / f) for f in ("cases.jsonl", "ts.jsonl", "py.jsonl", "go.jsonl")]
    code, _ = run_main(load("compare"), [*args, str(tmp_path / "bad.jsonl")], monkeypatch)
    assert code == 1
    bad = [json.loads(line) for line in (tmp_path / "bad.jsonl").read_text().splitlines()]
    assert bad and bad[-1]["why"] == "missing verdict"
