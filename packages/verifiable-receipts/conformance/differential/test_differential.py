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
import subprocess
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
        [0, 2, 1, *range(3, 50)],  # verdicts out of order
        [*range(11), 10, *range(12, 50)],  # a verdict repeated in place of the next
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


def test_gen_is_reproducible_from_the_seed(tmp_path: Path) -> None:
    gen = HERE / "gen.py"
    runs = {}
    for name, seed in (("a", "5"), ("b", "5"), ("c", "6")):
        out = tmp_path / name
        subprocess.run([sys.executable, str(gen), str(out), "300", seed], check=True)
        runs[name] = ((out / "public.pem").read_bytes(), (out / "cases.jsonl").read_bytes())
    assert runs["a"] == runs["b"]
    assert runs["a"][0] != runs["c"][0]
    assert runs["a"][1] != runs["c"][1]


def write_failed_run(out: Path, count: int, bad_ids: list[int]) -> None:
    out.mkdir()
    write_cases(out / "cases.jsonl", count)
    (out / "public.pem").write_bytes(PUBLIC_KEY.read_bytes())
    (out / "run.json").write_text(json.dumps({"cases": count, "seed": 9}) + "\n")
    (out / "summary.txt").write_text(f"FAIL: {len(bad_ids)} case(s)\n")
    with (out / "disagreements.jsonl").open("w") as fh:
        for i in bad_ids:
            fh.write(json.dumps({"id": i, "kind": "inclusion", "why": "test"}) + "\n")


def test_collect_keeps_what_reproduces_a_failure(tmp_path: Path) -> None:
    out, repro = tmp_path / "out", tmp_path / "repro"
    write_failed_run(out, 1_000, [3, 500, 999])
    subprocess.run([sys.executable, str(HERE / "collect.py"), str(out), str(repro)], check=True)
    assert sorted(p.name for p in repro.iterdir()) == [
        "cases-failing.jsonl",
        "disagreements.jsonl",
        "public.pem",
        "run.json",
        "summary.txt",
    ]
    lines = (repro / "cases-failing.jsonl").read_text().splitlines()
    failing = [json.loads(line) for line in lines]
    assert [c["id"] for c in failing] == [3, 500, 999]
    assert failing[1]["raw"] == inclusion_raw(500)
    run = json.loads((repro / "run.json").read_text())
    assert run["cases"] == 1_000 and run["seed"] == 9
    assert run["disagreements"] == 3 and run["included"] == 3
    assert run["reproduce"].endswith("run.sh 1000 9 <out-dir>")


def test_collect_is_bounded(tmp_path: Path) -> None:
    out, repro = tmp_path / "out", tmp_path / "repro"
    write_failed_run(out, 1_000, list(range(1_000)))
    args = [sys.executable, str(HERE / "collect.py"), str(out), str(repro), "20"]
    subprocess.run(args, check=True)
    assert len((repro / "disagreements.jsonl").read_text().splitlines()) == 20
    failing = (repro / "cases-failing.jsonl").read_text().splitlines()
    assert [json.loads(line)["id"] for line in failing] == list(range(20))
    run = json.loads((repro / "run.json").read_text())
    assert run["disagreements"] == 1_000 and run["included"] == 20


def test_collect_without_disagreements(tmp_path: Path) -> None:
    # A runner that crashes leaves no disagreements.jsonl; the rest is kept.
    out, repro = tmp_path / "out", tmp_path / "repro"
    write_failed_run(out, 10, [])
    (out / "disagreements.jsonl").unlink()
    subprocess.run([sys.executable, str(HERE / "collect.py"), str(out), str(repro)], check=True)
    assert json.loads((repro / "run.json").read_text())["disagreements"] == 0
    assert (repro / "public.pem").exists() and not (repro / "cases-failing.jsonl").exists()


@pytest.mark.parametrize(
    "broken",
    ["\n", '{"id": 20, "ok": fal\n', '{"id": 20, "ok"'],  # blank, truncated, cut off at EOF
)
def test_compare_reports_an_unreadable_verdict_as_missing(
    tmp_path: Path,
    broken: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    count = 50
    write_cases(tmp_path / "cases.jsonl", count)
    write_verdicts(tmp_path / "ts.jsonl", range(count))
    write_verdicts(tmp_path / "py.jsonl", range(count))
    write_verdicts(tmp_path / "go.jsonl", range(20))
    with (tmp_path / "go.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(broken)
    args = [str(tmp_path / f) for f in ("cases.jsonl", "ts.jsonl", "py.jsonl", "go.jsonl")]
    code, _ = run_main(load("compare"), [*args, str(tmp_path / "bad.jsonl")], monkeypatch)
    assert code == 1
    assert "missing verdict" in capsys.readouterr().out
    bad = [json.loads(line) for line in (tmp_path / "bad.jsonl").read_text().splitlines()]
    assert bad[-1]["id"] == 20 and bad[-1]["why"] == "missing verdict"
    assert bad[-1]["verdicts"]["go"] == {"id": None, "unparsed": broken}


def test_collect_skips_a_truncated_disagreement(tmp_path: Path) -> None:
    # compare.py killed mid-write leaves its last line cut off.
    out, repro = tmp_path / "out", tmp_path / "repro"
    write_failed_run(out, 1_000, [3, 500, 999])
    with (out / "disagreements.jsonl").open("a") as fh:
        fh.write('{"id": 7, "kind": "inclu')
    subprocess.run([sys.executable, str(HERE / "collect.py"), str(out), str(repro)], check=True)
    run = json.loads((repro / "run.json").read_text())
    assert run["disagreements"] == 3 and run["included"] == 3 and run["skipped"] == 1
    assert run["reproduce"].endswith("run.sh 1000 9 <out-dir>")
    copied = (repro / "disagreements.jsonl").read_text().splitlines()
    assert [json.loads(line)["id"] for line in copied] == [3, 500, 999]
    lines = (repro / "cases-failing.jsonl").read_text().splitlines()
    assert [json.loads(line)["id"] for line in lines] == [3, 500, 999]


def test_collect_writes_run_json_first(tmp_path: Path) -> None:
    # Whatever stops collect.py part way, the count, seed and rerun command are already there.
    out, repro = tmp_path / "out", tmp_path / "repro"
    write_failed_run(out, 1_000, [3])
    (out / "cases.jsonl").unlink()
    (out / "cases.jsonl").mkdir()  # reading it fails
    args = [sys.executable, str(HERE / "collect.py"), str(out), str(repro)]
    assert subprocess.run(args, capture_output=True).returncode != 0
    run = json.loads((repro / "run.json").read_text())
    assert run["cases"] == 1_000 and run["seed"] == 9
    assert run["reproduce"].endswith("run.sh 1000 9 <out-dir>")
