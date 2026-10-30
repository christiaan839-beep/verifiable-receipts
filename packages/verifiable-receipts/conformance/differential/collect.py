"""
Gathers what reproduces a failed differential run, without cases.jsonl.

Usage: python collect.py <out-dir> <repro-dir> [max-cases]

Copies run.json (the case count and seed), summary.txt and public.pem
from <out-dir>, the first <max-cases> (default 50) entries of
disagreements.jsonl, and those entries' lines of cases.jsonl as
cases-failing.jsonl. run.json gains the number of disagreements, how
many are included, and the command that reruns the whole run: the seed
gives back the same cases and key. run.json is written first, so it is
there whatever stops the collection. A disagreements.jsonl line that
does not parse (compare.py killed mid-write) is skipped and counted in
run.json. Files that a failed run did not get to write are left out.
cases.jsonl is read a line at a time and never copied, so the result
stays small however many cases there were.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

ID = re.compile(r'\{"id": (\d+),')


def main() -> int:
    out, repro = Path(sys.argv[1]), Path(sys.argv[2])
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    repro.mkdir(parents=True, exist_ok=True)
    for name in ("summary.txt", "public.pem"):
        if (out / name).exists():
            shutil.copyfile(out / name, repro / name)
    run: dict[str, object] = {}
    if (out / "run.json").exists():
        run = json.loads((out / "run.json").read_text(encoding="utf-8"))
    if "cases" in run and "seed" in run:
        run["reproduce"] = (
            "bash packages/verifiable-receipts/conformance/differential/run.sh "
            f"{run['cases']} {run['seed']} <out-dir>"
        )

    def write_run() -> None:
        (repro / "run.json").write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")

    write_run()

    total, skipped, wanted = 0, 0, set()
    if (out / "disagreements.jsonl").exists():
        with (
            (out / "disagreements.jsonl").open(encoding="utf-8") as src,
            (repro / "disagreements.jsonl").open("w", encoding="utf-8") as dst,
        ):
            for line in src:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue
                total += 1
                if total <= limit:
                    dst.write(line if line.endswith("\n") else line + "\n")
                    if isinstance(entry.get("id"), int):
                        wanted.add(entry["id"])
    run.update(disagreements=total, included=min(total, limit), skipped=skipped)
    write_run()

    if wanted and (out / "cases.jsonl").exists():
        last = max(wanted)
        with (
            (out / "cases.jsonl").open(encoding="utf-8") as src,
            (repro / "cases-failing.jsonl").open("w", encoding="utf-8") as dst,
        ):
            for line in src:
                m = ID.match(line)
                case_id = int(m.group(1)) if m else json.loads(line)["id"]
                if case_id in wanted:
                    dst.write(line)
                if case_id >= last:
                    break

    print(f"{min(total, limit)} of {total} disagreement(s) collected in {repro}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
