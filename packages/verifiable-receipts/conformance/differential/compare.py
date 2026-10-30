"""
Compares the three verifiers' verdicts on the differential cases.

Usage: python compare.py <cases.jsonl> <ts.jsonl> <py.jsonl> <go.jsonl> <disagreements.jsonl>
Exits 1 when the verifiers disagree on any case, in verdict or in reason
(for receipts all three; for Guardian attestations Python and Go, since
the TypeScript library names its reasons its own way), or any raised;
the cases go to <disagreements.jsonl> with each verifier's verdict.

Each runner writes one verdict per case, in case order, so the four
files are read a line at a time, side by side: memory does not grow
with the number of cases. A verdict missing, extra or out of order
fails the run ("missing verdict"), and the comparison stops there.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from contextlib import ExitStack
from typing import IO, Any

NAMES = ["typescript", "python", "go"]
SHOWN = 10  # disagreements printed; all are written to the file


def next_verdict(fh: IO[str]) -> dict[str, Any] | None:
    line = fh.readline()
    return json.loads(line) if line else None


def main() -> int:
    cases_path, out_path = sys.argv[1], sys.argv[5]
    stats: Counter[str] = Counter()
    bad_count = 0
    shown: list[dict[str, object]] = []
    with ExitStack() as stack:
        cases = stack.enter_context(open(cases_path, encoding="utf-8"))
        files = [stack.enter_context(open(p, encoding="utf-8")) for p in sys.argv[2:5]]
        out = stack.enter_context(open(out_path, "w", encoding="utf-8"))

        def report(entry: dict[str, object]) -> None:
            nonlocal bad_count
            bad_count += 1
            out.write(json.dumps(entry, ensure_ascii=False) + "\n")
            if len(shown) < SHOWN:
                shown.append(entry)

        for line in cases:
            case = json.loads(line)
            read = {n: next_verdict(fh) for n, fh in zip(NAMES, files, strict=True)}
            verdicts = {n: v for n, v in read.items() if v is not None and v["id"] == case["id"]}
            if len(verdicts) < len(NAMES):
                report({**case, "verdicts": read, "why": "missing verdict"})
                break
            oks = {n: v["ok"] for n, v in verdicts.items()}
            reasons = {n: v.get("reason") for n, v in verdicts.items()}
            threw = {n: v["threw"] for n, v in verdicts.items() if "threw" in v}
            # Receipts: all three give the same reason. Guardian attestations:
            # Python and Go do; the TypeScript library names its own reasons.
            compared = NAMES if case["kind"] == "receipt" else ["python", "go"]
            if case["kind"] == "inclusion":
                compared = []
            if (
                threw
                or len(set(oks.values())) > 1
                or len({reasons[n] for n in compared}) > 1
            ):
                report({**case, "verdicts": oks, "reasons": reasons, "threw": threw})
            else:
                stats[
                    f"{case['kind']} {'accepted' if next(iter(oks.values())) else 'rejected'}"
                ] += 1
        else:
            extra = {n: next_verdict(fh) for n, fh in zip(NAMES, files, strict=True)}
            if any(v is not None for v in extra.values()):
                report({"verdicts": extra, "why": "missing verdict"})
    for k in sorted(stats):
        print(f"  {k} by all three: {stats[k]}")
    if bad_count:
        print(f"FAIL: {bad_count} case(s) where the verifiers disagree or raised; see {out_path}")
        for b in shown:
            print("  ", json.dumps(b, ensure_ascii=False)[:400])
        return 1
    print("all three verifiers agree on every case")
    return 0


if __name__ == "__main__":
    sys.exit(main())
