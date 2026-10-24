"""
Compares the three verifiers' verdicts on the differential cases.

Usage: python compare.py <cases.jsonl> <ts.jsonl> <py.jsonl> <go.jsonl> <disagreements.jsonl>
Exits 1 when the verifiers disagree on any case, in verdict or in reason
(for receipts all three; for Guardian attestations Python and Go, since
the TypeScript library names its reasons its own way), or any raised;
the cases go to <disagreements.jsonl> with each verifier's verdict.
"""

from __future__ import annotations

import json
import sys
from collections import Counter


def load(path: str) -> dict[int, dict[str, object]]:
    with open(path, encoding="utf-8") as fh:
        return {r["id"]: r for r in map(json.loads, fh) if r}


def main() -> int:
    cases_path, out_path = sys.argv[1], sys.argv[5]
    names = ["typescript", "python", "go"]
    results = dict(zip(names, (load(p) for p in sys.argv[2:5]), strict=True))
    stats: Counter[str] = Counter()
    bad = []
    with open(cases_path, encoding="utf-8") as fh:
        for case in map(json.loads, fh):
            verdicts = {n: results[n].get(case["id"]) for n in names}
            if any(v is None for v in verdicts.values()):
                bad.append({**case, "verdicts": verdicts, "why": "missing verdict"})
                continue
            oks = {n: v["ok"] for n, v in verdicts.items()}
            reasons = {n: v.get("reason") for n, v in verdicts.items()}
            threw = {n: v["threw"] for n, v in verdicts.items() if "threw" in v}
            # Receipts: all three give the same reason. Guardian attestations:
            # Python and Go do; the TypeScript library names its own reasons.
            compared = names if case["kind"] == "receipt" else ["python", "go"]
            if case["kind"] == "inclusion":
                compared = []
            if (
                threw
                or len(set(oks.values())) > 1
                or len({reasons[n] for n in compared}) > 1
            ):
                bad.append({**case, "verdicts": oks, "reasons": reasons, "threw": threw})
            else:
                stats[
                    f"{case['kind']} {'accepted' if next(iter(oks.values())) else 'rejected'}"
                ] += 1
    with open(out_path, "w", encoding="utf-8") as fh:
        for b in bad:
            fh.write(json.dumps(b, ensure_ascii=False) + "\n")
    for k in sorted(stats):
        print(f"  {k} by all three: {stats[k]}")
    if bad:
        print(f"FAIL: {len(bad)} case(s) where the verifiers disagree or raised; see {out_path}")
        for b in bad[:10]:
            print("  ", json.dumps(b, ensure_ascii=False)[:400])
        return 1
    print("all three verifiers agree on every case")
    return 0


if __name__ == "__main__":
    sys.exit(main())
