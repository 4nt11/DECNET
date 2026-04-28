#!/usr/bin/env python3
"""
Classify the shape of a memray usage_over_time.csv as plateau, climb,
or climb-and-drop. Operates on the `memory_size_bytes` column.

Usage:
    scripts/profile/classify_usage.py profiles/usage_over_time.csv
    scripts/profile/classify_usage.py                  # newest *.csv in ./profiles/
"""
from __future__ import annotations

import csv
import statistics
import sys
from pathlib import Path


def _mb(n: float) -> str:
    return f"{n / (1024 * 1024):.1f} MB"


def load(path: Path) -> list[tuple[int, int]]:
    with path.open() as f:
        rows = list(csv.DictReader(f))
    out: list[tuple[int, int]] = []
    for r in rows:
        try:
            out.append((int(r["timestamp"]), int(r["memory_size_bytes"])))
        except (KeyError, ValueError):
            continue
    if not out:
        sys.exit(f"no usable rows in {path}")
    out.sort(key=lambda t: t[0])
    return out


def classify(series: list[tuple[int, int]]) -> None:
    mem = [v for _, v in series]
    n = len(mem)
    peak = max(mem)
    peak_idx = mem.index(peak)

    # Pre-peak baseline = first 10% of samples.
    baseline = statistics.median(mem[: max(1, n // 10)])

    # Plateau = last 10% of samples (what we settle to).
    plateau = statistics.median(mem[-max(1, n // 10) :])

    # "Tail drop" — how much we released after the peak.
    tail_drop = peak - plateau
    tail_drop_pct = (tail_drop / peak * 100) if peak else 0.0

    # "Growth during run" — end vs beginning.
    net_growth = plateau - baseline
    net_growth_pct = (net_growth / baseline * 100) if baseline else 0.0

    # Where is the peak in the timeline?
    peak_position = peak_idx / (n - 1) if n > 1 else 0.0

    print(f"samples: {n}")
    print(f"baseline (first 10%): {_mb(baseline)}")
    print(f"peak:                 {_mb(peak)}  at {peak_position:.0%} of run")
    print(f"plateau (last 10%):   {_mb(plateau)}")
    print(f"tail drop:            {_mb(tail_drop)}  ({tail_drop_pct:+.1f}% vs peak)")
    print(f"net growth:           {_mb(net_growth)}  ({net_growth_pct:+.1f}% vs baseline)")
    print()

    # Heuristic: the only reliable leak signal without a post-load rest
    # period is how much memory was released AFTER the peak. Net-growth-vs-
    # cold-start is not useful — an active workload always grows vs. a cold
    # interpreter.
    #
    # Caveat: if the workload was still running when memray stopped,
    # "sustained-at-peak" is inconclusive (not necessarily a leak). Re-run
    # with a rest period after the scan for a definitive answer.
    if tail_drop_pct >= 10:
        print("verdict: CLIMB-AND-DROP — memory released after peak.")
        print("         → no leak. Profile CPU next (pyinstrument).")
    elif tail_drop_pct >= 3:
        print("verdict: MOSTLY-RELEASED — partial release after peak.")
        print("         → likely healthy; re-run with a rest period after load")
        print("           to confirm (memray should capture post-workload idle).")
    else:
        print("verdict: SUSTAINED-AT-PEAK — memory held near peak at end of capture.")
        print("         → AMBIGUOUS: could be a leak, or the workload was still")
        print("           running when memray stopped. Re-run with a rest period")
        print("           after load, then check: memray flamegraph --leaks <bin>")


def main() -> None:
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
    else:
        profiles = Path("profiles")
        csvs = sorted(profiles.glob("*.csv"), key=lambda p: p.stat().st_mtime)
        if not csvs:
            sys.exit("no CSV found; pass a path or put one in ./profiles/")
        target = csvs[-1]

    print(f"analyzing {target}\n")
    classify(load(target))


if __name__ == "__main__":
    main()
