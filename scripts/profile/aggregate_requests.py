#!/usr/bin/env python3
"""
Aggregate pyinstrument request profiles from ./profiles/*.html.

The PyinstrumentMiddleware writes one HTML per request. After a Locust run
there are hundreds of them — reading one by one is useless. This rolls
everything up into two views:

    1. Per-endpoint summary (count, mean/p50/p95/max wall-time)
    2. Top hot functions by cumulative self-time across ALL requests

Usage:
    scripts/profile/aggregate_requests.py               # ./profiles/
    scripts/profile/aggregate_requests.py --dir PATH
    scripts/profile/aggregate_requests.py --top 30      # show top 30 funcs
    scripts/profile/aggregate_requests.py --endpoint login   # filter

Self-time of a frame = frame.time - sum(child.time) — i.e. time spent
executing the function's own code, excluding descendants. That's the
right signal for "where is the CPU actually going".
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path


_FILENAME_RE = re.compile(r"^(?P<ts>\d+)-(?P<method>[A-Z]+)-(?P<slug>.+)\.html$")
_SESSION_RE = re.compile(r"const sessionData = (\{.*?\});\s*\n\s*pyinstrumentHTMLRenderer", re.DOTALL)


def load_session(path: Path) -> tuple[dict, dict] | None:
    """Return (session_summary, frame_tree_root) or None."""
    try:
        text = path.read_text()
    except OSError:
        return None
    m = _SESSION_RE.search(text)
    if not m:
        return None
    try:
        payload = json.loads(m.group(1))
        return payload["session"], payload["frame_tree"]
    except (json.JSONDecodeError, KeyError):
        return None


_SYNTHETIC = {"[self]", "[await]"}


def _is_synthetic(identifier: str) -> bool:
    """Pyinstrument leaf markers: `[self]` / `[await]` carry no file/line."""
    return identifier in _SYNTHETIC or identifier.startswith(("[self]", "[await]"))


def walk_self_time(frame: dict, acc: dict[str, float], parent_ident: str | None = None) -> None:
    """
    Accumulate self-time by frame identifier.

    Pyinstrument attaches `[self]` / `[await]` synthetic leaves for non-sampled
    execution time. Rolling them into their parent ("self-time of X" vs. a
    global `[self]` bucket) is what gives us actionable per-function hotspots.
    """
    ident = frame["identifier"]
    total = frame.get("time", 0.0)
    children = frame.get("children") or []
    child_total = sum(c.get("time", 0.0) for c in children)
    self_time = total - child_total

    if _is_synthetic(ident):
        # Reattribute synthetic self-time to the enclosing real function.
        key = parent_ident if parent_ident else ident
        acc[key] = acc.get(key, 0.0) + total
        return

    if self_time > 0:
        acc[ident] = acc.get(ident, 0.0) + self_time
    for c in children:
        walk_self_time(c, acc, parent_ident=ident)


def short_ident(identifier: str) -> str:
    """`func\\x00/abs/path.py\\x00LINE` -> `func  path.py:LINE`."""
    parts = identifier.split("\x00")
    if len(parts) == 3:
        func, path, line = parts
        return f"{func:30s}  {Path(path).name}:{line}"
    return identifier[:80]


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    k = (len(values) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    if lo == hi:
        return values[lo]
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="profiles")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--endpoint", default=None, help="substring filter on endpoint slug")
    args = ap.parse_args()

    root = Path(args.dir)
    files = sorted(root.glob("*.html"))
    if not files:
        raise SystemExit(f"no HTMLs in {root}/")

    per_endpoint: dict[str, list[float]] = defaultdict(list)
    global_self: dict[str, float] = {}
    per_endpoint_self: dict[str, dict[str, float]] = defaultdict(dict)
    parsed = 0
    skipped = 0

    for f in files:
        m = _FILENAME_RE.match(f.name)
        if not m:
            skipped += 1
            continue
        endpoint = f"{m['method']} /{m['slug'].replace('_', '/')}"
        if args.endpoint and args.endpoint not in endpoint:
            continue

        loaded = load_session(f)
        if not loaded:
            skipped += 1
            continue
        session, root_frame = loaded

        duration = session.get("duration", 0.0)
        per_endpoint[endpoint].append(duration)

        walk_self_time(root_frame, global_self)
        walk_self_time(root_frame, per_endpoint_self[endpoint])

        parsed += 1

    print(f"parsed: {parsed}  skipped: {skipped}  from {root}/\n")

    print("=" * 100)
    print("PER-ENDPOINT WALL-TIME")
    print("=" * 100)
    print(f"{'endpoint':<55} {'n':>6} {'mean':>9} {'p50':>9} {'p95':>9} {'max':>9}")
    print("-" * 100)
    rows = sorted(per_endpoint.items(), key=lambda kv: -statistics.mean(kv[1]) * len(kv[1]))
    for ep, durations in rows:
        print(f"{ep[:55]:<55} {len(durations):>6} "
              f"{statistics.mean(durations)*1000:>8.1f}ms "
              f"{percentile(durations,0.50)*1000:>8.1f}ms "
              f"{percentile(durations,0.95)*1000:>8.1f}ms "
              f"{max(durations)*1000:>8.1f}ms")

    print()
    print("=" * 100)
    print(f"TOP {args.top} HOT FUNCTIONS BY CUMULATIVE SELF-TIME (across {parsed} requests)")
    print("=" * 100)
    total_self = sum(global_self.values()) or 1.0
    top = sorted(global_self.items(), key=lambda kv: -kv[1])[: args.top]
    print(f"{'fn  file:line':<70} {'self':>10} {'share':>8}")
    print("-" * 100)
    for ident, t in top:
        share = t / total_self * 100
        print(f"{short_ident(ident):<70} {t*1000:>8.1f}ms {share:>6.1f}%")

    print()
    print("=" * 100)
    print("TOP 3 HOT FUNCTIONS PER ENDPOINT")
    print("=" * 100)
    for ep in sorted(per_endpoint_self, key=lambda e: -sum(per_endpoint_self[e].values())):
        acc = per_endpoint_self[ep]
        ep_total = sum(acc.values()) or 1.0
        print(f"\n{ep}   ({len(per_endpoint[ep])} samples, {ep_total*1000:.0f}ms total self)")
        top3 = sorted(acc.items(), key=lambda kv: -kv[1])[:3]
        for ident, t in top3:
            print(f"  {short_ident(ident):<70} {t*1000:>7.1f}ms  ({t/ep_total*100:>4.1f}%)")


if __name__ == "__main__":
    main()
