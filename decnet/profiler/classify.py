"""Coarse behavior classification for DECNET attacker profiles."""

from __future__ import annotations

from typing import Any

from decnet.telemetry import traced as _traced


@_traced("profiler.classify_behavior")
def classify_behavior(stats: dict[str, Any], services_count: int) -> str:
    """
    Coarse behavior bucket:
      beaconing | interactive | scanning | brute_force | slow_scan | mixed | unknown

    Heuristics (evaluated in priority order):
      * `scanning`    — ≥ 3 services touched OR mean IAT < 2 s, ≥ 3 events
      * `brute_force` — 1 service, n ≥ 8, mean IAT < 5 s, CV < 0.6
      * `beaconing`   — CV < 0.35, mean IAT ≥ 5 s, ≥ 4 events
      * `slow_scan`   — ≥ 2 services, mean IAT ≥ 10 s, ≥ 4 events
      * `interactive` — mean IAT < 5 s AND CV ≥ 0.5, ≥ 6 events
      * `mixed`       — catch-all for sessions with enough data
      * `unknown`     — too few data points
    """
    n = stats.get("event_count") or 0
    mean = stats.get("mean_iat_s")
    cv = stats.get("cv")

    if n < 3 or mean is None:
        return "unknown"

    # Slow scan / low-and-slow: multiple services with long gaps.
    # Must be checked before generic scanning so slow multi-service sessions
    # don't get mis-bucketed as a fast sweep.
    if services_count >= 2 and mean >= 10.0 and n >= 4:
        return "slow_scan"

    # Scanning: broad service sweep (multi-service) or very rapid single-service bursts.
    if n >= 3 and (
        (services_count >= 3 and mean < 10.0)
        or (services_count >= 2 and mean < 2.0)
    ):
        return "scanning"

    # Brute force: hammering one service rapidly and repeatedly.
    if services_count == 1 and n >= 8 and mean < 5.0 and cv is not None and cv < 0.6:
        return "brute_force"

    # Beaconing: regular cadence over multiple events.
    if cv is not None and cv < 0.35 and mean >= 5.0 and n >= 4:
        return "beaconing"

    # Interactive: short but irregular bursts (human or tool with think time).
    if cv is not None and cv >= 0.5 and mean < 5.0 and n >= 6:
        return "interactive"

    return "mixed"
