"""Inter-arrival timing statistics for DECNET attacker profiles."""

from __future__ import annotations

import statistics
from typing import Any

from decnet.correlation.parser import LogEvent
from decnet.telemetry import traced as _traced


@_traced("profiler.timing_stats")
def timing_stats(events: list[LogEvent]) -> dict[str, Any]:
    """
    Compute inter-arrival-time statistics across *events* (sorted by ts).

    Returns a dict with:
      mean_iat_s, median_iat_s, stdev_iat_s, min_iat_s, max_iat_s, cv,
      event_count, duration_s

    For n < 2 events the interval-based fields are None/0.
    """
    if not events:
        return {
            "event_count": 0,
            "duration_s": 0.0,
            "mean_iat_s": None,
            "median_iat_s": None,
            "stdev_iat_s": None,
            "min_iat_s": None,
            "max_iat_s": None,
            "cv": None,
        }

    sorted_events = sorted(events, key=lambda e: e.timestamp)
    duration_s = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds()

    if len(sorted_events) < 2:
        return {
            "event_count": len(sorted_events),
            "duration_s": round(duration_s, 3),
            "mean_iat_s": None,
            "median_iat_s": None,
            "stdev_iat_s": None,
            "min_iat_s": None,
            "max_iat_s": None,
            "cv": None,
        }

    iats = [
        (sorted_events[i].timestamp - sorted_events[i - 1].timestamp).total_seconds()
        for i in range(1, len(sorted_events))
    ]
    # Exclude spuriously-negative (clock-skew) intervals.
    iats = [v for v in iats if v >= 0]
    if not iats:
        return {
            "event_count": len(sorted_events),
            "duration_s": round(duration_s, 3),
            "mean_iat_s": None,
            "median_iat_s": None,
            "stdev_iat_s": None,
            "min_iat_s": None,
            "max_iat_s": None,
            "cv": None,
        }

    mean = statistics.fmean(iats)
    median = statistics.median(iats)
    stdev = statistics.pstdev(iats) if len(iats) > 1 else 0.0
    cv = (stdev / mean) if mean > 0 else None

    return {
        "event_count": len(sorted_events),
        "duration_s": round(duration_s, 3),
        "mean_iat_s": round(mean, 3),
        "median_iat_s": round(median, 3),
        "stdev_iat_s": round(stdev, 3),
        "min_iat_s": round(min(iats), 3),
        "max_iat_s": round(max(iats), 3),
        "cv": round(cv, 4) if cv is not None else None,
    }
