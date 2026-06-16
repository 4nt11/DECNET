# SPDX-License-Identifier: AGPL-3.0-or-later
"""Work-hours gating and backdated mtime sampling.

The current orchestrator stamps every planted file at wall-clock-now,
which is one of the realism failures driving this migration: a `cron.log`
that says it was last touched at 03:14:22 UTC on a workstation
attributed to a 9-to-5 admin reads as fake on first glance.

Two helpers:

* :func:`in_work_hours` — gate planner ticks so a persona's files only
  appear inside the persona's ``active_hours`` window.  Wrap-around
  windows (``"22:00-06:00"``) are supported.
* :func:`sample_mtime` — return a backdated datetime whose hour-of-day
  falls inside the persona's window, biased toward "recent but not
  now".  Drivers pass this to ``touch -d``.

Clock and RNG are injectable so tests don't need to ``freeze_time`` or
patch :mod:`secrets`.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Protocol


class _ClockLike(Protocol):
    def __call__(self) -> datetime: ...


class _RandLike(Protocol):
    def random(self) -> float: ...
    def randint(self, a: int, b: int) -> int: ...


def _parse_window(window: str) -> tuple[int, int, int, int] | None:
    """Parse ``"HH:MM-HH:MM"`` into ``(start_h, start_m, end_h, end_m)``.

    Returns ``None`` for malformed input — callers treat that as
    "always-on" so a single config typo never silences the whole fleet
    (:func:`decnet.realism.personas.in_active_hours` delegates here).
    """
    try:
        start_s, end_s = window.split("-")
        start_h, start_m = (int(p) for p in start_s.split(":"))
        end_h, end_m = (int(p) for p in end_s.split(":"))
    except (ValueError, IndexError):
        return None
    if not (0 <= start_h < 24 and 0 <= end_h < 24):
        return None
    if not (0 <= start_m < 60 and 0 <= end_m < 60):
        return None
    return start_h, start_m, end_h, end_m


def in_work_hours(window: str, now: datetime) -> bool:
    """Return ``True`` when *now* falls inside the persona window.

    *window* is ``"HH:MM-HH:MM"``.  Wrap-around (``start > end``) means
    "spans midnight."  Equal ``start`` and ``end`` means always-on.
    Malformed windows return ``True`` — fail-open so a typo doesn't
    silence the fleet.
    """
    parsed = _parse_window(window)
    if parsed is None:
        return True
    start_h, start_m, end_h, end_m = parsed
    if (start_h, start_m) == (end_h, end_m):
        return True
    cur = now.hour * 60 + now.minute
    start = start_h * 60 + start_m
    end = end_h * 60 + end_m
    if start < end:
        return start <= cur < end
    # Wrap-around (e.g. 22:00-06:00).
    return cur >= start or cur < end


def sample_mtime(
    window: str,
    now: datetime,
    *,
    rand: _RandLike | None = None,
    backdate_min_hours: float = 0.5,
    backdate_max_days: float = 14.0,
) -> datetime:
    """Return a backdated ``datetime`` for ``touch -d`` after a write.

    The sampled time is in the past relative to *now*, capped at
    *backdate_max_days* days ago and at least *backdate_min_hours* ago.
    Weighted toward recent — half-life roughly 2 days — so most planted
    files look "edited recently" without all clustering at +30min.

    The hour-of-day of the result is forced into *window* so an
    `admin` persona's `TODO.md` doesn't carry an mtime of 03:14:22.
    Wrap-around windows are honoured.

    Falls back to a uniform 0.5h–14d backdate if *window* is malformed.
    """
    rng = rand or secrets.SystemRandom()
    parsed = _parse_window(window)

    # Exponential-ish backdate via -ln(u): heavier mass near "recent".
    # Cap by clipping; cheap and good enough for realism.
    u = max(rng.random(), 1e-6)  # avoid log(0)
    import math
    span_hours = max(backdate_min_hours, min(backdate_max_days * 24, -math.log(u) * 12.0))
    candidate = now - timedelta(hours=span_hours)

    if parsed is None:
        return candidate

    start_h, start_m, end_h, end_m = parsed
    if (start_h, start_m) == (end_h, end_m):
        return candidate

    # If the candidate's hour-of-day is outside the window, snap it into
    # the window on the same calendar date — preserves the "this many
    # days ago" feel while making the clock-face credible.
    cur = candidate.hour * 60 + candidate.minute
    start = start_h * 60 + start_m
    end = end_h * 60 + end_m
    if start < end:
        in_window = start <= cur < end
        snap_minutes = rng.randint(start, max(start, end - 1))
    else:
        # Wrap-around: in-window if cur is in either segment.
        in_window = cur >= start or cur < end
        # Snap into the larger of the two segments by total length.
        before_midnight = (24 * 60) - start
        after_midnight = end
        if before_midnight >= after_midnight:
            snap_minutes = rng.randint(start, 24 * 60 - 1)
        else:
            snap_minutes = rng.randint(0, max(0, end - 1))

    if in_window:
        return candidate
    snapped = candidate.replace(
        hour=snap_minutes // 60,
        minute=snap_minutes % 60,
        second=rng.randint(0, 59),
        microsecond=0,
    )
    # If the hour-snap pushed us too close to *now* (candidate was
    # earlier today but the random in-window minute landed near or
    # later than the current clock), shift back a full day so the
    # result honours the min-backdate floor.
    floor = now - timedelta(hours=backdate_min_hours)
    while snapped > floor:
        snapped -= timedelta(days=1)
    return snapped
