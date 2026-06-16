# SPDX-License-Identifier: AGPL-3.0-or-later
"""Coverage for :mod:`decnet.realism.diurnal`.

Two functions to exercise:

* :func:`in_work_hours` — straightforward window membership including
  the wrap-around (``22:00-06:00``) case and the fail-open behaviour
  on malformed windows.
* :func:`sample_mtime` — must (a) return a ``datetime`` strictly in
  the past, (b) clip to the configured backdate cap, and (c) snap the
  hour-of-day into the persona's window when the unconstrained
  candidate would land outside.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from decnet.realism.diurnal import in_work_hours, sample_mtime


# Fixed 'now' for reproducible tests — Monday 2026-04-27 14:00 UTC.
_NOW = datetime(2026, 4, 27, 14, 0, tzinfo=timezone.utc)


# ---- in_work_hours -----------------------------------------------------

@pytest.mark.parametrize(
    "now_hour,now_min,window,expected",
    [
        (10, 0, "09:00-18:00", True),
        (8, 59, "09:00-18:00", False),
        (9, 0, "09:00-18:00", True),
        (18, 0, "09:00-18:00", False),       # exclusive end
        (17, 59, "09:00-18:00", True),
        (23, 30, "22:00-06:00", True),       # wrap-around: late
        (3, 0, "22:00-06:00", True),         # wrap-around: early
        (12, 0, "22:00-06:00", False),       # wrap-around: middle of day
    ],
)
def test_in_work_hours_window_membership(
    now_hour: int, now_min: int, window: str, expected: bool,
) -> None:
    now = _NOW.replace(hour=now_hour, minute=now_min)
    assert in_work_hours(window, now) is expected


def test_in_work_hours_equal_start_end_means_always_on() -> None:
    # A persona pegged "00:00-00:00" should never be silenced by the
    # diurnal gate — interpreted as "no schedule".
    assert in_work_hours("00:00-00:00", _NOW) is True


@pytest.mark.parametrize(
    "garbage",
    ["not-a-window", "9-18", "09:00", "25:00-26:00", "09:00-18:99", ""],
)
def test_malformed_window_fails_open(garbage: str) -> None:
    # The fleet must not silence on a typo — same fail-open semantics
    # as decnet.realism.personas.in_active_hours.
    assert in_work_hours(garbage, _NOW) is True


# ---- sample_mtime ------------------------------------------------------

def test_sample_mtime_is_in_the_past() -> None:
    rng = random.Random(0)
    for _ in range(20):
        mt = sample_mtime("09:00-18:00", _NOW, rand=rng)
        assert mt < _NOW, f"sample_mtime returned future: {mt} >= {_NOW}"


def test_sample_mtime_respects_backdate_cap() -> None:
    rng = random.Random(0)
    cap_days = 7.0
    for _ in range(50):
        mt = sample_mtime(
            "09:00-18:00", _NOW, rand=rng,
            backdate_max_days=cap_days, backdate_min_hours=0.5,
        )
        assert _NOW - mt <= timedelta(days=cap_days) + timedelta(hours=1)
        assert _NOW - mt >= timedelta(hours=0.5) - timedelta(seconds=1)


def test_sample_mtime_snaps_hour_into_window() -> None:
    # Force a tight window then assert the hour-of-day is always in it.
    rng = random.Random(42)
    window = "09:00-18:00"
    for _ in range(60):
        mt = sample_mtime(window, _NOW, rand=rng)
        assert 9 <= mt.hour < 18, (
            f"hour {mt.hour} fell outside {window} on {mt.isoformat()}"
        )


def test_sample_mtime_handles_wrap_around_window() -> None:
    rng = random.Random(123)
    for _ in range(40):
        mt = sample_mtime("22:00-06:00", _NOW, rand=rng)
        assert mt.hour >= 22 or mt.hour < 6, (
            f"hour {mt.hour} fell outside wrap window on {mt.isoformat()}"
        )


def test_sample_mtime_malformed_window_does_not_snap() -> None:
    # When the window can't be parsed, just return the unconstrained
    # backdate. Belt-and-braces: shouldn't crash, shouldn't future-stamp.
    rng = random.Random(0)
    mt = sample_mtime("garbage", _NOW, rand=rng)
    assert mt < _NOW


def test_sample_mtime_is_deterministic_per_seed() -> None:
    # The diurnal sampler accepts a Random — pinning the seed must
    # produce stable output, otherwise tests can't assert anything
    # tighter than "returns a datetime in the past."
    a = sample_mtime("09:00-18:00", _NOW, rand=random.Random(7))
    b = sample_mtime("09:00-18:00", _NOW, rand=random.Random(7))
    assert a == b
