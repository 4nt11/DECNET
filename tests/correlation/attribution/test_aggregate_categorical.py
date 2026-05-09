"""Pure-function tests for the categorical merger — every state
transition the engine claims to detect, exercised by synthetic
observation lists. No DB, no bus.

State vocabulary: unknown / stable / drifting / conflicted /
multi_actor. Coverage drives one test per state plus the boundary
cases that distinguish them.
"""
from __future__ import annotations

from typing import Any, Sequence

from decnet.correlation.attribution import _thresholds as _T
from decnet.correlation.attribution.aggregate import (
    aggregate_categorical,
    aggregate_observations,
)


def _obs(value: Any, ts: float, confidence: float = 0.9) -> dict[str, Any]:
    return {"value": value, "ts": ts, "confidence": confidence}


def _pad(
    *, value: Any, count: int, start_ts: float = 1714000000.0,
) -> list[dict[str, Any]]:
    return [_obs(value, start_ts + i * 60.0) for i in range(count)]


def test_empty_returns_unknown_zero_count() -> None:
    out = aggregate_observations([])
    assert out.state == "unknown"
    assert out.observation_count == 0
    assert out.current_value is None


def test_below_min_threshold_is_unknown() -> None:
    obs = _pad(value="typed", count=_T.MIN_OBSERVATIONS_FOR_STATE - 1)
    out = aggregate_categorical(obs)
    assert out.state == "unknown"
    assert out.observation_count == len(obs)
    # Last value is surfaced even on unknown so the UI has something
    # to render.
    assert out.current_value == "typed"


def test_stable_when_recent_window_agrees() -> None:
    # 5 identical observations — window is full of one value.
    obs = _pad(value="typed", count=_T.CATEGORICAL_WINDOW_N)
    out = aggregate_categorical(obs)
    assert out.state == "stable"
    assert out.current_value == "typed"
    assert out.confidence == 1.0


def test_stable_tolerates_one_outlier_in_five() -> None:
    """Majority threshold is 4 of 5 — one stray paste in a typed
    window must not flip the state to conflicted."""
    obs = _pad(value="typed", count=4) + [_obs("pasted", 1714000400.0)]
    out = aggregate_categorical(obs)
    assert out.state == "stable"
    assert out.current_value == "typed"  # majority value, not last


def test_drifting_when_recent_disagrees_with_older() -> None:
    """Older window stable on A, recent window stable on B → drifting
    (the attacker switched behaviour)."""
    older = _pad(value="typed", count=_T.CATEGORICAL_WINDOW_N)
    newer = _pad(
        value="pasted",
        count=_T.CATEGORICAL_WINDOW_N,
        start_ts=1714001000.0,
    )
    out = aggregate_categorical(older + newer)
    assert out.state == "drifting"
    assert out.current_value == "pasted"


def test_drifting_when_older_was_conflicted_and_recent_stable() -> None:
    """Operator stabilised after an earlier mixed period."""
    older = [
        _obs("typed", 1714000000.0),
        _obs("pasted", 1714000060.0),
        _obs("typed", 1714000120.0),
        _obs("pasted", 1714000180.0),
        _obs("mixed", 1714000240.0),
    ]
    newer = _pad(
        value="pasted",
        count=_T.CATEGORICAL_WINDOW_N,
        start_ts=1714001000.0,
    )
    out = aggregate_categorical(older + newer)
    assert out.state == "drifting"
    assert out.current_value == "pasted"


def test_conflicted_on_random_split_no_alternation() -> None:
    """Recent window split across 3+ values, no two-value alternation
    → conflicted (random thrash, not multi_actor)."""
    obs = [
        _obs("typed", 1714000000.0),
        _obs("pasted", 1714000060.0),
        _obs("mixed", 1714000120.0),
        _obs("typed", 1714000180.0),
        _obs("pasted", 1714000240.0),
    ]
    out = aggregate_categorical(obs)
    # Three distinct values rules out 2-way alternation.
    assert out.state == "conflicted"


def test_multi_actor_on_clean_alternation() -> None:
    """Recent window alternates between exactly two values, flips
    >= 2× repeats — operator A↔B handoff signal."""
    # 5 obs: A B A B A — 4 flips, 0 repeats.
    obs = [
        _obs("typed", 1714000000.0),
        _obs("pasted", 1714000060.0),
        _obs("typed", 1714000120.0),
        _obs("pasted", 1714000180.0),
        _obs("typed", 1714000240.0),
    ]
    out = aggregate_categorical(obs)
    assert out.state == "multi_actor"
    assert out.confidence <= _T.MULTI_ACTOR_MAX_CONFIDENCE


def test_alternation_requires_two_distinct_values() -> None:
    """A single value flapping with itself is not multi_actor — it's
    just a flapping primitive on a flaky network."""
    obs = _pad(value="typed", count=_T.CATEGORICAL_WINDOW_N)
    out = aggregate_categorical(obs)
    assert out.state == "stable"


def test_short_run_after_threshold_is_stable_not_drifting() -> None:
    """Just past MIN_OBSERVATIONS_FOR_STATE but no older window —
    stable, not drifting (drifting requires comparison to a prior
    window that materially differs)."""
    obs = _pad(value="typed", count=_T.MIN_OBSERVATIONS_FOR_STATE)
    out = aggregate_categorical(obs)
    assert out.state == "stable"


def test_observation_count_reports_total_not_window_size() -> None:
    obs = _pad(value="typed", count=12)
    out = aggregate_categorical(obs)
    assert out.observation_count == 12


def test_last_observation_ts_is_most_recent() -> None:
    obs = _pad(value="typed", count=5)
    out = aggregate_categorical(obs)
    assert out.last_observation_ts == obs[-1]["ts"]


def test_dispatcher_routes_categorical() -> None:
    """aggregate_observations(value_kind=None|"categorical") delegates
    to the categorical merger; both produce the same output."""
    obs = _pad(value="typed", count=_T.CATEGORICAL_WINDOW_N)
    a = aggregate_observations(obs)
    b = aggregate_observations(obs, value_kind="categorical")
    c = aggregate_categorical(obs)
    assert a == b == c


def test_dispatcher_rejects_unknown_value_kind() -> None:
    """Unknown ValueKind tags surface as ValueError so misuse doesn't
    silently fall through to categorical. Phase 3 wired numeric +
    hash; the rejection is for typos and v1 kinds that haven't
    landed yet."""
    import pytest
    obs = _pad(value="typed", count=5)
    with pytest.raises(ValueError):
        aggregate_observations(obs, value_kind="bogus_kind")
