"""Phase 3 — numeric + hash merger tests + dispatcher coverage.

Pure-function tests; no DB, no bus. Synthetic input lists drive each
state transition the engine claims to detect.
"""
from __future__ import annotations

from typing import Any

import pytest

from decnet.correlation.attribution import _thresholds as _T
from decnet.correlation.attribution.aggregate import (
    aggregate_hash,
    aggregate_numeric,
    aggregate_observations,
)


def _obs(value: Any, ts: float, confidence: float = 0.9) -> dict[str, Any]:
    return {"value": value, "ts": ts, "confidence": confidence}


# ── numeric merger ────────────────────────────────────────────────────


def test_numeric_empty_is_unknown() -> None:
    out = aggregate_numeric([])
    assert out.state == "unknown"
    assert out.observation_count == 0


def test_numeric_below_min_is_unknown() -> None:
    obs = [_obs(5000.0, 1714000000.0 + i * 60) for i in range(_T.MIN_OBSERVATIONS_FOR_STATE - 1)]
    out = aggregate_numeric(obs)
    assert out.state == "unknown"


def test_numeric_tight_dispersion_is_stable() -> None:
    """Steady beacon ~5000ms with <20% jitter → stable."""
    base = 5000.0
    obs = [
        _obs(base + delta, 1714000000.0 + i * 60)
        for i, delta in enumerate([0.0, 50.0, -30.0, 20.0, 10.0])
    ]
    out = aggregate_numeric(obs)
    assert out.state == "stable"
    assert out.confidence > 0.9
    # current_value is the smoothed estimate, close to baseline.
    assert abs(out.current_value - base) < 100.0


def test_numeric_mean_shift_is_drifting() -> None:
    """Older window centred on 5000ms, recent window on 8000ms — that's
    a 60% mean shift, well above NUMERIC_DRIFT_MEAN_SHIFT_PCT."""
    older = [_obs(5000.0, 1714000000.0 + i * 60) for i in range(5)]
    newer = [_obs(8000.0, 1714001000.0 + i * 60) for i in range(5)]
    out = aggregate_numeric(older + newer)
    assert out.state == "drifting"
    assert out.current_value > 7000.0


def test_numeric_high_dispersion_is_conflicted() -> None:
    """Recent window with CV > 100% (wildly mixed values)."""
    obs = [
        _obs(100.0, 1714000000.0),
        _obs(20000.0, 1714000060.0),
        _obs(50.0, 1714000120.0),
        _obs(15000.0, 1714000180.0),
        _obs(200.0, 1714000240.0),
    ]
    out = aggregate_numeric(obs)
    assert out.state == "conflicted"
    assert out.confidence == 0.5


def test_numeric_zero_mean_constant_is_stable() -> None:
    """All-zero signal: CV is 0/0 by definition; helper returns 0 so
    the state machine claims 'stable' (the honest answer)."""
    obs = [_obs(0.0, 1714000000.0 + i * 60) for i in range(5)]
    out = aggregate_numeric(obs)
    assert out.state == "stable"


def test_numeric_handles_bool_values() -> None:
    """Some primitives use bools as numeric flags. The merger must
    coerce True/False to 1.0/0.0 without crashing the float math."""
    obs = [_obs(True, 1714000000.0 + i * 60) for i in range(5)]
    out = aggregate_numeric(obs)
    assert out.state == "stable"
    assert out.current_value == pytest.approx(1.0)


# ── hash merger ───────────────────────────────────────────────────────


def test_hash_empty_is_unknown() -> None:
    out = aggregate_hash([])
    assert out.state == "unknown"
    assert out.observation_count == 0


def test_hash_single_observation_is_stable() -> None:
    """Hashes don't have a noisy baseline — one observation of one
    hash is enough signal to say 'stable'. Distinct from
    categorical/numeric where MIN_OBSERVATIONS gates the assertion."""
    obs = [_obs("deadbeef" * 8, 1714000000.0)]
    out = aggregate_hash(obs)
    assert out.state == "stable"
    assert out.current_value == "deadbeef" * 8


def test_hash_repeated_same_value_is_stable() -> None:
    """No rotations within window → stable, regardless of count."""
    same = "cafefade" * 8
    obs = [_obs(same, 1714000000.0 + i * 60) for i in range(10)]
    out = aggregate_hash(obs)
    assert out.state == "stable"
    assert out.confidence == 1.0


def test_hash_one_rotation_in_window_is_drifting() -> None:
    """Two distinct hashes within HASH_DRIFT_WINDOW → 1 rotation,
    below HASH_DRIFT_MAX → drifting."""
    obs = [
        _obs("a" * 64, 1714000000.0),
        _obs("a" * 64, 1714000060.0),
        _obs("b" * 64, 1714000120.0),
    ]
    out = aggregate_hash(obs)
    assert out.state == "drifting"
    assert out.current_value == "b" * 64
    assert out.confidence == pytest.approx(0.5)


def test_hash_two_rotations_still_drifting() -> None:
    """Three distinct hashes within window → 2 rotations,
    HASH_DRIFT_MAX exactly → still drifting (boundary)."""
    obs = [
        _obs("a" * 64, 1714000000.0),
        _obs("b" * 64, 1714000060.0),
        _obs("c" * 64, 1714000120.0),
    ]
    out = aggregate_hash(obs)
    assert out.state == "drifting"


def test_hash_many_rotations_is_conflicted() -> None:
    """More than HASH_DRIFT_MAX rotations within window → conflicted."""
    obs = [
        _obs(f"hash-{i}", 1714000000.0 + i * 60)
        for i in range(_T.HASH_DRIFT_MAX + 3)
    ]
    out = aggregate_hash(obs)
    assert out.state == "conflicted"


def test_hash_old_rotations_drop_out_of_window() -> None:
    """Old hash observations outside HASH_DRIFT_WINDOW_SECS don't count
    against the rotation tally — operator stabilised after past churn."""
    cutoff = 1714000000.0
    obs = [
        # 10 days old — outside the 24h window.
        _obs("oldhash", cutoff - 10 * 86400),
        _obs("anotheroldhash", cutoff - 9 * 86400),
        # Recent: single hash.
        _obs("currenthash", cutoff),
    ]
    out = aggregate_hash(obs)
    assert out.state == "stable"
    assert out.current_value == "currenthash"


# ── dispatcher ────────────────────────────────────────────────────────


def test_dispatcher_routes_numeric() -> None:
    obs = [_obs(5000.0, 1714000000.0 + i * 60) for i in range(5)]
    a = aggregate_observations(obs, value_kind="numeric")
    b = aggregate_numeric(obs)
    assert a == b


def test_dispatcher_routes_hash() -> None:
    obs = [_obs("a" * 64, 1714000000.0 + i * 60) for i in range(3)]
    a = aggregate_observations(obs, value_kind="hash")
    b = aggregate_hash(obs)
    assert a == b


def test_dispatcher_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError):
        aggregate_observations([_obs(1, 1714000000.0)], value_kind="bogus")
