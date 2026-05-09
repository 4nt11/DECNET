"""Phase 7 — calibration lockdown.

Four synthetic operator-behaviour scenarios that exercise the full
attribution merge contract end-to-end at the library level
(``aggregate_observations``). These are the v0 ship gate per
``ATTRIBUTION-ENGINE.md`` §"Phase 7": if a future change to the
merger / thresholds breaks any of them silently, this file is the
one that catches it.

Each scenario is shaped like a per-(identity, primitive) observation
series the worker would assemble from
``observations_for_identity_primitive``; the merger output is asserted
against the expected state vocabulary.

These tests are **load-bearing on the threshold defaults in
``_thresholds.py``** — when calibration shifts, both files change
together.
"""
from __future__ import annotations

from typing import Any

from decnet.correlation.attribution import _thresholds as _T
from decnet.correlation.attribution.aggregate import aggregate_observations


def _categorical(value: str, ts: float, conf: float = 0.9) -> dict[str, Any]:
    return {"value": value, "ts": ts, "confidence": conf}


def _numeric(value: float, ts: float, conf: float = 0.9) -> dict[str, Any]:
    return {"value": value, "ts": ts, "confidence": conf}


# ── Scenario 1: stable HUMAN over 7 sessions ──────────────────────────


def test_stable_human_seven_sessions_all_primitives_stable() -> None:
    """A consistent operator: same input modality, same feedback loop
    pattern, same beacon cadence. Every primitive should land
    ``stable`` after seven sessions."""
    # 7 sessions, one observation per session, all agreeing.
    sessions = [_categorical("typed", 1714000000.0 + i * 86400) for i in range(7)]
    out = aggregate_observations(sessions, value_kind="categorical")
    assert out.state == "stable"
    assert out.current_value == "typed"
    assert out.confidence == 1.0

    feedback = [_categorical("closed_loop", 1714000000.0 + i * 86400) for i in range(7)]
    out_fb = aggregate_observations(feedback, value_kind="categorical")
    assert out_fb.state == "stable"

    beacon = [_numeric(5000.0 + (i * 20), 1714000000.0 + i * 86400) for i in range(7)]
    out_num = aggregate_observations(beacon, value_kind="numeric")
    assert out_num.state == "stable"


# ── Scenario 2: HUMAN switches to LLM mid-week ────────────────────────


def test_human_to_llm_drift_flips_stable_to_drifting() -> None:
    """Operator behaviour shifts mid-week: typed-by-hand becomes
    paste-from-LLM. The merger should flag ``drifting`` once the
    recent window stabilises on the new value but disagrees with
    the older window."""
    typed = [_categorical("typed", 1714000000.0 + i * 86400) for i in range(5)]
    pasted = [_categorical("pasted", 1714600000.0 + i * 86400) for i in range(5)]
    out = aggregate_observations(typed + pasted, value_kind="categorical")
    assert out.state == "drifting"
    assert out.current_value == "pasted"

    # Numeric drift: beacon interval shifts from 5000ms to 12000ms.
    older_beacon = [_numeric(5000.0 + i * 30, 1714000000.0 + i * 60) for i in range(5)]
    newer_beacon = [_numeric(12000.0 + i * 50, 1714600000.0 + i * 60) for i in range(5)]
    out_num = aggregate_observations(
        older_beacon + newer_beacon, value_kind="numeric",
    )
    assert out_num.state == "drifting"


# ── Scenario 3: two operators alternating on shared creds ─────────────


def test_two_operators_alternating_flags_multi_actor() -> None:
    """Two operators take turns on the same credentials: A → B → A
    → B → A. The categorical merger should flag ``multi_actor``
    (alternation pattern, exactly two distinct values, flips
    >> repeats). Confidence is capped at 0.6."""
    # 5 alternating observations across 5 sessions.
    series = [
        _categorical("typed",  1714000000.0),
        _categorical("pasted", 1714086400.0),
        _categorical("typed",  1714172800.0),
        _categorical("pasted", 1714259200.0),
        _categorical("typed",  1714345600.0),
    ]
    out = aggregate_observations(series, value_kind="categorical")
    assert out.state == "multi_actor"
    assert out.confidence <= _T.MULTI_ACTOR_MAX_CONFIDENCE

    # A second primitive also flagging multi_actor — this is what
    # Phase 5's cross-primitive correlator escalates to
    # multi_actor_suspected. Both primitives independently must land
    # multi_actor for the escalation; the per-primitive merger is
    # what we lock down here.
    series_b = [
        _categorical("closed_loop", 1714000000.0),
        _categorical("open_loop",   1714086400.0),
        _categorical("closed_loop", 1714172800.0),
        _categorical("open_loop",   1714259200.0),
        _categorical("closed_loop", 1714345600.0),
    ]
    out_b = aggregate_observations(series_b, value_kind="categorical")
    assert out_b.state == "multi_actor"


# ── Scenario 4: single short session ──────────────────────────────────


def test_single_short_session_yields_unknown() -> None:
    """One short session emits at most a couple of observations per
    primitive; below ``MIN_OBSERVATIONS_FOR_STATE`` the merger MUST
    return ``unknown`` rather than confabulate a stable signal from
    a sample of two."""
    short = [
        _categorical("typed", 1714000000.0),
        _categorical("typed", 1714000060.0),
    ]
    assert len(short) < _T.MIN_OBSERVATIONS_FOR_STATE
    out = aggregate_observations(short, value_kind="categorical")
    assert out.state == "unknown"
    assert out.confidence == 0.0
    assert out.observation_count == len(short)

    # Numeric series under the same threshold.
    short_num = [_numeric(5000.0, 1714000000.0), _numeric(5050.0, 1714000060.0)]
    out_num = aggregate_observations(short_num, value_kind="numeric")
    assert out_num.state == "unknown"

    # Even a single hash observation, despite the hash merger's
    # one-obs-is-enough rule, is not "unknown" — but the empty case
    # is. Surface that contract too.
    out_empty = aggregate_observations([], value_kind="hash")
    assert out_empty.state == "unknown"
    assert out_empty.observation_count == 0


# ── Threshold lockdown ────────────────────────────────────────────────


def test_threshold_constants_are_load_bearing() -> None:
    """If anyone changes a threshold, this test forces them to look at
    the calibration scenarios and decide whether to update them. v0
    ship values:"""
    assert _T.CATEGORICAL_WINDOW_N == 5
    assert _T.MIN_OBSERVATIONS_FOR_STATE == 3
    assert _T.CATEGORICAL_MAJORITY_THRESHOLD == 4
    assert _T.MULTI_ACTOR_MAX_CONFIDENCE == 0.6
    assert _T.MULTI_ACTOR_MIN_PRIMITIVES == 2
    assert _T.NUMERIC_STABLE_DISPERSION_PCT == 0.20
    assert _T.NUMERIC_DRIFT_MEAN_SHIFT_PCT == 0.30
    assert _T.NUMERIC_CONFLICT_DISPERSION_PCT == 1.0
    assert _T.HASH_DRIFT_MAX == 2
