# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-(identity, primitive) state-machine — the attribution engine's
core merge logic.

Pure: given a list of BEHAVE observations for one
``(identity_uuid, primitive)`` pair (already ordered by ``ts`` ASC),
returns the derived state. No DB, no bus, no I/O. The worker
(``decnet.correlation.attribution_worker``) is responsible for loading
the observations and writing the state row.

State vocabulary is frozen at five values (see
``ATTRIBUTION-ENGINE.md``):

* ``unknown``      — < ``MIN_OBSERVATIONS_FOR_STATE`` observations
* ``stable``       — recent N agree
* ``drifting``     — recent N stable but disagree with older N
* ``conflicted``   — recent N split
* ``multi_actor``  — conflicted + cross-session alternation pattern

Phase 2 ships :func:`_aggregate_categorical` (the dominant ValueKind
for BEHAVE-SHELL primitives). Phase 3 adds numeric + hash mergers and
the ValueKind dispatcher in :func:`aggregate_observations`.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Sequence, cast

from decnet.correlation.attribution import _thresholds as _T

__all__ = [
    "AttributionState",
    "aggregate_observations",
    "aggregate_categorical",
    "aggregate_numeric",
    "aggregate_hash",
]


@dataclass(frozen=True)
class AttributionState:
    """Output of the merger for one ``(identity, primitive)`` pair.

    The fields map onto :class:`AttributionStateRow` columns; the
    worker composes the final dict for ``upsert_attribution_state``
    by adding ``identity_uuid`` + ``primitive`` (the merger does not
    own the natural key) and a ``last_change_ts`` derived from the
    prior row.
    """

    current_value: Any
    state: str
    confidence: float
    observation_count: int
    last_observation_ts: float


def aggregate_observations(
    observations: Sequence[dict[str, Any]],
    *,
    value_kind: str | None = None,
) -> AttributionState:
    """Run the merger over *observations* and return derived state.

    *observations* is a list of dicts with at minimum ``value``,
    ``ts``, ``confidence`` (matching
    ``ObservationRow.observations_time_series`` output). Sessions
    are derived from the ``ts`` axis — the merger does not need a
    separate session id; cross-session alternation is detected by
    the gap distribution. Sessions are NOT collapsed before the
    merger; ``multi_actor`` reasons over the full per-observation
    series.

    *value_kind* is a hint from the BEHAVE primitive registry — Phase
    2 only honours ``"categorical"`` (or ``None``, treated as
    categorical). Phase 3 will dispatch on ``"numeric"`` /
    ``"hash"`` to the matching merger.
    """
    if not observations:
        return _unknown(0.0, count=0)
    if value_kind in (None, "categorical"):
        return aggregate_categorical(observations)
    if value_kind == "numeric":
        return aggregate_numeric(observations)
    if value_kind == "hash":
        return aggregate_hash(observations)
    raise ValueError(
        f"aggregate_observations: unknown value_kind={value_kind!r}; "
        "expected 'categorical' | 'numeric' | 'hash' | None",
    )


def aggregate_numeric(
    observations: Sequence[dict[str, Any]],
) -> AttributionState:
    """Numeric merger — for primitives whose ``value`` is an int /
    float (e.g. ``toolchain.c2.beacon_interval_ms``,
    ``motor.paste_burst_rate``).

    Compares the EWMA of the recent window against the EWMA of the
    older window; reports dispersion as coefficient of variation.

    * < ``MIN_OBSERVATIONS_FOR_STATE`` → ``unknown``
    * recent CV < ``NUMERIC_STABLE_DISPERSION_PCT`` *and* mean shift
      from older window < ``NUMERIC_DRIFT_MEAN_SHIFT_PCT`` → ``stable``
    * mean shifted >= ``NUMERIC_DRIFT_MEAN_SHIFT_PCT`` → ``drifting``
    * recent CV > ``NUMERIC_CONFLICT_DISPERSION_PCT`` → ``conflicted``
    * otherwise → ``stable`` (falling-through case for moderate
      dispersion that hasn't yet become drift)

    Confidence on stable/drifting is ``1 - min(CV, 1.0)`` —
    tighter dispersion = higher confidence. Conflicted is ``0.5``
    by convention; we cannot meaningfully claim certainty in a
    statistic computed over a degenerate sample.

    ``current_value`` is the recent EWMA, not the last raw
    observation: numeric primitives are noisy by nature and
    surfacing the smoothed estimate keeps the dashboard from
    flapping on every tick. ``multi_actor`` is *not* a numeric state
    in v0 — bimodal distributions belong to the categorical
    detector once the primitive's value space is bucketed.
    """
    n = len(observations)
    last_ts = float(observations[-1].get("ts", 0.0)) if observations else 0.0
    if n < _T.MIN_OBSERVATIONS_FOR_STATE:
        return AttributionState(
            current_value=_safe_float(observations[-1].get("value")) if n else None,
            state="unknown",
            confidence=0.0,
            observation_count=n,
            last_observation_ts=last_ts,
        )

    window = _T.CATEGORICAL_WINDOW_N
    recent_vals = [_safe_float(o.get("value")) for o in observations[-window:]]
    older_vals = [
        _safe_float(o.get("value"))
        for o in observations[-2 * window: -window]
    ]
    recent_mean = _ewma(recent_vals, _T.NUMERIC_EWMA_ALPHA)
    recent_cv = _coef_of_variation(recent_vals, recent_mean)

    if recent_cv > _T.NUMERIC_CONFLICT_DISPERSION_PCT:
        return AttributionState(
            current_value=recent_mean,
            state="conflicted",
            confidence=0.5,
            observation_count=n,
            last_observation_ts=last_ts,
        )

    if older_vals:
        older_mean = _ewma(older_vals, _T.NUMERIC_EWMA_ALPHA)
        denom = abs(older_mean) if older_mean != 0 else 1.0
        mean_shift = abs(recent_mean - older_mean) / denom
        if mean_shift >= _T.NUMERIC_DRIFT_MEAN_SHIFT_PCT:
            return AttributionState(
                current_value=recent_mean,
                state="drifting",
                confidence=max(0.0, 1.0 - min(recent_cv, 1.0)),
                observation_count=n,
                last_observation_ts=last_ts,
            )

    return AttributionState(
        current_value=recent_mean,
        state="stable",
        confidence=max(0.0, 1.0 - min(recent_cv, 1.0)),
        observation_count=n,
        last_observation_ts=last_ts,
    )


def aggregate_hash(
    observations: Sequence[dict[str, Any]],
) -> AttributionState:
    """Hash merger — for rotation-resistant fingerprints
    (``toolchain.tls.jarm_server``, ``toolchain.ssh.hassh_client``).

    The merger does NOT recompute hashes; DEBT-032
    (``decnet.correlation.fingerprint_rotation``) already produces
    one observation per rotation event. The state machine counts
    distinct hash values inside ``HASH_DRIFT_WINDOW_SECS`` of the
    most recent observation:

    * 0 rotations (single hash, any count) → ``stable``
    * 1 to ``HASH_DRIFT_MAX`` rotations within window → ``drifting``
    * > ``HASH_DRIFT_MAX`` rotations within window → ``conflicted``

    ``unknown`` fires only on empty input — a single hash with one
    observation is enough signal to say "stable", because hashes
    don't have a noisy baseline the way categorical/numeric
    primitives do.

    ``current_value`` is the most recent hash. Confidence is
    ``1 / (1 + rotations_in_window)`` — one rotation halves
    confidence, two thirds it, etc.
    """
    n = len(observations)
    if n == 0:
        return _unknown(0.0, count=0)
    last_ts = float(observations[-1].get("ts", 0.0))
    last_value = observations[-1].get("value")

    window_start = last_ts - _T.HASH_DRIFT_WINDOW_SECS
    in_window = [
        o for o in observations
        if float(o.get("ts", 0.0)) >= window_start
    ]
    distinct = len({o.get("value") for o in in_window if o.get("value") is not None})
    rotations = max(0, distinct - 1)
    confidence = 1.0 / (1.0 + rotations)

    if rotations == 0:
        state = "stable"
    elif rotations <= _T.HASH_DRIFT_MAX:
        state = "drifting"
    else:
        state = "conflicted"

    return AttributionState(
        current_value=last_value,
        state=state,
        confidence=confidence,
        observation_count=n,
        last_observation_ts=last_ts,
    )


def _ewma(values: Sequence[float], alpha: float) -> float:
    """Single-pass EWMA. Empty input is illegal; callers gate on
    ``MIN_OBSERVATIONS_FOR_STATE`` upstream."""
    it = iter(values)
    smoothed = next(it)
    for v in it:
        smoothed = alpha * v + (1.0 - alpha) * smoothed
    return smoothed


def _coef_of_variation(values: Sequence[float], mean: float) -> float:
    """Population-style CV = stdev / |mean|. Returns 0 on a constant
    signal; returns +inf-equivalent (1e9) when the mean is exactly
    zero and the signal isn't constant — so the conflicted threshold
    fires without us having to special-case it upstream."""
    if not values:
        return 0.0
    diffs_sq = [(v - mean) ** 2 for v in values]
    variance = sum(diffs_sq) / len(values)
    stdev = variance ** 0.5
    if mean == 0:
        return 0.0 if stdev == 0 else 1e9
    return cast(float, stdev / abs(mean))


def _safe_float(value: Any) -> float:
    """Defensive coercion — observations may carry value=None on
    unknown-emitter primitives. Treat None as 0.0; the dispersion
    check will surface the resulting flat baseline as 'stable'
    which is the honest answer for a single-observation primitive
    that hasn't fired yet."""
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    return float(value)


def aggregate_categorical(
    observations: Sequence[dict[str, Any]],
) -> AttributionState:
    """Categorical merger — the dominant case for BEHAVE-SHELL.

    Compares the recent N-window against the older N-window. With
    ``CATEGORICAL_WINDOW_N = 5`` and ``CATEGORICAL_MAJORITY_THRESHOLD
    = 4``:

    * fewer than ``MIN_OBSERVATIONS_FOR_STATE`` → ``unknown``
    * recent window has a clear majority + matches older window → ``stable``
    * recent window has a clear majority + differs from older window → ``drifting``
    * recent window split + alternation pattern across observations → ``multi_actor``
    * recent window split + no alternation → ``conflicted``

    Confidence is the recent-window agreement ratio; ``multi_actor``
    is capped at ``MULTI_ACTOR_MAX_CONFIDENCE``. The merger returns
    the most-recent observation's value as ``current_value``
    regardless of state — the dashboard wants a value to render
    even on ``conflicted`` rows.
    """
    n = len(observations)
    last_ts = float(observations[-1].get("ts", 0.0))
    last_value = observations[-1].get("value")
    if n < _T.MIN_OBSERVATIONS_FOR_STATE:
        return AttributionState(
            current_value=last_value,
            state="unknown",
            confidence=0.0,
            observation_count=n,
            last_observation_ts=last_ts,
        )

    window = _T.CATEGORICAL_WINDOW_N
    recent = observations[-window:]
    recent_values = [o.get("value") for o in recent]
    recent_count = Counter(recent_values)
    top_value, top_count = recent_count.most_common(1)[0]
    recent_size = len(recent)
    confidence = top_count / recent_size

    is_recent_clear = top_count >= min(
        _T.CATEGORICAL_MAJORITY_THRESHOLD, recent_size,
    )

    if not is_recent_clear:
        # Split recent window. Distinguish multi_actor (alternation)
        # from random conflict.
        if _is_alternation(observations):
            return AttributionState(
                current_value=last_value,
                state="multi_actor",
                confidence=min(confidence, _T.MULTI_ACTOR_MAX_CONFIDENCE),
                observation_count=n,
                last_observation_ts=last_ts,
            )
        return AttributionState(
            current_value=last_value,
            state="conflicted",
            confidence=confidence,
            observation_count=n,
            last_observation_ts=last_ts,
        )

    # Recent window has a clear majority. Compare to the prior
    # window to decide stable vs drifting.
    older = observations[-2 * window: -window]
    if not older:
        # Only one window's worth of data — call it stable. The
        # dashboard already gates "unknown" on
        # MIN_OBSERVATIONS_FOR_STATE so this branch is reachable
        # only when the operator has produced enough observations
        # for one full window but not two.
        return AttributionState(
            current_value=top_value,
            state="stable",
            confidence=confidence,
            observation_count=n,
            last_observation_ts=last_ts,
        )

    older_values = [o.get("value") for o in older]
    older_count = Counter(older_values)
    older_top_value, older_top_count = older_count.most_common(1)[0]
    older_size = len(older)
    older_clear = older_top_count >= min(
        _T.CATEGORICAL_MAJORITY_THRESHOLD, older_size,
    )

    if not older_clear:
        # Older window was itself conflicted; we just stabilised.
        # That's drift in the colloquial sense — the attacker
        # converged onto a single behaviour.
        return AttributionState(
            current_value=top_value,
            state="drifting",
            confidence=confidence,
            observation_count=n,
            last_observation_ts=last_ts,
        )

    if older_top_value != top_value:
        return AttributionState(
            current_value=top_value,
            state="drifting",
            confidence=confidence,
            observation_count=n,
            last_observation_ts=last_ts,
        )
    return AttributionState(
        current_value=top_value,
        state="stable",
        confidence=confidence,
        observation_count=n,
        last_observation_ts=last_ts,
    )


def _is_alternation(observations: Sequence[dict[str, Any]]) -> bool:
    """Heuristic: do recent observations alternate between two values
    (operator A → B → A → B), as opposed to random thrashing?

    Conservative: requires at least 4 observations in the window,
    exactly 2 distinct values, and that flips outnumber repeats by
    at least 2:1. ATTRIBUTION-ENGINE.md §"Open question 1" warns
    that flapping primitives on flaky networks look like two
    operators; this guard is what keeps the false-positive rate down.
    """
    window = _T.CATEGORICAL_WINDOW_N
    recent = observations[-window:]
    if len(recent) < 4:
        return False
    values = [o.get("value") for o in recent]
    distinct = set(values)
    if len(distinct) != 2:
        return False
    flips = sum(
        1 for i in range(1, len(values)) if values[i] != values[i - 1]
    )
    repeats = (len(values) - 1) - flips
    return flips >= 2 * max(repeats, 1)


def _unknown(last_ts: float, *, count: int) -> AttributionState:
    return AttributionState(
        current_value=None,
        state="unknown",
        confidence=0.0,
        observation_count=count,
        last_observation_ts=last_ts,
    )
