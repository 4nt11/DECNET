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
from typing import Any, Sequence

from decnet.correlation.attribution import _thresholds as _T

__all__ = [
    "AttributionState",
    "aggregate_observations",
    "aggregate_categorical",
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
    raise NotImplementedError(
        f"aggregate_observations: value_kind={value_kind!r} lands in Phase 3 "
        "(numeric + hash). v0 Phase 2 only supports categorical.",
    )


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
