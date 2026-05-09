"""Per-(identity, primitive) state-machine — the attribution engine's
core merge logic.

Pure: given a list of BEHAVE observations for one
``(identity_uuid, primitive)`` pair, returns the derived state and
mirror metadata. No DB, no bus, no I/O. The worker
(``decnet.correlation.attribution_worker``) is responsible for loading
the observations and writing the state row.

State vocabulary is frozen at five values (see
``ATTRIBUTION-ENGINE.md``):

* ``unknown``      — < 3 observations (insufficient signal)
* ``stable``       — recent N agree
* ``drifting``     — recent N stable but disagree with older N
* ``conflicted``   — recent N split
* ``multi_actor``  — conflicted + cross-session alternation pattern

Phase 2 ships :func:`_aggregate_categorical`. Phase 3 will add
:func:`_aggregate_numeric` and :func:`_aggregate_hash` and the
ValueKind dispatcher.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Sequence

__all__ = ["AttributionState", "aggregate_observations"]


@dataclass(frozen=True)
class AttributionState:
    """Output of the merger for one ``(identity, primitive)`` pair.

    The fields map 1:1 onto :class:`AttributionStateRow` columns —
    callers compose the final dict for ``upsert_attribution_state``
    by adding ``identity_uuid`` and ``primitive`` (the merger does not
    own the natural key).
    """

    current_value: Any
    state: str
    confidence: float
    observation_count: int
    last_observation_ts: float


def aggregate_observations(
    observations: Sequence[dict[str, Any]],
) -> AttributionState:
    """Run the merger over *observations* and return the derived state.

    *observations* is a list of dicts with at minimum ``value``,
    ``ts``, and ``confidence`` fields (matching the BEHAVE
    ``Observation`` envelope shape that
    ``ObservationRow.observations_time_series`` returns). They MUST
    arrive ordered by ``ts`` ascending; the merger assumes that.

    Phase 2 only supports categorical values. Phase 3 will dispatch
    on the BEHAVE primitive's ``ValueKind`` and pick the right merger.
    """
    if not observations:
        return AttributionState(
            current_value=None,
            state="unknown",
            confidence=0.0,
            observation_count=0,
            last_observation_ts=0.0,
        )
    # Phase 2 stub — categorical only. Phase 3 will inspect
    # ``primitive`` (passed in alongside observations) to pick a
    # merger; for now defer to the categorical implementation
    # (``_aggregate_categorical``) which Phase 2 lands.
    raise NotImplementedError(
        "aggregate_observations is implemented in Phase 2 (categorical) "
        "and Phase 3 (numeric + hash). v0 Phase 1 ships the substrate "
        "only; the worker logs without invoking the merger.",
    )


def _coerce_obs_iter(
    observations: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Defensive: accept any iterable, return a list. Used by the
    worker which pulls observations off the bus + DB into mixed
    iterables."""
    return list(observations)
