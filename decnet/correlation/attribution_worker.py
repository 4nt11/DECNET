"""Attribution-engine bus subscriber — v0 Phase 1 skeleton.

Subscribes to ``attacker.observation.>`` and, for each event, ensures
the source attacker has a stub identity in ``attacker_identities``.
Phase 1 does **not** invoke the merger or write
``attribution_state`` rows; that wiring lands in Phase 4 once the
Phase 2/3 mergers are in.

Pattern mirrors :mod:`decnet.correlation.reuse_worker`: bus-subscribe
with a wake event, fall back to poll-only if the bus is unavailable,
publish derived events with :func:`publish_safely`, log per-handler
exceptions and continue.

Trigger isolation: the per-event handler is wrapped in a single
try/except. Any exception is logged and the loop continues with the
next event. This is the same posture BEHAVE-SHELL's
``_handler.handle_session_ended`` adopts.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    publish_safely,
    run_control_listener_signal as _run_control_listener_signal,
    run_health_heartbeat as _run_health_heartbeat,
)
from decnet.correlation.attribution.aggregate import aggregate_observations
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository

try:
    from decnet_behave_shell.spec import (
        PRIMITIVE_REGISTRY,
        ValueKind,
    )
    _BEHAVE_REGISTRY_AVAILABLE = True
except ImportError:  # pragma: no cover
    PRIMITIVE_REGISTRY = {}
    ValueKind = None
    _BEHAVE_REGISTRY_AVAILABLE = False

log = get_logger("correlation.attribution_worker")

_WORKER_NAME = "attribution"
_OBSERVATION_PATTERN = f"{_topics.ATTACKER}.{_topics.ATTACKER_OBSERVATION_PREFIX}.>"


async def run_attribution_loop(
    repo: BaseRepository,
    *,
    shutdown: asyncio.Event | None = None,
) -> None:
    """Run the attribution worker until cancelled.

    *shutdown* is an optional external stop signal; the loop also
    exits cleanly on ``CancelledError`` and ``KeyboardInterrupt``.
    """
    log.info("attribution worker started pattern=%s", _OBSERVATION_PATTERN)

    bus: BaseBus | None = None
    sub_task: asyncio.Task | None = None
    heartbeat_task: asyncio.Task | None = None
    control_task: asyncio.Task | None = None
    try:
        candidate = get_bus(client_name=f"{_WORKER_NAME}-correlator")
        await candidate.connect()
        bus = candidate
        sub_task = asyncio.create_task(
            _consume_observations(bus, repo),
        )
        heartbeat_task = asyncio.create_task(
            _run_health_heartbeat(bus, _WORKER_NAME),
        )
        control_task = asyncio.create_task(
            _run_control_listener_signal(bus, _WORKER_NAME),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "attribution worker: bus unavailable, idle until bus returns: %s",
            exc,
        )

    if shutdown is None:
        shutdown = asyncio.Event()

    try:
        await shutdown.wait()
    except (asyncio.CancelledError, KeyboardInterrupt):
        log.info("attribution worker stopped")
    finally:
        for task in (sub_task, heartbeat_task, control_task):
            if task is None:
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()


async def _consume_observations(
    bus: BaseBus, repo: BaseRepository,
) -> None:
    """Pull events off ``attacker.observation.>`` and dispatch each
    to :func:`handle_observation_event`.

    Per-event exceptions are caught and logged; the subscription
    survives bad payloads. If the subscription itself dies (bus
    disconnect), the worker idles — the supervisor systemd unit
    will restart on a clean exit.
    """
    try:
        sub = bus.subscribe(_OBSERVATION_PATTERN)
        async with sub:
            async for event in sub:
                try:
                    await handle_observation_event(bus, repo, event)
                except Exception:  # noqa: BLE001
                    log.exception("attribution worker: handler failed")
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "attribution worker: subscriber for %s died (%s)",
            _OBSERVATION_PATTERN, exc,
        )


async def handle_observation_event(
    bus: BaseBus | None,
    repo: BaseRepository,
    event: Any,
) -> None:
    """Handle one ``attacker.observation.<primitive>`` event.

    Phase 1: ensure the source attacker has a stub identity, then log
    and return. Phase 4 will: load prior state, run merger, upsert
    new state, emit ``attribution.profile.state_changed`` on
    transition.

    *event* is whatever shape :class:`BaseBus`'s subscription yields —
    a ``BusEvent`` with ``payload`` (dict) and ``event_type`` (str)
    fields. The payload carries the BEHAVE envelope plus DECNET-side
    ``attacker_uuid`` denorm (see
    ``decnet.profiler.behave_shell._handler._publish_observation``).
    """
    payload = _payload_of(event)
    attacker_uuid = payload.get("attacker_uuid")
    primitive = payload.get("primitive")
    if not attacker_uuid or not primitive:
        log.debug(
            "attribution worker: skipping malformed event (uuid=%r primitive=%r)",
            attacker_uuid, primitive,
        )
        return
    identity_uuid = await repo.ensure_stub_identity_for_attacker(
        str(attacker_uuid),
    )
    if identity_uuid is None:
        log.info(
            "attribution worker: no Attacker row for uuid=%s yet; deferring",
            attacker_uuid,
        )
        return
    primitive_str = str(primitive)

    # Load the full per-(identity, primitive) observation series.
    # v0 with 1:1 stub identities, this is the single attacker's
    # series; v1's clusterer makes it a cross-attacker union.
    observations = await repo.observations_for_identity_primitive(
        identity_uuid, primitive_str,
    )
    if not observations:
        log.debug(
            "attribution worker: no observations yet for identity=%s "
            "primitive=%s (race with upsert)",
            identity_uuid, primitive_str,
        )
        return

    # Run merger.
    value_kind = _value_kind_for(primitive_str)
    new_state = aggregate_observations(observations, value_kind=value_kind)

    # Load prior state to detect transitions.
    prior = await repo.get_attribution_state(identity_uuid, primitive_str)
    state_changed = prior is None or prior.get("state") != new_state.state

    # Persist. last_change_ts is locked to the prior row when state is
    # unchanged so the dashboard's "stable since" timestamp doesn't
    # reset on every observation.
    if prior is not None and not state_changed:
        last_change_ts = float(prior.get("last_change_ts", new_state.last_observation_ts))
    else:
        last_change_ts = new_state.last_observation_ts
    await repo.upsert_attribution_state({
        "identity_uuid": identity_uuid,
        "primitive": primitive_str,
        "current_value": new_state.current_value,
        "state": new_state.state,
        "confidence": new_state.confidence,
        "observation_count": new_state.observation_count,
        "last_change_ts": last_change_ts,
        "last_observation_ts": new_state.last_observation_ts,
    })

    # Emit state_changed only on transition. Idempotent re-runs (same
    # observations, same merger output) produce no event — matches
    # the loop-prevention invariant that ttp.tagged uses.
    if state_changed and bus is not None:
        await publish_safely(
            bus,
            _topics.attribution(_topics.ATTRIBUTION_PROFILE_STATE_CHANGED),
            {
                "identity_uuid": identity_uuid,
                "primitive": primitive_str,
                "old_state": prior.get("state") if prior else None,
                "new_state": new_state.state,
                "current_value": new_state.current_value,
                "confidence": new_state.confidence,
                "observation_count": new_state.observation_count,
                "ts": new_state.last_observation_ts,
            },
            event_type=_topics.ATTRIBUTION_PROFILE_STATE_CHANGED,
        )
        log.info(
            "attribution worker: identity=%s primitive=%s %s -> %s confidence=%.2f",
            identity_uuid, primitive_str,
            (prior or {}).get("state") or "<new>", new_state.state,
            new_state.confidence,
        )


def _value_kind_for(primitive: str) -> str:
    """Resolve a BEHAVE primitive name to the merger's ValueKind tag.

    Maps the BEHAVE registry's ``ValueKind`` enum onto the three
    mergers the engine ships:

    * ``CATEGORICAL`` / ``BOOL`` / ``FREE_STRING`` / ``ARRAY`` →
      ``"categorical"`` (BOOL is a 2-cardinality categorical;
      FREE_STRING and ARRAY collapse to opaque-token categorical
      until a v1 specialised merger lands)
    * ``NUMERIC`` → ``"numeric"``
    * ``HASH``    → ``"hash"``

    Unknown primitives (registry miss) default to categorical — the
    safest fallback because the categorical merger is one-outlier-
    tolerant and won't lie about confidence on noisy categorical
    data the way a numeric merger would on non-numeric values.
    """
    if not _BEHAVE_REGISTRY_AVAILABLE:
        return "categorical"
    spec = PRIMITIVE_REGISTRY.get(primitive)
    if spec is None or ValueKind is None:
        return "categorical"
    if spec.kind is ValueKind.NUMERIC:
        return "numeric"
    if spec.kind is ValueKind.HASH:
        return "hash"
    return "categorical"


def _payload_of(event: Any) -> dict[str, Any]:
    """Extract the dict payload from a BusEvent or fall through if
    *event* is already a dict (test fixtures may pass either)."""
    payload = getattr(event, "payload", event)
    return payload if isinstance(payload, dict) else {}


__all__ = [
    "run_attribution_loop",
    "handle_observation_event",
]
