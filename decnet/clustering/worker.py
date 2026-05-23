# SPDX-License-Identifier: AGPL-3.0-or-later
"""Long-running identity-resolution clusterer worker.

Runs :meth:`Clusterer.tick` on bus-wake or slow-tick fallback. Mirrors
:mod:`decnet.intel.worker` and :mod:`decnet.correlation.reuse_worker`:
woken on ``attacker.observed`` and ``attacker.scored`` for sub-second
latency, falls back to a 60s poll when the bus is unavailable.

The clusterer itself owns its DB writes (``attacker_identities`` +
``attackers.identity_id`` updates). The worker shell is responsible only
for:

* lifecycle (bus connect, heartbeat, control listener, clean shutdown),
* publishing ``identity.formed`` / ``identity.observation.linked`` /
  ``identity.merged`` / ``identity.unmerged`` from the
  :class:`ClusterResult` returned by ``tick``.

The skeleton ``ConnectedComponentsClusterer.tick`` returns an empty
result, so this worker runs but emits no identity events until edges
are wired in.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Optional

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    publish_safely,
    run_control_listener_signal as _run_control_listener_signal,
    run_health_heartbeat as _run_health_heartbeat,
)
from decnet.clustering.base import Clusterer, ClusterResult
from decnet.clustering.factory import get_clusterer
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository

log = get_logger("clustering.worker")

_DEFAULT_POLL_SECS = 60.0


async def run_clusterer_loop(
    repo: BaseRepository,
    *,
    poll_interval_secs: float = _DEFAULT_POLL_SECS,
    clusterer: Optional[Clusterer] = None,
    shutdown: Optional[asyncio.Event] = None,
) -> None:
    """Run the identity clusterer until cancelled.

    *clusterer* defaults to :func:`get_clusterer` — tests pass a fake.
    *shutdown* is an optional external stop signal; the loop also exits
    cleanly on :class:`asyncio.CancelledError` and
    :class:`KeyboardInterrupt`.
    """
    if clusterer is None:
        clusterer = get_clusterer()
    log.info(
        "clusterer started impl=%s poll_interval_secs=%s",
        clusterer.name, poll_interval_secs,
    )

    bus: Optional[BaseBus] = None
    wake = asyncio.Event()
    wake_tasks: list[asyncio.Task] = []
    heartbeat_task: Optional[asyncio.Task] = None
    try:
        candidate = get_bus(client_name="clusterer")
        await candidate.connect()
        bus = candidate
        wake_tasks.append(asyncio.create_task(
            _wake_on(bus, wake, _topics.attacker(_topics.ATTACKER_OBSERVED)),
        ))
        wake_tasks.append(asyncio.create_task(
            _wake_on(bus, wake, _topics.attacker(_topics.ATTACKER_SCORED)),
        ))
        heartbeat_task = asyncio.create_task(
            _run_health_heartbeat(bus, "clusterer"),
        )
        wake_tasks.append(asyncio.create_task(
            _run_control_listener_signal(bus, "clusterer"),
        ))
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "clusterer: bus unavailable, running in poll-only mode: %s", exc,
        )

    if shutdown is None:
        shutdown = asyncio.Event()

    try:
        while not shutdown.is_set():
            try:
                result = await clusterer.tick(repo)
            except Exception:  # noqa: BLE001
                log.exception("clusterer: tick failed")
                result = ClusterResult()

            await _publish_result(bus, result)

            try:
                await asyncio.wait_for(
                    wake.wait(), timeout=float(poll_interval_secs),
                )
            except asyncio.TimeoutError:
                pass
            wake.clear()
    except (asyncio.CancelledError, KeyboardInterrupt):
        log.info("clusterer stopped")
    finally:
        for t in wake_tasks:
            t.cancel()
        if heartbeat_task is not None:
            heartbeat_task.cancel()
        for task in (*wake_tasks, heartbeat_task):
            if task is None:
                continue
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()


async def _publish_result(bus: Optional[BaseBus], result: ClusterResult) -> None:
    """Fan ``ClusterResult`` out to the four ``identity.*`` topics."""
    for formed in result.identities_formed:
        await publish_safely(
            bus,
            _topics.identity(_topics.IDENTITY_FORMED),
            formed,
            event_type=_topics.IDENTITY_FORMED,
        )
    for linked in result.observations_linked:
        await publish_safely(
            bus,
            _topics.identity(_topics.IDENTITY_OBSERVATION_LINKED),
            linked,
            event_type=_topics.IDENTITY_OBSERVATION_LINKED,
        )
    for merged in result.identities_merged:
        await publish_safely(
            bus,
            _topics.identity(_topics.IDENTITY_MERGED),
            merged,
            event_type=_topics.IDENTITY_MERGED,
        )
    for unmerged in result.identities_unmerged:
        await publish_safely(
            bus,
            _topics.identity(_topics.IDENTITY_UNMERGED),
            unmerged,
            event_type=_topics.IDENTITY_UNMERGED,
        )


async def _wake_on(bus: BaseBus, wake: asyncio.Event, pattern: str) -> None:
    """Flip *wake* every time *pattern* fires on the bus.

    Survives transient subscriber errors by logging and exiting; the
    poll-interval fallback keeps the loop alive in poll-only mode.
    """
    try:
        sub = bus.subscribe(pattern)
        async with sub:
            async for _event in sub:
                wake.set()
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "clusterer: subscriber for %s died (%s); falling back to poll",
            pattern, exc,
        )


__all__ = ["run_clusterer_loop"]
