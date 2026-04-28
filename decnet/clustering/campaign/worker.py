"""Long-running campaign-clusterer worker.

Mirrors :mod:`decnet.clustering.worker` for the layer above. Bus-woken
on ``identity.>`` (not ``attacker.>`` — the campaign clusterer reads
identities, not raw observations); falls back to a 60s slow-tick poll
when the bus is unavailable.

Publishes the four ``campaign.*`` events plus the cross-family
``identity.campaign.assigned`` so existing identity-stream subscribers
see campaign-id changes without subscribing to ``campaign.>``.
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
from decnet.clustering.campaign.base import (
    CampaignClusterer,
    CampaignClusterResult,
)
from decnet.clustering.campaign.factory import get_campaign_clusterer
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository

log = get_logger("clustering.campaign.worker")

_DEFAULT_POLL_SECS = 60.0
_WORKER_NAME = "campaign-clusterer"


async def run_campaign_clusterer_loop(
    repo: BaseRepository,
    *,
    poll_interval_secs: float = _DEFAULT_POLL_SECS,
    clusterer: Optional[CampaignClusterer] = None,
    shutdown: Optional[asyncio.Event] = None,
) -> None:
    """Run the campaign clusterer until cancelled."""
    if clusterer is None:
        clusterer = get_campaign_clusterer()
    log.info(
        "campaign-clusterer started impl=%s poll_interval_secs=%s",
        clusterer.name, poll_interval_secs,
    )

    bus: Optional[BaseBus] = None
    wake = asyncio.Event()
    wake_tasks: list[asyncio.Task] = []
    heartbeat_task: Optional[asyncio.Task] = None
    try:
        candidate = get_bus(client_name=_WORKER_NAME)
        await candidate.connect()
        bus = candidate
        # Wake on any identity-layer event — formed / linked / merged /
        # unmerged all change the input set the campaign clusterer
        # operates over.
        wake_tasks.append(asyncio.create_task(
            _wake_on(bus, wake, f"{_topics.IDENTITY}.>"),
        ))
        heartbeat_task = asyncio.create_task(
            _run_health_heartbeat(bus, _WORKER_NAME),
        )
        wake_tasks.append(asyncio.create_task(
            _run_control_listener_signal(bus, _WORKER_NAME),
        ))
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "campaign-clusterer: bus unavailable, running in poll-only "
            "mode: %s", exc,
        )

    if shutdown is None:
        shutdown = asyncio.Event()

    try:
        while not shutdown.is_set():
            try:
                result = await clusterer.tick(repo)
            except Exception:  # noqa: BLE001
                log.exception("campaign-clusterer: tick failed")
                result = CampaignClusterResult()

            await _publish_result(bus, result)

            try:
                await asyncio.wait_for(
                    wake.wait(), timeout=float(poll_interval_secs),
                )
            except asyncio.TimeoutError:
                pass
            wake.clear()
    except (asyncio.CancelledError, KeyboardInterrupt):
        log.info("campaign-clusterer stopped")
    finally:
        for t in wake_tasks:
            t.cancel()
        if heartbeat_task is not None:
            heartbeat_task.cancel()
        for t in (*wake_tasks, heartbeat_task):
            if t is None:
                continue
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()


async def _publish_result(
    bus: Optional[BaseBus], result: CampaignClusterResult,
) -> None:
    """Fan ``CampaignClusterResult`` out to ``campaign.*`` topics +
    cross-family ``identity.campaign.assigned``."""
    for formed in result.campaigns_formed:
        await publish_safely(
            bus,
            _topics.campaign(_topics.CAMPAIGN_FORMED),
            formed,
            event_type=_topics.CAMPAIGN_FORMED,
        )
        # Also fire identity.campaign.assigned per identity so the
        # existing identity SSE stream sees the badge update.
        for identity_uuid in formed.get("identity_uuids", []):
            await publish_safely(
                bus,
                _topics.identity(_topics.IDENTITY_CAMPAIGN_ASSIGNED),
                {
                    "identity_uuid": identity_uuid,
                    "campaign_uuid": formed["campaign_uuid"],
                    "prior_campaign_uuid": None,
                },
                event_type=_topics.IDENTITY_CAMPAIGN_ASSIGNED,
            )
    for assigned in result.identities_assigned:
        await publish_safely(
            bus,
            _topics.campaign(_topics.CAMPAIGN_IDENTITY_ASSIGNED),
            assigned,
            event_type=_topics.CAMPAIGN_IDENTITY_ASSIGNED,
        )
        await publish_safely(
            bus,
            _topics.identity(_topics.IDENTITY_CAMPAIGN_ASSIGNED),
            {
                "identity_uuid": assigned["identity_uuid"],
                "campaign_uuid": assigned["campaign_uuid"],
                "prior_campaign_uuid": assigned.get("prior_campaign_uuid"),
            },
            event_type=_topics.IDENTITY_CAMPAIGN_ASSIGNED,
        )
    for merged in result.campaigns_merged:
        await publish_safely(
            bus,
            _topics.campaign(_topics.CAMPAIGN_MERGED),
            merged,
            event_type=_topics.CAMPAIGN_MERGED,
        )
    for unmerged in result.campaigns_unmerged:
        await publish_safely(
            bus,
            _topics.campaign(_topics.CAMPAIGN_UNMERGED),
            unmerged,
            event_type=_topics.CAMPAIGN_UNMERGED,
        )


async def _wake_on(bus: BaseBus, wake: asyncio.Event, pattern: str) -> None:
    try:
        sub = bus.subscribe(pattern)
        async with sub:
            async for _event in sub:
                wake.set()
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "campaign-clusterer: subscriber for %s died (%s); falling back "
            "to poll", pattern, exc,
        )


__all__ = ["run_campaign_clusterer_loop"]
