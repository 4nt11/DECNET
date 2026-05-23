# SPDX-License-Identifier: AGPL-3.0-or-later
"""Long-lived periodic reconciler worker.

Modeled on :mod:`decnet.orchestrator.worker`: same control listener, same
heartbeat helper, same shutdown semantics.  One tick = one
:func:`reconcile_once` pass.

Default interval is short (30s) because reconciliation is cheap when
nothing has drifted (three reads, no writes), and a short cadence keeps
the dashboard's view of crashed containers fresh.
"""
from __future__ import annotations

import asyncio
import contextlib

from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    run_control_listener,
    run_health_heartbeat,
)
from decnet.fleet.reconciler import reconcile_once
from decnet.logging import get_logger
from decnet.web.db.models import LOCAL_HOST_SENTINEL
from decnet.web.db.repository import BaseRepository

logger = get_logger("fleet.reconciler")


async def fleet_reconciler_worker(
    repo: BaseRepository,
    *,
    interval: int = 30,
    host_uuid: str = LOCAL_HOST_SENTINEL,
) -> None:
    """Periodically converge JSON ↔ DB ↔ docker for the local host.

    Honours the bus control topic (``system.reconciler.control``) for
    graceful shutdown — same lifecycle contract as every other DECNET
    worker.
    """
    logger.info("fleet reconciler started interval=%ds host=%s", interval, host_uuid)

    bus = None
    try:
        bus = get_bus(client_name="reconciler")
        await bus.connect()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "reconciler: bus unavailable, continuing without publish: %s", exc,
        )
        bus = None

    shutdown = asyncio.Event()
    heartbeat_task = asyncio.create_task(run_health_heartbeat(bus, "reconciler"))
    control_task = asyncio.create_task(
        run_control_listener(bus, "reconciler", shutdown),
    )

    try:
        while not shutdown.is_set():
            try:
                await asyncio.wait_for(shutdown.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass  # normal tick
            if shutdown.is_set():
                break
            try:
                counts = await reconcile_once(
                    repo, host_uuid=host_uuid, bus=bus,
                )
                if any(counts.values()):
                    logger.info(
                        "reconcile inserted=%d deleted=%d state_updated=%d",
                        counts["inserted"], counts["deleted"],
                        counts["state_updated"],
                    )
            except Exception as exc:  # noqa: BLE001
                logger.error("reconcile tick failed: %s", exc)
    finally:
        for t in (heartbeat_task, control_task):
            t.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await t
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()
