# SPDX-License-Identifier: AGPL-3.0-or-later
"""``decnet bus`` worker entrypoint.

Starts a :class:`~decnet.bus.unix_server.BusServer` on the configured UNIX
socket and serves forever, emitting a ``system.bus.health`` heartbeat on
its own bus every :data:`HEARTBEAT_INTERVAL_SEC` seconds so liveness-aware
consumers (dashboards, watchdogs) can tell the bus is up without polling
the filesystem.

Cross-host federation is **out of scope** for the MVP; each host runs its
own bus independently.  See DEBT-029 for the deferred ``--bridge-tcp``
mode that would proxy the socket over the swarm mTLS channel.
"""
from __future__ import annotations

import asyncio
import os
import pathlib
import signal
import time

from decnet.bus import topics
from decnet.bus.unix_server import BusServer
from decnet.logging import get_logger

log = get_logger("bus.worker")

HEARTBEAT_INTERVAL_SEC = 10


async def bus_worker(
    socket_path: str | pathlib.Path,
    *,
    group: str | None = "decnet",
    heartbeat_interval: int = HEARTBEAT_INTERVAL_SEC,
) -> None:
    """Run the bus server until cancelled or SIGTERM/SIGINT is received.

    The parent directory of *socket_path* must already exist (systemd's
    ``RuntimeDirectory=decnet`` handles this in prod; dev code is expected
    to ``mkdir`` first).  This function does not create it implicitly
    because the right choice of perms/owner depends on the deployment
    context.
    """
    path = pathlib.Path(socket_path)
    _ensure_parent(path)

    server = BusServer(path, group=group)
    await server.start()
    log.info("bus.worker: pid=%d socket=%s", os.getpid(), path)

    stop_event = asyncio.Event()
    _install_signal_handlers(stop_event)

    heartbeat_task = asyncio.create_task(_heartbeat_loop(server, heartbeat_interval))
    serve_task = asyncio.create_task(server.serve_forever())

    try:
        await stop_event.wait()
        log.info("bus.worker: shutdown signal received")
    finally:
        heartbeat_task.cancel()
        serve_task.cancel()
        for task in (heartbeat_task, serve_task):
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001 - draining shutdown
                pass
        await server.close()
        log.info("bus.worker: stopped")


async def _heartbeat_loop(server: BusServer, interval: int) -> None:
    """Publish ``system.bus.health`` on the server's own fan-out."""
    started_at = time.time()
    while True:
        try:
            await server.publish(
                topics.system(topics.SYSTEM_BUS_HEALTH),
                {
                    "pid": os.getpid(),
                    "uptime_sec": round(time.time() - started_at, 3),
                    "ts": time.time(),
                },
                event_type=topics.SYSTEM_BUS_HEALTH,
            )
        except Exception:  # pragma: no cover - heartbeat must never kill the worker
            log.exception("bus.worker: heartbeat publish failed")
        await asyncio.sleep(interval)


def _install_signal_handlers(stop_event: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError):
            # add_signal_handler is not supported on Windows / in some
            # test harnesses where the loop is running in a non-main thread.
            # The worker still exits via KeyboardInterrupt bubbling up.
            pass


def _ensure_parent(path: pathlib.Path) -> None:
    parent = path.parent
    if parent.exists():
        return
    # Dev-box convenience: if the parent is the user's ``~/.decnet`` dir,
    # create it.  We do not auto-mkdir ``/run/decnet`` — that's systemd's job
    # and silently creating it as the wrong user would cause permission
    # confusion later.
    home_prefix = pathlib.Path.home() / ".decnet"
    try:
        parent.relative_to(home_prefix.parent)
    except ValueError:
        raise FileNotFoundError(
            f"bus socket parent {parent} does not exist; create it first"
        )
    parent.mkdir(parents=True, exist_ok=True)


__all__ = ["bus_worker", "HEARTBEAT_INTERVAL_SEC"]
