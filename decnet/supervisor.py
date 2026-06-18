# SPDX-License-Identifier: AGPL-3.0-or-later
"""In-process worker supervision — host several worker coroutines in one process
without losing per-worker fault isolation.

This is the consolidation primitive for DECNET 1.1 (see
``development/RELEASE-1.1.md``). It deliberately does NOT use
``asyncio.TaskGroup``: TaskGroup cancels every sibling when one task raises,
which is the opposite of worker isolation. Instead each worker runs in its own
``supervise()`` restart loop — the in-process equivalent of systemd
``Restart=on-failure`` with exponential backoff — and the loops are run
concurrently so one crashing worker never takes down the others.
"""
from __future__ import annotations

import asyncio
import logging
import signal
from collections.abc import Awaitable, Callable

log = logging.getLogger("decnet.supervisor")

# A worker is anything that returns a fresh awaitable each time it's (re)started.
WorkerFactory = Callable[[], Awaitable[None]]


async def supervise(
    name: str, factory: WorkerFactory, *, max_backoff: float = 30.0
) -> None:
    """Run one worker, restarting it with exponential backoff if it crashes.

    - A raised exception → log, sleep (capped backoff), restart.
    - A clean return → stop supervising (the worker decided it was done).
    - Cancellation (group shutdown) → propagate, do not restart.
    """
    backoff = 1.0
    while True:
        try:
            await factory()
        except asyncio.CancelledError:
            log.info("worker %s cancelled; stopping", name)
            raise
        except Exception:
            log.exception(
                "worker %s crashed; restarting in %.0fs", name, backoff
            )
            try:
                await asyncio.sleep(backoff)
            except asyncio.CancelledError:
                raise
            backoff = min(backoff * 2.0, max_backoff)
        else:
            log.info("worker %s exited cleanly; not restarting", name)
            return


async def run_group(
    specs: list[tuple[str, WorkerFactory]],
    *,
    stop: asyncio.Event | None = None,
    install_signals: bool = True,
) -> None:
    """Host a group of workers as independently-supervised concurrent tasks.

    Returns when ``stop`` is set (SIGTERM/SIGINT install it by default), at which
    point every worker task is cancelled and awaited. A worker that exits or
    crashes on its own never cancels its siblings — that is the whole point.
    """
    if not specs:
        return
    if stop is None:
        stop = asyncio.Event()
    if install_signals:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError):  # pragma: no cover
                pass

    tasks = [
        asyncio.create_task(supervise(name, fac), name=name)
        for name, fac in specs
    ]
    log.info("supervisor: hosting %d workers: %s", len(tasks),
             ", ".join(n for n, _ in specs))
    try:
        await stop.wait()
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        log.info("supervisor: group shut down (%d workers)", len(tasks))
