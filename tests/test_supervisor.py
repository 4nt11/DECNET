# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the in-process worker supervisor (DECNET 1.1 consolidation)."""
from __future__ import annotations

import asyncio

import pytest

from decnet.supervisor import run_group, supervise

pytestmark = pytest.mark.asyncio


async def test_supervise_restarts_on_crash():
    calls = []

    async def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise RuntimeError("boom")
        # third start: block until cancelled
        await asyncio.Event().wait()

    task = asyncio.create_task(supervise("flaky", flaky, max_backoff=0.01))
    # let it crash-restart its way to the blocking third start
    for _ in range(200):
        if len(calls) >= 3:
            break
        await asyncio.sleep(0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(calls) == 3  # crashed twice, restarted, then stuck on the 3rd


async def test_supervise_clean_exit_does_not_restart():
    calls = []

    async def one_shot():
        calls.append(1)

    await asyncio.wait_for(supervise("once", one_shot), timeout=1.0)
    assert calls == [1]  # returned cleanly, no restart loop


async def test_one_worker_crash_does_not_kill_siblings():
    survivor_ticks = []
    crash_count = []

    async def survivor():
        while True:
            survivor_ticks.append(1)
            await asyncio.sleep(0.005)

    async def crasher():
        crash_count.append(1)
        raise RuntimeError("crash")

    stop = asyncio.Event()
    group = asyncio.create_task(
        run_group(
            [("survivor", survivor), ("crasher", crasher)],
            stop=stop,
            install_signals=False,
        )
    )
    await asyncio.sleep(0.1)
    # survivor kept ticking despite crasher dying — the isolation property.
    # (restart/backoff timing is covered by test_supervise_restarts_on_crash)
    assert len(survivor_ticks) > 3
    assert len(crash_count) >= 1
    stop.set()
    await asyncio.wait_for(group, timeout=1.0)


async def test_run_group_shutdown_cancels_all():
    running = {"a": False, "b": False}

    def make(name):
        async def worker():
            running[name] = True
            try:
                await asyncio.Event().wait()
            finally:
                running[name] = False
        return worker

    stop = asyncio.Event()
    group = asyncio.create_task(
        run_group(
            [("a", make("a")), ("b", make("b"))],
            stop=stop,
            install_signals=False,
        )
    )
    await asyncio.sleep(0.05)
    assert running == {"a": True, "b": True}
    stop.set()
    await asyncio.wait_for(group, timeout=1.0)
    assert running == {"a": False, "b": False}  # finally blocks ran → clean cancel


async def test_empty_group_returns_immediately():
    await asyncio.wait_for(run_group([], install_signals=False), timeout=1.0)
