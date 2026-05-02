"""E.3.18a — Worker hydrates per-lifter rule indexes via watch_store().

Pins the wiring fix from ``development/TTP_TAGGING.md`` §"Worker shape":
each :class:`~decnet.ttp.base.WatchableTagger` child of the
:class:`CompositeTagger` (every per-source lifter, plus the
:class:`RuleEngineTagger`) must have its ``watch_store()`` coroutine
launched as an :mod:`asyncio` task by ``run_ttp_worker_loop`` — without
this fan-out every dispatch index stays empty and no rule fires in
production.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from decnet.bus.fake import FakeBus
from decnet.ttp.base import Tagger, TaggerEvent
from decnet.ttp.factory import CompositeTagger
from decnet.ttp.worker import run_ttp_worker_loop
from decnet.web.db.models.ttp import TTPTag


class _WatchableLifter(Tagger):
    """Stub lifter exposing a ``watch_store`` that records lifecycle events."""

    name = "watchable"
    HANDLES = frozenset({"session"})

    def __init__(self, *, raise_on_watch: bool = False) -> None:
        self.watch_started = asyncio.Event()
        self.watch_cancelled = False
        self.watch_finished = False
        self.raise_on_watch = raise_on_watch

    async def tag(self, event: TaggerEvent) -> list[TTPTag]:
        return []

    async def watch_store(self) -> None:
        self.watch_started.set()
        if self.raise_on_watch:
            raise RuntimeError("watch_store blew up")
        try:
            await asyncio.Event().wait()  # block forever until cancelled
        except asyncio.CancelledError:
            self.watch_cancelled = True
            raise
        finally:
            self.watch_finished = True


class _NonWatchableLifter(Tagger):
    """Stub lifter with NO watch_store — must be skipped by fan-out."""

    name = "nonwatch"
    HANDLES = frozenset({"intel"})

    async def tag(self, event: TaggerEvent) -> list[TTPTag]:
        return []


class _StubRepo:
    async def insert_tags(self, rows: list[TTPTag]) -> int:
        return 0


async def _run_worker_briefly(
    composite: CompositeTagger, repo: Any, *, settle: float = 0.05,
) -> None:
    bus = FakeBus()
    await bus.connect()
    shutdown = asyncio.Event()
    task = asyncio.create_task(run_ttp_worker_loop(
        repo=repo,
        poll_interval_secs=0.05,
        tagger=composite,
        shutdown=shutdown,
        bus=bus,
    ))
    await asyncio.sleep(settle)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)
    await bus.close()


@pytest.mark.asyncio
async def test_iter_watchables_filters_to_watch_capable_lifters() -> None:
    watchable = _WatchableLifter()
    non = _NonWatchableLifter()
    composite = CompositeTagger(lifters=[watchable, non])
    yielded = list(composite.iter_watchables())
    assert watchable in yielded
    assert non not in yielded


@pytest.mark.asyncio
async def test_worker_starts_watch_store_for_every_watchable() -> None:
    a, b = _WatchableLifter(), _WatchableLifter()
    composite = CompositeTagger(lifters=[a, b])
    await _run_worker_briefly(composite, _StubRepo())
    assert a.watch_started.is_set()
    assert b.watch_started.is_set()
    assert a.watch_cancelled and b.watch_cancelled


@pytest.mark.asyncio
async def test_worker_does_not_call_watch_store_on_nonwatchable() -> None:
    watch = _WatchableLifter()
    non = _NonWatchableLifter()
    composite = CompositeTagger(lifters=[watch, non])
    # If the worker tried to call watch_store on `non` it would
    # AttributeError; that the run completes cleanly proves we filter.
    await _run_worker_briefly(composite, _StubRepo())
    assert watch.watch_started.is_set()


@pytest.mark.asyncio
async def test_watch_store_failure_does_not_kill_worker() -> None:
    bad = _WatchableLifter(raise_on_watch=True)
    good = _WatchableLifter()
    composite = CompositeTagger(lifters=[bad, good])
    # A blow-up in one watch task must not propagate; the worker shuts
    # down cleanly and the surviving lifter's task still runs.
    await _run_worker_briefly(composite, _StubRepo())
    assert good.watch_started.is_set()


@pytest.mark.asyncio
async def test_watch_tasks_cancelled_on_worker_shutdown() -> None:
    watch = _WatchableLifter()
    composite = CompositeTagger(lifters=[watch])
    await _run_worker_briefly(composite, _StubRepo())
    assert watch.watch_cancelled
    assert watch.watch_finished
