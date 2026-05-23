# SPDX-License-Identifier: AGPL-3.0-or-later
"""Clusterer publishes ``identity.formed`` and ``identity.merged``.

Pins the producer wiring. The clusterer reports its tick output via a
:class:`ClusterResult`; the worker fans the four sub-lists out to the
matching ``identity.*`` topics. This test runs one tick with a fake
clusterer that returns a result containing one formed and one merged
identity, and asserts the bus saw both envelopes.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.clustering import worker as _cw
from decnet.clustering.base import ClusterResult, Clusterer
from decnet.web.db.repository import BaseRepository


class _FakeClusterer(Clusterer):
    name = "fake"

    def __init__(self, results: list[ClusterResult]) -> None:
        self._results = list(results)

    async def tick(self, _repo: BaseRepository) -> ClusterResult:
        if self._results:
            return self._results.pop(0)
        return ClusterResult()


@pytest.mark.asyncio
async def test_clusterer_publishes_identity_formed_and_merged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = FakeBus()
    await bus.connect()
    monkeypatch.setattr(_cw, "get_bus", lambda *_a, **_kw: bus)

    captured: list[tuple[str, dict[str, Any]]] = []
    sub = bus.subscribe("identity.>")

    async def drain() -> None:
        try:
            async with sub:
                async for ev in sub:
                    captured.append((ev.topic, ev.payload))
        except Exception:
            pass

    drain_task = asyncio.create_task(drain())
    await asyncio.sleep(0)

    result = ClusterResult(
        identities_formed=[
            {"identity_uuid": "id-1", "observation_uuids": ["obs-1", "obs-2"]},
        ],
        identities_merged=[
            {"winner_uuid": "id-1", "loser_uuid": "id-9"},
        ],
    )
    fake = _FakeClusterer([result])

    shutdown = asyncio.Event()

    class _RepoStub:
        pass

    loop_task = asyncio.create_task(_cw.run_clusterer_loop(
        _RepoStub(),  # type: ignore[arg-type]
        poll_interval_secs=0.05, clusterer=fake,
        shutdown=shutdown,
    ))
    await asyncio.sleep(0.15)
    shutdown.set()
    await asyncio.wait_for(loop_task, timeout=2.0)
    drain_task.cancel()
    await bus.close()

    topics_seen = [t for t, _ in captured]
    assert _topics.identity(_topics.IDENTITY_FORMED) in topics_seen
    assert _topics.identity(_topics.IDENTITY_MERGED) in topics_seen
    formed = next(
        p for t, p in captured
        if t == _topics.identity(_topics.IDENTITY_FORMED)
    )
    assert formed["identity_uuid"] == "id-1"
    merged = next(
        p for t, p in captured
        if t == _topics.identity(_topics.IDENTITY_MERGED)
    )
    assert merged["winner_uuid"] == "id-1"
    assert merged["loser_uuid"] == "id-9"
