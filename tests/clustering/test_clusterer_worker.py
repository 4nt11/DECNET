"""End-to-end tests for the clusterer worker shell.

The skeleton clusterer is a no-op; these tests cover the shell:

* exits cleanly on shutdown signal (and via cancel)
* invokes ``tick`` on each loop iteration
* publishes :class:`ClusterResult` side-effects on the right topics
* a clusterer raising from ``tick`` is logged and does not crash the loop
"""
from __future__ import annotations

import asyncio

import pytest

from decnet.bus import topics as _topics
from decnet.clustering.base import Clusterer, ClusterResult
from decnet.clustering.impl.connected_components import ConnectedComponentsClusterer
from decnet.clustering.worker import run_clusterer_loop
from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "clusterer.db"))
    await r.initialize()
    return r


@pytest.fixture(autouse=True)
def _no_bus(monkeypatch):
    """Run workers in poll-only mode — no real Unix socket."""
    monkeypatch.setenv("DECNET_BUS_ENABLED", "false")


class _FakeClusterer(Clusterer):
    """Test double: returns canned :class:`ClusterResult` per call."""

    name = "fake"

    def __init__(self, results: list[ClusterResult] | None = None) -> None:
        self._results = list(results or [])
        self.calls = 0

    async def tick(self, repo) -> ClusterResult:
        self.calls += 1
        if self._results:
            return self._results.pop(0)
        return ClusterResult()


class _RaisingClusterer(Clusterer):
    name = "raising"

    def __init__(self) -> None:
        self.calls = 0

    async def tick(self, repo) -> ClusterResult:
        self.calls += 1
        raise RuntimeError("boom")


@pytest.mark.anyio
async def test_loop_exits_on_shutdown_signal(repo):
    shutdown = asyncio.Event()
    clusterer = _FakeClusterer()
    task = asyncio.create_task(
        run_clusterer_loop(
            repo,
            poll_interval_secs=0.05,
            clusterer=clusterer,
            shutdown=shutdown,
        )
    )
    await asyncio.sleep(0.12)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)
    assert clusterer.calls >= 1


@pytest.mark.anyio
async def test_loop_exits_on_cancel(repo):
    clusterer = _FakeClusterer()
    task = asyncio.create_task(
        run_clusterer_loop(
            repo,
            poll_interval_secs=0.05,
            clusterer=clusterer,
        )
    )
    await asyncio.sleep(0.1)
    task.cancel()
    # The loop catches CancelledError and exits cleanly, mirroring the
    # intel + reuse worker shells.
    await asyncio.wait_for(task, timeout=2.0)
    assert clusterer.calls >= 1


@pytest.mark.anyio
async def test_tick_failure_does_not_crash_loop(repo):
    """A clusterer raising from tick must be logged, not propagated."""
    shutdown = asyncio.Event()
    clusterer = _RaisingClusterer()
    task = asyncio.create_task(
        run_clusterer_loop(
            repo,
            poll_interval_secs=0.05,
            clusterer=clusterer,
            shutdown=shutdown,
        )
    )
    await asyncio.sleep(0.2)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)
    # Loop kept ticking despite the raise.
    assert clusterer.calls >= 2


@pytest.mark.anyio
async def test_skeleton_clusterer_returns_empty_result(repo):
    """The connected-components skeleton produces no side-effects yet."""
    c = ConnectedComponentsClusterer()
    result = await c.tick(repo)
    assert result.identities_formed == []
    assert result.observations_linked == []
    assert result.identities_merged == []
    assert result.identities_unmerged == []


@pytest.mark.anyio
async def test_publishes_cluster_result_on_bus(monkeypatch, repo):
    """Every entry in ClusterResult fans out to the correct topic."""
    published: list[tuple[str, dict, str]] = []

    async def _fake_publish(bus, topic, payload, event_type=""):
        published.append((topic, payload, event_type))

    monkeypatch.setattr(
        "decnet.clustering.worker.publish_safely", _fake_publish,
    )

    result = ClusterResult(
        identities_formed=[
            {"identity_uuid": "id-1", "observation_uuids": ["obs-1", "obs-2"]},
        ],
        observations_linked=[
            {"identity_uuid": "id-1", "observation_uuid": "obs-3"},
        ],
        identities_merged=[
            {"winner_uuid": "id-1", "loser_uuid": "id-2"},
        ],
        identities_unmerged=[
            {"resurrected_uuid": "id-2", "former_winner_uuid": "id-1"},
        ],
    )
    clusterer = _FakeClusterer(results=[result])

    shutdown = asyncio.Event()
    task = asyncio.create_task(
        run_clusterer_loop(
            repo,
            poll_interval_secs=0.05,
            clusterer=clusterer,
            shutdown=shutdown,
        )
    )
    await asyncio.sleep(0.1)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)

    topics_seen = {t for t, _, _ in published}
    assert _topics.identity(_topics.IDENTITY_FORMED) in topics_seen
    assert _topics.identity(_topics.IDENTITY_OBSERVATION_LINKED) in topics_seen
    assert _topics.identity(_topics.IDENTITY_MERGED) in topics_seen
    assert _topics.identity(_topics.IDENTITY_UNMERGED) in topics_seen


@pytest.mark.anyio
async def test_clusterer_registered_in_cli():
    """`decnet clusterer` is registered as a master-only command."""
    from decnet.cli.gating import MASTER_ONLY_COMMANDS
    assert "clusterer" in MASTER_ONLY_COMMANDS
