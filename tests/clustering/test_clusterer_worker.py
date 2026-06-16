# SPDX-License-Identifier: AGPL-3.0-or-later
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


@pytest.mark.anyio
async def test_wake_during_tick_is_not_lost(repo):
    """BUG-14 regression: wake.clear() must run BEFORE wake.wait(), not after.

    The worker loop pattern:

        Fixed (after fix):   tick → clear → wait     ← current code
        Buggy (before fix):  tick → wait → clear

    The race in the buggy pattern: a wake.set() could arrive from a _wake_on
    background task between wait() returning and clear() executing.  In asyncio
    the task switch requires an ``await``; the original code had
    ``await _publish_result`` between wait() and clear(), providing a real
    window.  The fix closes this by moving clear() to run immediately after
    tick (before wait), so there is no window between wait() returning and the
    next clear().

    **Structural test (red-before / green-after, deterministic):**
    We intercept the internal ``wake`` event's ``clear()`` and ``wait()``
    methods to record their invocation order, then assert that every
    ``clear`` call is immediately followed by a ``wait`` (never preceded by
    one).  Reverting the worker to the buggy ``wait → clear`` order produces
    ``("wait", "clear")`` consecutive pairs, which the assertion catches
    deterministically without relying on wall-clock timing races.
    """
    import unittest.mock as _mock

    captured_wake: list[asyncio.Event] = []
    call_log: list[str] = []

    _orig_event_cls = asyncio.Event

    class _LoggingEvent(_orig_event_cls):  # type: ignore[misc]
        """Subclass captures the first event created (the wake event) and
        logs clear()/wait() calls so we can verify their relative order."""

        def __init__(self) -> None:
            super().__init__()
            if not captured_wake:
                captured_wake.append(self)

        def clear(self) -> None:
            if captured_wake and self is captured_wake[0]:
                call_log.append("clear")
            super().clear()

        async def wait(self) -> bool:  # type: ignore[override]
            if captured_wake and self is captured_wake[0]:
                call_log.append("wait")
            return await super().wait()

    class _SimpleTicker(Clusterer):
        name = "bug14_ticker"

        async def tick(self, _repo) -> ClusterResult:
            return ClusterResult()

    shutdown = asyncio.Event()

    with _mock.patch("decnet.clustering.worker.asyncio.Event", _LoggingEvent):
        task = asyncio.create_task(
            run_clusterer_loop(
                repo,
                poll_interval_secs=0.1,
                clusterer=_SimpleTicker(),
                shutdown=shutdown,
            )
        )
        # Run for long enough to accumulate several clear/wait pairs.
        await asyncio.sleep(0.5)
        shutdown.set()
        await asyncio.wait_for(task, timeout=2.0)

    # Must have enough events to be meaningful.
    assert len(call_log) >= 4, (
        f"BUG-14: too few clear/wait calls recorded ({call_log!r}); "
        "loop may not have run or event capture failed"
    )

    # Fixed invariant: every loop iteration runs clear() BEFORE wait().
    # The resulting call_log for the fixed code is: clear, wait, clear, wait, ...
    # For the buggy code (wait → clear) the log would be:  wait, clear, wait, clear, ...
    #
    # We verify TWO conditions that together guarantee the fixed order:
    #
    # 1. The log starts with "clear" — the very first thing after tick is a clear.
    #    Buggy code starts with "wait" (wait ran first in the original loop).
    #
    # 2. Within each (clear, wait) pair at positions (2k, 2k+1), clear always
    #    precedes wait.  We check that no "clear" appears at an ODD index (which
    #    would mean a clear followed another clear, or a wait appeared before
    #    the next clear).
    assert call_log[0] == "clear", (
        f"BUG-14 regression: first wake call was {call_log[0]!r}, expected 'clear'. "
        f"Full log: {call_log!r}.  The worker is using the buggy 'wait-then-clear' "
        "order — wake.clear() must execute BEFORE wake.wait() each iteration."
    )
    # Verify the alternating pattern holds: indices 0,2,4,... should be "clear"
    # and indices 1,3,5,... should be "wait".
    for idx, call in enumerate(call_log):
        if idx % 2 == 0:
            assert call == "clear", (
                f"BUG-14 regression: expected 'clear' at position {idx} but got "
                f"{call!r} in log {call_log!r}.  This indicates the loop is NOT "
                "using the fixed 'clear → wait' order within each iteration."
            )
        else:
            assert call == "wait", (
                f"BUG-14 regression: expected 'wait' at position {idx} but got "
                f"{call!r} in log {call_log!r}.  This indicates the loop is NOT "
                "using the fixed 'clear → wait' order within each iteration."
            )
