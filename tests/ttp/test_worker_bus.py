"""E.2.12 — TTP worker bus integration tests.

Pins the bus surface from ``development/TTP_TAGGING.md`` §"Bus topics",
§"Worker shape", §"Bus delivery requirements":

* ``_TOPICS`` is the single source of truth for worker subscriptions
  and matches the documented set exactly.
* Worker subscribes ONLY to topics in ``_TOPICS`` (no accidental
  string-literal subscriptions drifting from the constants).
* Loop-prevention invariant: invoking the worker on the same source
  event twice (or N=10×) publishes exactly one ``ttp.tagged`` event.
* Engine invoked on incoming events.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import pytest
import pytest_asyncio

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.ttp import worker as _worker
from decnet.ttp.base import Tagger, TaggerEvent
from decnet.ttp.worker import _TOPICS, run_ttp_worker_loop
from decnet.web.db.models.ttp import TTPTag


# ── Fixtures ────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def fake_bus() -> AsyncIterator[FakeBus]:
    bus = FakeBus()
    await bus.connect()
    try:
        yield bus
    finally:
        await bus.close()


# ── Helpers ─────────────────────────────────────────────────────────


def _make_tag(rule_id: str = "R0007", technique_id: str = "T1110") -> TTPTag:
    return TTPTag(
        uuid=f"tag-{rule_id}-{technique_id}",
        source_kind="session",
        source_id="sess-1",
        attacker_uuid="att1",
        identity_uuid="id1",
        session_id="sess-1",
        decky_id="d1",
        tactic="TA0006",
        technique_id=technique_id,
        sub_technique_id=None,
        confidence=0.85,
        rule_id=rule_id,
        rule_version=1,
        evidence={},
        attack_release="v15.1",
        created_at=datetime.now(tz=timezone.utc),
    )


class _FixedTagger(Tagger):
    """Tagger that returns a preset list of tags every time it's invoked."""

    name = "fixed"
    HANDLES = frozenset({"session", "intel", "credential", "identity",
                         "email", "canary_fingerprint"})

    def __init__(self, tags: list[TTPTag]) -> None:
        self._tags = tags
        self.calls: list[TaggerEvent] = []

    async def tag(self, event: TaggerEvent) -> list[TTPTag]:
        self.calls.append(event)
        return list(self._tags)


class _StubRepo:
    """Minimal repo that mimics the deterministic-PK INSERT OR IGNORE.

    First call with a given uuid set returns the row count; replays
    return zero (idempotent). Mirrors :meth:`SQLiteRepository.
    _insert_tags_or_ignore` for tests without a real DB.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self.calls: int = 0

    async def insert_tags(self, rows: list[TTPTag]) -> int:
        self.calls += 1
        new = [r for r in rows if r.uuid not in self._seen]
        for r in new:
            self._seen.add(r.uuid)
        return len(new)


async def _drive_worker(
    bus: FakeBus,
    tagger: Tagger,
    repo: Any,
    publish: list[tuple[str, dict[str, Any]]],
    *,
    settle: float = 0.05,
) -> None:
    """Run the worker, fire publishes, allow the queue to drain, stop."""
    shutdown = asyncio.Event()
    task = asyncio.create_task(run_ttp_worker_loop(
        repo=repo,
        poll_interval_secs=0.05,
        tagger=tagger,
        shutdown=shutdown,
        bus=bus,
    ))
    # Give the per-topic pumps a tick to register their subscriptions.
    await asyncio.sleep(0.01)
    for topic, payload in publish:
        await bus.publish(topic, payload)
    await asyncio.sleep(settle)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)


async def _collect(
    bus: FakeBus, pattern: str,
) -> list[tuple[str, dict[str, Any]]]:
    """Collect every event seen on *pattern* from now until the bus closes."""
    collected: list[tuple[str, dict[str, Any]]] = []
    sub = bus.subscribe(pattern)

    async def _drain() -> None:
        try:
            async with sub:
                async for ev in sub:
                    collected.append((ev.topic, ev.payload))
        except Exception:
            pass

    asyncio.create_task(_drain())
    await asyncio.sleep(0)  # let subscriber register
    return collected


# ── _TOPICS surface ─────────────────────────────────────────────────


def test_topics_matches_documented_set() -> None:
    expected = frozenset({
        _topics.attacker(_topics.ATTACKER_SESSION_ENDED),
        _topics.attacker(_topics.ATTACKER_OBSERVED),
        _topics.attacker(_topics.ATTACKER_INTEL_ENRICHED),
        _topics.identity(_topics.IDENTITY_FORMED),
        _topics.identity(_topics.IDENTITY_MERGED),
        _topics.credential(_topics.CREDENTIAL_REUSE_DETECTED),
        _topics.email_topic(_topics.EMAIL_RECEIVED),
        f"{_topics.CANARY}.>",
    })
    assert frozenset(_TOPICS) == expected


def test_topics_is_module_level_constant() -> None:
    assert hasattr(_worker, "_TOPICS")
    assert isinstance(_worker._TOPICS, tuple)
    assert all(isinstance(t, str) for t in _worker._TOPICS)


def test_topics_published_on_publish_topics_match_pattern() -> None:
    from decnet.bus.base import matches  # noqa: PLC0415

    for pattern in _TOPICS:
        assert pattern, "empty pattern in _TOPICS"
        assert " " not in pattern
        if pattern.endswith(".>"):
            base = pattern[:-2]
            assert matches(pattern, f"{base}.example")
        else:
            assert matches(pattern, pattern)


# ── Subscription wiring ─────────────────────────────────────────────


async def test_worker_subscribes_only_to_topics(fake_bus: FakeBus) -> None:
    """Run the worker briefly and assert every subscription pattern
    appears in :data:`_TOPICS`. Reads ``FakeBus._subs`` directly —
    the in-process transport's only introspection hook.
    """
    shutdown = asyncio.Event()
    task = asyncio.create_task(run_ttp_worker_loop(
        repo=_StubRepo(),
        poll_interval_secs=0.05,
        tagger=_FixedTagger(tags=[]),
        shutdown=shutdown,
        bus=fake_bus,
    ))
    await asyncio.sleep(0.02)
    # Heartbeat + control-listener subscribe to system.* topics; filter
    # those out and assert what's left is exactly the documented set.
    patterns = {sub.pattern for sub in fake_bus._subs}
    ttp_patterns = {p for p in patterns if not p.startswith("system.")}
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)
    assert ttp_patterns == set(_TOPICS), (
        f"worker subscribed outside _TOPICS: extras={ttp_patterns - set(_TOPICS)}, "
        f"missing={set(_TOPICS) - ttp_patterns}"
    )


# ── Worker invokes engine on session.ended ──────────────────────────


async def test_session_ended_invokes_engine(fake_bus: FakeBus) -> None:
    """A faked ``attacker.session.ended`` event triggers tagger.tag()."""
    tagger = _FixedTagger(tags=[_make_tag()])
    repo = _StubRepo()
    await _drive_worker(
        fake_bus, tagger, repo,
        [(_topics.attacker(_topics.ATTACKER_SESSION_ENDED), {
            "session_id": "sess-1", "attacker_uuid": "att1",
        })],
    )
    assert len(tagger.calls) >= 1
    assert tagger.calls[0].source_kind == "session"
    assert tagger.calls[0].session_id == "sess-1"
    assert repo.calls == 1


# ── Loop prevention ─────────────────────────────────────────────────


async def test_loop_prevention_no_re_fire(fake_bus: FakeBus) -> None:
    """Same upstream event fired N=5× → exactly one ``ttp.tagged``.

    The repo's idempotent INSERT OR IGNORE returns 0 on replays; the
    worker is contractually forbidden from publishing on a 0-rowcount
    write (TTP_TAGGING.md §"Bus topics").
    """
    tagged: list[tuple[str, dict[str, Any]]] = []

    async def _capture() -> None:
        sub = fake_bus.subscribe(_topics.ttp(_topics.TTP_TAGGED))
        async with sub:
            async for ev in sub:
                tagged.append((ev.topic, ev.payload))

    capture_task = asyncio.create_task(_capture())
    await asyncio.sleep(0)
    tagger = _FixedTagger(tags=[_make_tag()])
    repo = _StubRepo()
    await _drive_worker(
        fake_bus, tagger, repo,
        [
            (_topics.attacker(_topics.ATTACKER_SESSION_ENDED), {
                "session_id": "sess-replay", "attacker_uuid": "att1",
            }),
        ] * 5,
        settle=0.15,
    )
    capture_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await capture_task
    assert len(tagged) == 1, f"expected 1 ttp.tagged event, got {len(tagged)}"


# ── Worker module surface ───────────────────────────────────────────


def test_run_ttp_worker_loop_signature() -> None:
    import inspect  # noqa: PLC0415
    assert asyncio.iscoroutinefunction(run_ttp_worker_loop)
    sig = inspect.signature(run_ttp_worker_loop)
    assert "repo" in sig.parameters
    assert "tagger" in sig.parameters
    assert "shutdown" in sig.parameters


# ── Bus delivery asymmetry (still xfail — catch-up paths are E.3.14b) ─


@pytest.mark.xfail(
    strict=True,
    reason="catch-up via attacker.session.ended is design-deferred to "
    "E.3.14b; today the worker fans events 1:1 by source_kind",
)
async def test_dropped_intel_enriched_still_produces_intel_tags(
    fake_bus: FakeBus,
) -> None:
    pytest.fail("intel catch-up path not yet implemented")


async def test_dropped_email_received_produces_no_email_tags(
    fake_bus: FakeBus,
) -> None:
    """Dropping ``email.received`` produces NO email-derived tags.

    The asymmetry is deliberate: emails arrive as a single bus event
    and are processed once. There is no catch-up path. Exercise this
    by NOT publishing email.received and confirming the tagger never
    sees an email-source event.
    """
    tagger = _FixedTagger(tags=[])
    repo = _StubRepo()
    await _drive_worker(
        fake_bus, tagger, repo,
        [(_topics.attacker(_topics.ATTACKER_SESSION_ENDED), {
            "session_id": "sess-1",
        })],
    )
    email_calls = [c for c in tagger.calls if c.source_kind == "email"]
    assert email_calls == []
