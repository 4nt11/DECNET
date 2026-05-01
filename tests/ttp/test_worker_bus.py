"""E.2.12 — TTP worker bus integration tests.

Pins the bus surface from ``development/TTP_TAGGING.md`` §"Bus topics",
§"Worker shape", §"Bus delivery requirements":

* ``_TOPICS`` is the single source of truth for worker subscriptions
  and matches the documented set exactly.
* Worker subscribes ONLY to topics in ``_TOPICS`` (no accidental
  string-literal subscriptions drifting from the constants).
* Loop-prevention invariant: invoking the worker on the same source
  event twice (or N=10×) publishes exactly one ``ttp.tagged`` event.
* Bus delivery asymmetry: dropping ``attacker.enriched`` still
  produces intel-derived tags via the ``attacker.session.ended``
  catch-up path; dropping ``email.received`` produces NO email tags
  (no catch-up exists for email).
* Engine invoked on incoming events.

Topic-set equality is GREEN today. Worker-loop behavior beyond the
empty inner loop xfail-gated behind E.3.14.
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator

import pytest
import pytest_asyncio

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.ttp import worker as _worker

# Re-imported so a `__all__` regression on the worker module fails
# noisily here rather than via a vague "module has no attribute".
from decnet.ttp.worker import _TOPICS, run_ttp_worker_loop


# ── Fixtures ────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def fake_bus() -> AsyncIterator[FakeBus]:
    bus = FakeBus()
    await bus.connect()
    try:
        yield bus
    finally:
        await bus.close()


# ── _TOPICS surface (GREEN today) ───────────────────────────────────


def test_topics_matches_documented_set() -> None:
    """``_TOPICS`` equals the exact set declared in TTP_TAGGING.md
    §"Bus topics".

    Pinning frozenset equality (rather than tuple equality) since
    subscription order has no observable effect — but the *set*
    must match. A future contributor adding a topic without doc /
    test updates trips this.
    """
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
    """``_TOPICS`` lives at module scope (not method-local) so tests
    can introspect it without invoking the loop. Catches a refactor
    that hides the list inside :func:`run_ttp_worker_loop`."""
    assert hasattr(_worker, "_TOPICS")
    assert isinstance(_worker._TOPICS, tuple)
    assert all(isinstance(t, str) for t in _worker._TOPICS)


def test_topics_published_on_publish_topics_match_pattern() -> None:
    """Every entry in ``_TOPICS`` is a valid bus topic / wildcard.

    Cheap sanity check — no dot-prefix bug, no empty strings, the
    wildcard form (``canary.>``) actually parses through the bus
    matcher.
    """
    from decnet.bus.base import matches  # noqa: PLC0415 — local import to avoid contaminate
    for pattern in _TOPICS:
        assert pattern, f"empty pattern in _TOPICS"
        assert " " not in pattern
        # Self-match: every pattern matches itself when interpreted
        # as both pattern and concrete topic (modulo the ``>`` form
        # which is only valid as pattern-side; for those we test a
        # synthetic concrete extension matches).
        if pattern.endswith(".>"):
            base = pattern[:-2]
            assert matches(pattern, f"{base}.example")
        else:
            assert matches(pattern, pattern)


# ── Subscription wiring (GREEN today: empty subset trivially holds) ─


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.14 — worker bootstrap wires real "
    "subscriptions; today the contract loop subscribes via _wake_on "
    "but the assertion that no OTHER patterns are subscribed needs "
    "introspection that the contract phase doesn't provide.",
)
async def test_worker_subscribes_only_to_topics(fake_bus: FakeBus) -> None:
    """Run the worker briefly against a FakeBus and assert every
    subscription target appears in :data:`_TOPICS`.

    Today the worker creates per-pattern wake tasks via
    :func:`_wake_on`, which DO call ``bus.subscribe`` — but the
    FakeBus doesn't expose a subscriber registry the test can read
    without poking at private state. xfail until E.3.14 wires a
    proper introspection hook (or the impl naturally exposes
    subscribed patterns via a public method).
    """
    pytest.fail("subscription introspection not yet wired")


# ── Worker invokes engine on session.ended (xfail until E.3.14) ─────


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.14 — worker inner loop is a no-op idle "
    "today; engine invocation lands with the worker bootstrap step",
)
async def test_session_ended_invokes_engine(fake_bus: FakeBus) -> None:
    """A faked ``attacker.session.ended`` event triggers a call to
    ``RuleEngine.evaluate`` for the session's events.

    Today the worker idles on the wake event without invoking
    anything, so this assertion xfails. Flips at E.3.14.
    """
    pytest.fail("worker → engine wiring not yet implemented")


# ── Loop prevention (xfail until E.3.14) ────────────────────────────


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.14 — loop-prevention invariant requires "
    "the worker to actually publish ttp.tagged on first eval and "
    "no-op on replay; today the worker publishes nothing.",
)
async def test_loop_prevention_no_re_fire(fake_bus: FakeBus) -> None:
    """Invoking the worker on the same source event N=10× publishes
    exactly one ``ttp.tagged`` event.

    Re-firing on a tag-write would create a feedback loop:
    ttp.tagged → re-eval → ttp.tagged → … . The worker MUST NOT
    subscribe to its own output, AND the underlying repo's
    ``insert_tags`` is idempotent so re-eval writes nothing — both
    halves of the invariant land at E.3.14 + E.3.3.
    """
    pytest.fail("loop-prevention invariant not yet implemented")


# ── Bus delivery asymmetry (xfail until E.3.14) ─────────────────────


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.14 — catch-up via attacker.session.ended "
    "lands with the intel lifter wire-up",
)
async def test_dropped_intel_enriched_still_produces_intel_tags(
    fake_bus: FakeBus,
) -> None:
    """Dropping ``attacker.enriched`` events does NOT lose intel-derived
    tags, because the ``attacker.session.ended`` handler ALSO runs the
    intel lifter as a catch-up path. Pinned per design doc §"Bus
    delivery requirements": "best-effort intel events are belt; the
    session-ended sweep is braces"."""
    pytest.fail("intel catch-up path not yet implemented")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.14 — email lifter only fires on "
    "email.received; no catch-up path exists by design",
)
async def test_dropped_email_received_produces_no_email_tags(
    fake_bus: FakeBus,
) -> None:
    """Dropping ``email.received`` produces NO email-derived tags.

    The asymmetry is deliberate: emails are not stored as a
    re-readable log the worker can sweep on session-ended — they
    arrive as a single bus event and are processed once. The test
    pins this rather than papering over it; a future contributor
    "improving" the worker by adding an email catch-up path would
    trip this test, which is the trip-wire that says "discuss the
    PII implications first".
    """
    pytest.fail("email lifter wiring not yet implemented")


# ── Worker module surface (GREEN today) ─────────────────────────────


def test_run_ttp_worker_loop_signature() -> None:
    """The public entry point exists and is async. Catches a
    refactor that accidentally renames or de-async's the function.
    """
    import inspect  # noqa: PLC0415
    assert asyncio.iscoroutinefunction(run_ttp_worker_loop)
    sig = inspect.signature(run_ttp_worker_loop)
    # Per E.1.7 contract: positional `repo`, keyword-only
    # `poll_interval_secs`, `tagger`, `shutdown`.
    assert "repo" in sig.parameters
    assert "tagger" in sig.parameters
    assert "shutdown" in sig.parameters
