"""Contract tests for :mod:`decnet.ttp.worker` (E.1.7).

Scoped to the contract surface: ``_TOPICS`` shape and contents,
:func:`run_ttp_worker_loop` signature, clean shutdown via the
``shutdown`` event in poll-only mode, and worker-registry membership.
The full E.2.12 bus-integration battery (subscribed-set equality on
a fake bus, fan-out, loop-prevention invariant) is xfail-strict
pending E.3.
"""
from __future__ import annotations

import asyncio
import inspect

import pytest

from decnet.ttp.base import Tagger, TaggerEvent
from decnet.ttp.worker import _TOPICS, run_ttp_worker_loop
from decnet.web.db.models.ttp import TTPTag
from decnet.web.worker_registry import KNOWN_WORKERS


class _NoopTagger(Tagger):
    name = "noop"

    async def tag(self, event: TaggerEvent) -> list[TTPTag]:
        return []


def test_topics_is_non_empty_tuple_of_strings():
    assert isinstance(_TOPICS, tuple)
    assert _TOPICS, "_TOPICS must enumerate at least one subscription"
    assert all(isinstance(t, str) and t for t in _TOPICS)


def test_topics_covers_documented_design_subscriptions():
    # Sanity: the design doc names session.ended, intel.enriched,
    # email.received, identity.formed, credential.reuse.detected,
    # canary triggers, attacker.observed. We assert the topic STRINGS
    # contain the documented leaves rather than re-importing the
    # builders — keeps the test cheap and immune to topic-builder
    # refactors that preserve wire format.
    joined = " ".join(_TOPICS)
    must_have = [
        "session.ended",
        "intel.enriched",
        "received",  # email.received
        "formed",     # identity.formed
        "reuse.detected",  # credential reuse
        "canary",
        "observed",
    ]
    for fragment in must_have:
        assert fragment in joined, f"_TOPICS missing {fragment!r}"


def test_run_ttp_worker_loop_signature():
    sig = inspect.signature(run_ttp_worker_loop)
    params = sig.parameters
    assert "repo" in params
    assert "poll_interval_secs" in params
    assert "tagger" in params
    assert "shutdown" in params
    # Mirrors :mod:`decnet.intel.worker` and
    # :mod:`decnet.clustering.worker` — keyword-only after ``repo``.
    kw_only = [
        p for p in params.values()
        if p.kind is inspect.Parameter.KEYWORD_ONLY
    ]
    kw_only_names = {p.name for p in kw_only}
    assert {"poll_interval_secs", "tagger", "shutdown"} <= kw_only_names


def test_worker_exits_cleanly_when_shutdown_set_immediately():
    async def _run() -> None:
        shutdown = asyncio.Event()
        shutdown.set()
        # repo isn't touched in the contract phase; pass a sentinel.
        # Bus is unavailable in test env → poll-only path.
        await asyncio.wait_for(
            run_ttp_worker_loop(
                repo=object(),  # type: ignore[arg-type]
                poll_interval_secs=0.05,
                tagger=_NoopTagger(),
                shutdown=shutdown,
            ),
            timeout=5.0,
        )

    asyncio.run(_run())


def test_ttp_registered_in_known_workers():
    assert "ttp" in KNOWN_WORKERS


# ── E.2.12 deferred bus-integration assertions ─────────────────────


@pytest.mark.xfail(strict=True, reason="impl phase E.3 — fan-out invokes engine")
def test_e212_session_ended_invokes_rule_engine():
    raise AssertionError("not yet implemented")


@pytest.mark.xfail(strict=True, reason="impl phase E.3 — loop-prevention invariant")
def test_e212_idempotent_re_evaluation_publishes_zero_events():
    raise AssertionError("not yet implemented")
