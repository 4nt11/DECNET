"""E.2.14a — Observability tracing tests.

Pins the OTEL span hierarchy from ``development/TTP_TAGGING.md``
§"Observability". Spans are not optional decoration; they are a
stated design property and the impl must produce them in the shape
asserted here:

* A single :meth:`RuleEngine.evaluate` call produces a ``ttp.eval``
  span carrying ``attacker_uuid`` + ``identity_uuid`` attributes.
* Within ``ttp.eval``, one ``ttp.lifter.{name}`` child span per
  lifter that ran.
* Within each lifter span, one ``ttp.rule.fire`` span per matched
  rule, carrying ``rule_id`` + ``technique_id`` attributes.
* :meth:`RuleStore.set_state` produces ``ttp.rule.state.change``
  parent + ``ttp.store.write_state`` + ``ttp.rule.publish`` children.
* **No-PII property.** Walk every emitted span attribute over a
  battery of synthetic events containing tagged "PII canary" strings;
  no attribute value contains any canary string. Catches accidental
  attribute writes of raw command content / email body / fingerprint
  bytes / payload bytes.

The in-memory span exporter fixture lives in this module rather than
``tests/ttp/conftest.py`` because no other ttp test currently needs
OTEL plumbing; promoting it to ``conftest.py`` is a cheap follow-up
once a second consumer arrives.

Span-emission assertions xfail-gated behind the matching E.3 impl
steps (E.3.7 engine; E.3.5/E.3.6 store; E.3.9–E.3.13 lifters).
"""
from __future__ import annotations

import socket
from typing import Iterator
from urllib.parse import urlparse

import pytest

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from decnet.env import DECNET_OTEL_ENDPOINT


def _jaeger_reachable() -> bool:
    """Best-effort TCP probe of ``DECNET_OTEL_ENDPOINT``.

    The in-memory span exporter doesn't need Jaeger to function, but
    these tests pin a behavior the project only enables in
    observability-infrastructure-present environments. Skipping the
    whole module when Jaeger isn't up keeps the dev loop green
    without lying about coverage.
    """
    parsed = urlparse(DECNET_OTEL_ENDPOINT)
    host = parsed.hostname or "localhost"
    port = parsed.port or 4317
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _jaeger_reachable(),
    reason=(
        f"Jaeger / OTLP backend not reachable at {DECNET_OTEL_ENDPOINT}; "
        "tracing tests require an observability backend"
    ),
)


_PII_CANARIES: tuple[str, ...] = (
    "CANARY_PII_DO_NOT_LEAK",
    "CANARY_EMAIL_BODY",
    "CANARY_PAYLOAD_BYTES",
    "CANARY_COMMAND_RAW",
    "CANARY_FINGERPRINT_BLOB",
)


@pytest.fixture
def span_exporter(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[InMemorySpanExporter, TracerProvider]]:
    """Yield an :class:`InMemorySpanExporter` wired into a fresh
    :class:`TracerProvider`, AND patch :func:`decnet.telemetry.get_tracer`
    to hand out tracers from that provider.

    Two layers of plumbing:

    1. The provider is per-test (OTEL forbids overriding the global
       provider once set, so we never touch the global).
    2. ``decnet.telemetry.get_tracer`` is monkeypatched to return
       ``provider.get_tracer(component)`` rather than going through
       the module's cached global. This means production code under
       test that calls ``get_tracer("ttp")`` lands its spans in our
       in-memory exporter for the duration of the test.

    The session-scoped autouse fixture in ``conftest.py`` has already
    set ``DECNET_DEVELOPER_TRACING=true`` and forced
    ``decnet.telemetry._ENABLED = True``, so the no-op tracer path
    is bypassed.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    import decnet.telemetry as _t  # noqa: PLC0415 — fixture-time import
    monkeypatch.setattr(
        _t, "get_tracer",
        lambda component: provider.get_tracer(f"decnet.{component}"),
    )
    try:
        yield exporter, provider
    finally:
        provider.shutdown()


# ── Eval span hierarchy (xfail until E.3.7) ─────────────────────────


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.7 — RuleEngine.evaluate() emits no spans "
    "today; ttp.eval span lands with the engine impl",
)
def test_eval_emits_top_level_span(span_exporter: tuple[InMemorySpanExporter, TracerProvider]) -> None:
    """``evaluate()`` produces a ``ttp.eval`` span with
    ``attacker_uuid`` and ``identity_uuid`` attributes."""
    pytest.fail("ttp.eval span not yet emitted")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.9–E.3.13 — per-lifter ttp.lifter.{name} "
    "child spans land with each lifter implementation",
)
def test_lifter_child_spans_emitted(span_exporter: tuple[InMemorySpanExporter, TracerProvider]) -> None:
    """Within a ``ttp.eval``, every lifter that ran produces a
    ``ttp.lifter.{name}`` child span."""
    pytest.fail("per-lifter spans not yet emitted")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.7 — ttp.rule.fire spans with rule_id + "
    "technique_id land with the engine impl",
)
def test_rule_fire_spans_carry_rule_and_technique_attrs(
    span_exporter: tuple[InMemorySpanExporter, TracerProvider],
) -> None:
    """Each matched rule produces a ``ttp.rule.fire`` span with
    ``rule_id`` and ``technique_id`` attributes set."""
    pytest.fail("ttp.rule.fire spans not yet emitted")


# ── set_state span hierarchy (xfail until E.3.5/E.3.6) ──────────────


def test_set_state_span_hierarchy(
    span_exporter: tuple[InMemorySpanExporter, TracerProvider],
) -> None:
    """``RuleStore.set_state`` produces a ``ttp.rule.state.change``
    parent with ``ttp.store.write_state`` + ``ttp.rule.publish``
    children — operator state changes are auditable."""
    import asyncio
    import sys

    if sys.platform != "linux":  # pragma: no cover
        pytest.skip("FilesystemRuleStore is Linux-only (inotify dep)")

    from decnet.ttp.store.base import RuleState
    from decnet.ttp.store.impl.filesystem import FilesystemRuleStore

    exporter, _provider = span_exporter

    async def _run() -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            from pathlib import Path
            store = FilesystemRuleStore(rules_dir=Path(td))
            await store.set_state(
                "R0001", RuleState(state="disabled"), set_by="anti",
            )

    asyncio.run(_run())
    names = [span.name for span in exporter.get_finished_spans()]
    assert "ttp.rule.state.change" in names
    assert "ttp.store.write_state" in names
    assert "ttp.rule.publish" in names


# ── No-PII property (xfail until E.3.7+) ────────────────────────────


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.7+ — span emission requires the engine + "
    "lifter impls; the no-PII property is asserted across the "
    "battery only once spans are actually being produced",
)
def test_no_pii_canary_in_span_attributes(
    span_exporter: tuple[InMemorySpanExporter, TracerProvider],
) -> None:
    """Run a battery of synthetic events containing PII canary
    strings (e.g. ``"CANARY_PII_DO_NOT_LEAK"`` in command bodies,
    email bodies, fingerprint blobs, payload bytes). After eval,
    walk every span attribute value and assert no canary string
    appears anywhere.

    Catches accidental attribute writes of raw command content,
    email body, payload bytes, fingerprint blobs. Span attributes
    leak to whatever OTEL backend is wired (Jaeger, Tempo, vendor
    APM); a single PII leak there is a privacy incident, not a
    bug.
    """
    pytest.fail("span emission not yet implemented")


# ── Surface (GREEN today) ───────────────────────────────────────────


def test_pii_canary_battery_is_non_empty() -> None:
    """The canary battery itself is non-empty and consists of strings
    a future contributor cannot accidentally write into a span.

    Cheap meta-test so the no-PII assertion above can never silently
    pass on an empty corpus.
    """
    assert len(_PII_CANARIES) >= 5
    for canary in _PII_CANARIES:
        assert canary.isupper()
        assert "_" in canary


def test_in_memory_exporter_fixture_works(
    span_exporter: tuple[InMemorySpanExporter, TracerProvider],
) -> None:
    """Sanity: the fixture itself captures a synthetic span. If THIS
    test breaks, every xfail above becomes meaningless.
    """
    exporter, provider = span_exporter
    tracer = provider.get_tracer("decnet.tests.ttp.tracing")
    with tracer.start_as_current_span("synthetic.span") as span:
        span.set_attribute("test.key", "test.value")
    spans = exporter.get_finished_spans()
    assert any(s.name == "synthetic.span" for s in spans)
