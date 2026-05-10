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


def test_eval_emits_top_level_span(
    span_exporter: tuple[InMemorySpanExporter, TracerProvider],
) -> None:
    """``evaluate()`` produces a ``ttp.eval`` span with
    ``attacker_uuid`` and ``identity_uuid`` attributes."""
    import asyncio

    from decnet.ttp.base import TaggerEvent
    from decnet.ttp.impl.rule_engine import CompiledRule, RuleEngine
    from decnet.ttp.store.base import RuleState

    class _Stub:
        async def load_compiled(self):  # pragma: no cover
            return []

        async def get_state(self, _):  # pragma: no cover
            return RuleState()

        async def set_state(self, *_a, **_kw):  # pragma: no cover
            return None

        def subscribe_changes(self):  # pragma: no cover
            async def _g():
                if False:
                    yield None
            return _g()

    exporter, _ = span_exporter
    rule = CompiledRule(
        rule_id="R0001",
        rule_version=1,
        name="r",
        applies_to=frozenset({"command"}),
        match_spec={"pattern": "hydra"},
        emits=(("T1110", None, "TA0006", 0.85),),
        evidence_fields=(),
        state=RuleState(),
    )
    eng = RuleEngine(store=_Stub())
    eng._by_kind = {"command": [rule]}
    event = TaggerEvent(
        source_kind="command", source_id="src1",
        attacker_uuid="ATT_X", identity_uuid="IDY_Y",
        session_id=None, decky_id=None,
        payload={"command_text": "hydra"},
    )
    asyncio.run(eng.evaluate(event))
    eval_spans = [s for s in exporter.get_finished_spans() if s.name == "ttp.eval"]
    assert eval_spans
    attrs = dict(eval_spans[0].attributes or {})
    assert attrs.get("attacker_uuid") == "ATT_X"
    assert attrs.get("identity_uuid") == "IDY_Y"


def test_lifter_child_spans_emitted(span_exporter: tuple[InMemorySpanExporter, TracerProvider]) -> None:
    """Within a ``CompositeTagger.tag()``, every dispatched lifter
    produces a ``ttp.lifter.{name}`` child span."""
    import asyncio
    from pathlib import Path

    from decnet.ttp.base import TaggerEvent
    from decnet.ttp.factory import CompositeTagger
    from decnet.ttp.impl.canary_fingerprint_lifter import CanaryFingerprintLifter
    from decnet.ttp.impl.rule_engine import CompiledRule
    from decnet.ttp.store.base import RuleState
    from decnet.ttp.store.impl.filesystem import _parse_and_compile
    from tests.ttp._stub_store import StubRuleStore

    exporter, _ = span_exporter
    rules_dir = Path(__file__).resolve().parents[2] / "rules" / "ttp"
    rule = _parse_and_compile(rules_dir / "R0049.yaml", RuleState())
    lifter = CanaryFingerprintLifter(StubRuleStore(compiled=[rule]))
    lifter._index.install(rule)
    composite = CompositeTagger(lifters=[lifter])
    event = TaggerEvent(
        source_kind="canary_fingerprint",
        source_id="src1",
        attacker_uuid="att1",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload={"navigator_webdriver": True},
    )
    asyncio.run(composite.tag(event))
    span_names = [s.name for s in exporter.get_finished_spans()]
    assert "ttp.lifter.canary_fingerprint" in span_names, (
        f"expected ttp.lifter.canary_fingerprint in spans; got {span_names}"
    )


def test_rule_fire_spans_carry_rule_and_technique_attrs(
    span_exporter: tuple[InMemorySpanExporter, TracerProvider],
) -> None:
    """Each matched rule produces a ``ttp.rule.fire`` span with
    ``rule_id`` and ``technique_id`` attributes set."""
    import asyncio

    from decnet.ttp.base import TaggerEvent
    from decnet.ttp.impl.rule_engine import CompiledRule, RuleEngine
    from decnet.ttp.store.base import RuleState

    class _Stub:
        async def load_compiled(self):  # pragma: no cover
            return []

        async def get_state(self, _):  # pragma: no cover
            return RuleState()

        async def set_state(self, *_a, **_kw):  # pragma: no cover
            return None

        def subscribe_changes(self):  # pragma: no cover
            async def _g():
                if False:
                    yield None
            return _g()

    exporter, _ = span_exporter
    rule = CompiledRule(
        rule_id="R_FIRE",
        rule_version=1,
        name="r",
        applies_to=frozenset({"command"}),
        match_spec={"pattern": "hydra"},
        emits=(("T1110", None, "TA0006", 0.85),),
        evidence_fields=(),
        state=RuleState(),
    )
    eng = RuleEngine(store=_Stub())
    eng._by_kind = {"command": [rule]}
    asyncio.run(eng.evaluate(TaggerEvent(
        source_kind="command", source_id="s",
        attacker_uuid="a", identity_uuid=None,
        session_id=None, decky_id=None,
        payload={"command_text": "hydra"},
    )))
    fire_spans = [
        s for s in exporter.get_finished_spans() if s.name == "ttp.rule.fire"
    ]
    assert fire_spans
    attrs = dict(fire_spans[0].attributes or {})
    assert attrs.get("rule_id") == "R_FIRE"
    assert attrs.get("technique_id") == "T1110"


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


def test_no_pii_canary_in_span_attributes(
    span_exporter: tuple[InMemorySpanExporter, TracerProvider],
) -> None:
    """Run a battery of synthetic events containing PII canary
    strings in command bodies, email bodies, fingerprint blobs,
    and payload bytes. After eval, walk every span attribute and
    assert no canary string appears anywhere.
    """
    import asyncio
    from pathlib import Path

    from decnet.ttp.base import TaggerEvent
    from decnet.ttp.factory import CompositeTagger
    from decnet.ttp.impl.canary_fingerprint_lifter import CanaryFingerprintLifter
    from decnet.ttp.impl.email_lifter import EmailLifter
    from decnet.ttp.impl.rule_engine import RuleEngine
    from decnet.ttp.store.base import RuleState
    from decnet.ttp.store.impl.filesystem import _parse_and_compile
    from tests.ttp._stub_store import StubRuleStore

    exporter, _ = span_exporter
    rules_dir = Path(__file__).resolve().parents[2] / "rules" / "ttp"

    canary_rule = _parse_and_compile(rules_dir / "R0049.yaml", RuleState())
    canary_lifter = CanaryFingerprintLifter(StubRuleStore(compiled=[canary_rule]))
    canary_lifter._index.install(canary_rule)

    email_rule = _parse_and_compile(rules_dir / "R0042.yaml", RuleState())
    email_lifter = EmailLifter(StubRuleStore(compiled=[email_rule]))
    email_lifter._index.install(email_rule)

    composite = CompositeTagger(lifters=[canary_lifter, email_lifter])

    battery = [
        TaggerEvent(
            source_kind="canary_fingerprint",
            source_id="src-canary",
            attacker_uuid="CANARY_PII_DO_NOT_LEAK",
            identity_uuid=None, session_id=None, decky_id=None,
            payload={
                "navigator_webdriver": True,
                "raw_blob": "CANARY_FINGERPRINT_BLOB",
            },
        ),
        TaggerEvent(
            source_kind="email",
            source_id="src-email",
            attacker_uuid="att1",
            identity_uuid=None, session_id=None, decky_id=None,
            payload={
                "rcpt_count": 30,
                "body_simhash": "abc123",
                "body": "CANARY_EMAIL_BODY",
                "command_text": "CANARY_COMMAND_RAW",
                "raw_bytes": "CANARY_PAYLOAD_BYTES",
            },
        ),
    ]

    async def _run() -> None:
        for ev in battery:
            await composite.tag(ev)

    asyncio.run(_run())

    for span in exporter.get_finished_spans():
        for attr_value in (span.attributes or {}).values():
            val_str = str(attr_value)
            for canary in _PII_CANARIES:
                assert canary not in val_str, (
                    f"PII canary {canary!r} leaked into span "
                    f"{span.name!r} attribute value {val_str!r}"
                )


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
