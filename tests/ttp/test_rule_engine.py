"""Contract tests for :mod:`decnet.ttp.impl.rule_engine` (E.1.5 + E.2.5).

E.1.5 contract surface: shape of :class:`CompiledRule`, constructor
signature of :class:`RuleEngine`, the empty-list / ``None`` returns
from :meth:`evaluate` / :meth:`watch_store`, and the
:class:`RuleSchema` field set.

E.2.5 behavioral assertions (this commit): empty store still
evaluates, unknown source_kind returns ``[]``, malformed YAML raises
at compile time (the deploy-time / runtime asymmetry), one rule
with multiple ``emits`` fans out into N tags, and two rules with
distinct ``rule_version`` emitting the same technique on the same
event produce two distinct tag UUIDs (the worked-example invariant).

Behaviors that still require :class:`RuleEngine.evaluate` to grow a
real body live behind ``@pytest.mark.xfail(strict=True)`` so the
suite stays GREEN today and trips when impl lands.
"""
from __future__ import annotations

import asyncio
import inspect
import sys
from typing import Any

import pytest
from pydantic import ValidationError

from decnet.ttp.base import TaggerEvent
from decnet.ttp.impl.rule_engine import CompiledRule, RuleEngine, RuleSchema
from decnet.web.db.models.ttp import compute_tag_uuid


def _ev() -> TaggerEvent:
    return TaggerEvent(
        source_kind="command",
        source_id="src1",
        attacker_uuid="att1",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload={},
    )


class _StubStore:
    """Minimal duck-typed RuleStore for engine construction in tests.

    Provides the subset of the ABC the engine touches at construction
    time. Tests that drive ``evaluate()`` populate ``eng._by_kind``
    directly rather than going through ``watch_store()``; the
    ``load_compiled`` / ``subscribe_changes`` stubs are only here so a
    test that DOES want to drive the watch loop can opt in.
    """

    async def load_compiled(self) -> list[CompiledRule]:  # pragma: no cover
        return []

    async def get_state(self, _rule_id: str):  # pragma: no cover
        from decnet.ttp.store.base import RuleState
        return RuleState()

    async def set_state(self, *_a: Any, **_kw: Any) -> None:  # pragma: no cover
        return None

    def subscribe_changes(self):  # pragma: no cover
        async def _gen():
            if False:
                yield None
        return _gen()


def _make_compiled_rule(
    *,
    rule_id: str = "R0001",
    rule_version: int = 1,
    emits: tuple[tuple[str, str | None, str, float], ...] = (
        ("T1110", None, "TA0006", 0.85),
    ),
    match_spec: dict[str, Any] | None = None,
) -> CompiledRule:
    from decnet.ttp.store.base import RuleState  # noqa: PLC0415

    return CompiledRule(
        rule_id=rule_id,
        rule_version=rule_version,
        name="test rule",
        applies_to=frozenset({"command"}),
        match_spec=match_spec or {"pattern": "hydra"},
        emits=emits,
        evidence_fields=("matched_tokens",),
        state=RuleState(),
    )


def test_compiled_rule_is_namedtuple_with_documented_fields() -> None:
    assert issubclass(CompiledRule, tuple)
    fields = CompiledRule._fields
    assert fields == (
        "rule_id",
        "rule_version",
        "name",
        "applies_to",
        "match_spec",
        "emits",
        "evidence_fields",
        "state",
        "description",
    )


def test_compiled_rule_is_immutable() -> None:
    # NamedTuple gives us field-level immutability — the atomic-swap
    # property (E.2.14b) requires that a rule in the dispatch index
    # cannot be mutated in place; replacement is the only legal edit.
    from decnet.ttp.store.base import RuleState  # noqa: PLC0415

    cr = CompiledRule(
        rule_id="R0001",
        rule_version=1,
        name="brute",
        applies_to=frozenset({"command"}),
        match_spec={},
        emits=(("T1110", None, "TA0006", 0.85),),
        evidence_fields=("matched_tokens",),
        state=RuleState(),
    )
    with pytest.raises(AttributeError):
        cr.rule_id = "R9999"  # type: ignore[misc]


def test_rule_engine_constructs_with_store() -> None:
    eng = RuleEngine(store=_StubStore()) 
    # Dispatch index starts empty in the contract phase.
    assert eng._by_kind == {}


def test_rule_engine_init_signature_takes_store() -> None:
    sig = inspect.signature(RuleEngine.__init__)
    assert list(sig.parameters)[1] == "store"


def test_evaluate_returns_empty_list_for_unknown_source_kind() -> None:
    eng = RuleEngine(store=_StubStore())
    out = asyncio.run(eng.evaluate(_ev()))
    assert out == []


def test_watch_store_drains_and_can_be_cancelled() -> None:
    """``watch_store()`` blocks on ``subscribe_changes`` after loading
    the empty corpus. Test that it can be cancelled cleanly — the
    worker bootstrap (E.3.14) cancels it during shutdown."""
    eng = RuleEngine(store=_StubStore())

    async def _drive() -> None:
        task = asyncio.create_task(eng.watch_store())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_drive())


def test_rule_schema_has_documented_fields() -> None:
    fields = RuleSchema.model_fields
    must_have = {
        "rule_id",
        "rule_version",
        "name",
        "applies_to",
        "match",
        "emits",
        "evidence_fields",
    }
    assert must_have <= set(fields)


def test_rule_schema_validates_minimal_yaml_shape() -> None:
    rs = RuleSchema.model_validate({
        "rule_id": "R0001",
        "rule_version": 1,
        "name": "brute force ssh",
        "applies_to": ["command"],
        "match": {"contains": "hydra"},
        "emits": [{"technique_id": "T1110"}],
    })
    assert rs.rule_id == "R0001"
    assert rs.evidence_fields == []  # default


# ── E.2.5 behavioral assertions ────────────────────────────────────


def test_e25_empty_store_evaluates_to_empty_list() -> None:
    """The worker must be able to start with no rules — evaluate() on
    an engine whose dispatch index is empty must return [], never
    raise. GREEN today (the contract phase already returns [])."""
    eng = RuleEngine(store=_StubStore()) 
    assert asyncio.run(eng.evaluate(_ev())) == []


def test_e25_malformed_yaml_fails_at_schema_validation() -> None:
    """The deploy-time / runtime asymmetry: a malformed rule must
    surface as a Pydantic ValidationError when the store calls
    :meth:`RuleSchema.model_validate`, NOT silently as runtime
    misbehavior. GREEN today via Pydantic's own validation."""
    bad: dict[str, Any] = {
        # missing required ``applies_to`` and ``match`` and ``emits``
        "rule_id": "R0001",
        "rule_version": 1,
        "name": "broken",
    }
    with pytest.raises(ValidationError):
        RuleSchema.model_validate(bad)


def test_e25_malformed_yaml_fails_at_compile_not_evaluate(tmp_path: Any) -> None:
    """Feeding the store a malformed YAML document raises during
    :meth:`RuleStore.load_compiled` — the deploy-time hook — never at
    :meth:`RuleEngine.evaluate` time. Pinned at E.3.5 once the
    filesystem store implementation lands."""
    if sys.platform != "linux":  # pragma: no cover
        pytest.skip("FilesystemRuleStore is Linux-only (inotify dep)")
    from decnet.ttp.store.impl.filesystem import FilesystemRuleStore

    bad = tmp_path / "R0001.yaml"
    bad.write_text(
        "rule_id: R0001\nrule_version: 1\nname: broken\n",
        encoding="utf-8",
    )
    store = FilesystemRuleStore(rules_dir=tmp_path)
    with pytest.raises((ValidationError, ValueError)):
        asyncio.run(store.load_compiled())


def test_e25_evaluate_unknown_source_kind_returns_empty() -> None:
    """A source_kind that no compiled rule claims must produce []
    silently. GREEN today (dispatch index is empty)."""
    eng = RuleEngine(store=_StubStore()) 
    weird = TaggerEvent(
        source_kind="never_seen_before_kind",
        source_id="src1",
        attacker_uuid="att1",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload={},
    )
    assert asyncio.run(eng.evaluate(weird)) == []


def test_e25_one_rule_multiple_emits_produces_multiple_tags() -> None:
    """One matching rule with N entries in ``emits`` must produce N
    tag rows from a single event. The "one event maps to many
    techniques" property enforced at engine level."""
    eng = RuleEngine(store=_StubStore())
    rule = _make_compiled_rule(
        rule_id="R_MULTI",
        emits=(
            ("T1110", None, "TA0006", 0.85),
            ("T1078", None, "TA0001", 0.80),
            ("T1059", "001", "TA0002", 0.90),
        ),
    )
    eng._by_kind = {"command": [rule]}
    event = _ev()._replace(payload={"command_text": "hydra -l root ssh://1.2.3.4"})
    out = asyncio.run(eng.evaluate(event))
    assert len(out) == 3
    techs = {(t.technique_id, t.sub_technique_id) for t in out}
    assert techs == {("T1110", None), ("T1078", None), ("T1059", "001")}


def test_e25_rule_version_collision_yields_distinct_tag_uuids() -> None:
    """Two rules emitting the same (technique_id, sub_technique_id)
    on the same source event must produce two distinct tag UUIDs
    when their ``rule_version`` differs. The replay-safety hash from
    E.2.2 already enforces this property at the function layer; this
    test pins the worked example from the schema section."""
    u_v1 = compute_tag_uuid(
        source_kind="command",
        source_id="src1",
        rule_id="R_VER",
        rule_version=1,
        technique_id="T1110",
        sub_technique_id=None,
    )
    u_v2 = compute_tag_uuid(
        source_kind="command",
        source_id="src1",
        rule_id="R_VER",
        rule_version=2,
        technique_id="T1110",
        sub_technique_id=None,
    )
    assert u_v1 != u_v2


def test_e25_rule_version_collision_via_engine_yields_distinct_tag_uuids() -> None:
    """Same property as above, but driven through the engine: two
    CompiledRule instances differing only in rule_version produce two
    rows whose ``uuid`` columns differ."""
    eng = RuleEngine(store=_StubStore())
    r1 = _make_compiled_rule(rule_id="R_VER", rule_version=1)
    r2 = _make_compiled_rule(rule_id="R_VER", rule_version=2)
    eng._by_kind = {"command": [r1, r2]}
    event = _ev()._replace(payload={"command_text": "hydra -l root ssh://1.2.3.4"})
    out = asyncio.run(eng.evaluate(event))
    assert len(out) == 2
    uuids = {t.uuid for t in out}
    assert len(uuids) == 2
