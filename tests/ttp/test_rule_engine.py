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
    """Minimal duck-typed RuleStore for contract-phase construction."""


def _make_compiled_rule(
    *,
    rule_id: str = "R0001",
    rule_version: int = 1,
    emits: tuple[tuple[str, str | None], ...] = (("T1110", None),),
) -> CompiledRule:
    return CompiledRule(
        rule_id=rule_id,
        rule_version=rule_version,
        name="test rule",
        applies_to=frozenset({"command"}),
        match_spec={"contains": "hydra"},
        emits=emits,
        evidence_fields=("matched_tokens",),
        state=object(),  # RuleState lands in E.1.11; opaque here
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
    )


def test_compiled_rule_is_immutable() -> None:
    # NamedTuple gives us field-level immutability — the atomic-swap
    # property (E.2.14b) requires that a rule in the dispatch index
    # cannot be mutated in place; replacement is the only legal edit.
    cr = CompiledRule(
        rule_id="R0001",
        rule_version=1,
        name="brute",
        applies_to=frozenset({"command"}),
        match_spec={},
        emits=(("T1110", None),),
        evidence_fields=("matched_tokens",),
        state=object(),
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


def test_evaluate_returns_empty_list_in_contract_phase() -> None:
    eng = RuleEngine(store=_StubStore()) 
    out = asyncio.run(eng.evaluate(_ev()))
    assert out == []


def test_watch_store_returns_none_and_does_not_raise() -> None:
    eng = RuleEngine(store=_StubStore()) 
    assert asyncio.run(eng.watch_store()) is None


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


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.5: RuleStore.load_compiled raises on malformed YAML",
)
def test_e25_malformed_yaml_fails_at_compile_not_evaluate() -> None:
    """Once the store contract lands (E.1.11) and impl ships (E.3.5),
    feeding the store a malformed YAML document must raise during
    :meth:`RuleStore.load_compiled` (the deploy-time hook) — never at
    :meth:`RuleEngine.evaluate` time. The trip-wire fires when impl
    surfaces ``RuleStore`` and stores accept malformed input.
    """
    from decnet.ttp.store.base import RuleStore  # noqa: F401
    raise AssertionError("E.3.5 will pin this once RuleStore lands")


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


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.5: evaluate() does not yet fan out emits",
)
def test_e25_one_rule_multiple_emits_produces_multiple_tags() -> None:
    """One matching rule with N entries in ``emits`` must produce N
    tag rows from a single event. The "one event maps to many
    techniques" property enforced at engine level."""
    eng = RuleEngine(store=_StubStore()) 
    rule = _make_compiled_rule(
        rule_id="R_MULTI",
        emits=(("T1110", None), ("T1078", None), ("T1059", "001")),
    )
    eng._by_kind = {"command": [rule]}
    out = asyncio.run(eng.evaluate(_ev()))
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


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.5: evaluate() does not yet emit tags",
)
def test_e25_rule_version_collision_via_engine_yields_distinct_tag_uuids() -> None:
    """Same property as above, but driven through the engine: two
    CompiledRule instances differing only in rule_version produce two
    rows whose ``uuid`` columns differ."""
    eng = RuleEngine(store=_StubStore()) 
    r1 = _make_compiled_rule(rule_id="R_VER", rule_version=1)
    r2 = _make_compiled_rule(rule_id="R_VER", rule_version=2)
    eng._by_kind = {"command": [r1, r2]}
    out = asyncio.run(eng.evaluate(_ev()))
    assert len(out) == 2
    uuids = {t.uuid for t in out}
    assert len(uuids) == 2
