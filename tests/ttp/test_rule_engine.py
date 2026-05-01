"""Contract tests for :mod:`decnet.ttp.impl.rule_engine` (E.1.5).

Scoped to the contract surface: shape of :class:`CompiledRule`,
constructor signature of :class:`RuleEngine`, the empty-list /
``None`` returns from :meth:`evaluate` / :meth:`watch_store`, and the
:class:`RuleSchema` field set. Behavioral assertions from E.2.5
(malformed-YAML compile failure, multi-emit fan-out, version-collision
distinct UUIDs) are present but xfail-strict pending E.3.
"""
from __future__ import annotations

import asyncio
import inspect

import pytest

from decnet.ttp.base import TaggerEvent
from decnet.ttp.impl.rule_engine import CompiledRule, RuleEngine, RuleSchema


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


def test_compiled_rule_is_namedtuple_with_documented_fields():
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


def test_compiled_rule_is_immutable():
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


def test_rule_engine_constructs_with_store():
    eng = RuleEngine(store=_StubStore())  # type: ignore[arg-type]
    # Dispatch index starts empty in the contract phase.
    assert eng._by_kind == {}


def test_rule_engine_init_signature_takes_store():
    sig = inspect.signature(RuleEngine.__init__)
    assert list(sig.parameters)[1] == "store"


def test_evaluate_returns_empty_list_in_contract_phase():
    eng = RuleEngine(store=_StubStore())  # type: ignore[arg-type]
    out = asyncio.run(eng.evaluate(_ev()))
    assert out == []


def test_watch_store_returns_none_and_does_not_raise():
    eng = RuleEngine(store=_StubStore())  # type: ignore[arg-type]
    assert asyncio.run(eng.watch_store()) is None


def test_rule_schema_has_documented_fields():
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


def test_rule_schema_validates_minimal_yaml_shape():
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


# ── E.2.5 deferred behavioral assertions ───────────────────────────


@pytest.mark.xfail(strict=True, reason="impl phase E.3 — malformed YAML")
def test_e25_malformed_yaml_fails_at_compile_not_evaluate():
    raise AssertionError("not yet implemented")


@pytest.mark.xfail(strict=True, reason="impl phase E.3 — multi-emit fan-out")
def test_e25_one_rule_multiple_emits_produces_multiple_tags():
    raise AssertionError("not yet implemented")


@pytest.mark.xfail(strict=True, reason="impl phase E.3 — rule_version collision")
def test_e25_rule_version_collision_yields_distinct_tag_uuids():
    raise AssertionError("not yet implemented")
