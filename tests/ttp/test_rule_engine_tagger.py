"""E.3.18c — RuleEngineTagger wires RuleEngine into the composite.

Pins the wiring fix from ``development/TTP_TAGGING.md`` §"Tagging
engines, layered §1": the canonical rule-based engine must dispatch
through the :class:`CompositeTagger` like any other lifter. The
adapter is intentionally thin — it is only here so the composite's
fan-out reaches :class:`RuleEngine` and so the worker's per-watchable
fan-out (E.3.18a) hydrates the engine's index alongside the lifters'.
"""
from __future__ import annotations

from typing import Any

import pytest

from decnet.ttp.base import Tagger, TaggerEvent, WatchableTagger
from decnet.ttp.factory import CompositeTagger, get_tagger
from decnet.ttp.impl.rule_engine import (
    CompiledRule,
    RuleEngineTagger,
    _is_engine_owned,
)

from tests.ttp._stub_store import StubRuleStore


def _rule(
    *,
    rule_id: str = "R9001",
    applies_to: frozenset[str] = frozenset({"command"}),
    match_spec: dict[str, Any] | None = None,
) -> CompiledRule:
    from decnet.ttp.store.base import RuleState  # noqa: PLC0415

    return CompiledRule(
        rule_id=rule_id,
        rule_version=1,
        name="test",
        applies_to=applies_to,
        match_spec=match_spec or {"pattern": "whoami"},
        emits=(("T1059", None, "TA0002", 0.9),),
        evidence_fields=("command_text",),
        state=RuleState(),
    )


def test_rule_engine_tagger_handles_generic_source_kinds() -> None:
    assert "command" in RuleEngineTagger.HANDLES
    assert "http_request" in RuleEngineTagger.HANDLES
    assert "auth_attempt" in RuleEngineTagger.HANDLES
    assert "payload" in RuleEngineTagger.HANDLES


def test_rule_engine_tagger_is_a_tagger() -> None:
    store = StubRuleStore()
    tagger = RuleEngineTagger(store)
    assert isinstance(tagger, Tagger)


def test_rule_engine_tagger_is_watchable() -> None:
    """Worker's `iter_watchables()` filters on this Protocol."""
    store = StubRuleStore()
    tagger = RuleEngineTagger(store)
    assert isinstance(tagger, WatchableTagger)


@pytest.mark.asyncio
async def test_tag_proxies_to_engine_evaluate() -> None:
    rule = _rule(match_spec={"field": "command_text", "pattern": r"\bwhoami\b"})
    store = StubRuleStore(compiled=[rule])
    tagger = RuleEngineTagger(store)
    # Hydrate the engine's index (uses the predicate; pure pattern
    # rule is engine-owned so it lands in the index).
    await tagger._engine._index.hydrate_from(store, predicate=_is_engine_owned)
    event = TaggerEvent(
        source_kind="command",
        source_id="cmd-1",
        attacker_uuid="att-1",
        identity_uuid=None,
        session_id="sess-1",
        decky_id=None,
        payload={"command_text": "whoami"},
    )
    tags = await tagger.tag(event)
    assert len(tags) == 1
    assert tags[0].technique_id == "T1059"
    assert tags[0].rule_id == "R9001"


@pytest.mark.asyncio
async def test_engine_predicate_excludes_lifter_owned_rules() -> None:
    """Lifter-owned rules don't pollute the engine's dispatch index."""
    engine_rule = _rule(rule_id="R9100", match_spec={"pattern": "x"})
    lifter_rule = _rule(
        rule_id="R9101",
        match_spec={"kind": "lifter:behavioral_beaconing"},
    )
    assert _is_engine_owned(engine_rule)
    assert not _is_engine_owned(lifter_rule)

    store = StubRuleStore(compiled=[engine_rule, lifter_rule])
    tagger = RuleEngineTagger(store)
    await tagger._engine._index.hydrate_from(store, predicate=_is_engine_owned)
    by_rule = tagger._engine._by_rule
    assert "R9100" in by_rule
    assert "R9101" not in by_rule


def test_get_tagger_includes_rule_engine_tagger_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The canonical engine must be one of the composite's lifters."""
    monkeypatch.setenv("DECNET_TTP_TAGGER_TYPE", "composite")
    composite = get_tagger()
    assert isinstance(composite, CompositeTagger)
    names = [lifter.name for lifter in composite._lifters]
    assert "rule_engine" in names
    # Prepended so generic pattern rules dispatch before per-source
    # lifters' cross-event logic.
    assert names[0] == "rule_engine"


@pytest.mark.asyncio
async def test_engine_auto_promotes_uid_user_src_pwd_into_evidence() -> None:
    """Shell-rule evidence should always carry uid/user/src/pwd.

    The rule's ``evidence_fields: [command_text]`` is unchanged; the
    engine adds the four shell-aux keys when ``source_kind="command"``
    so the inspector renders structured rows without forcing every
    rule author to repeat the same evidence_fields list.
    """
    rule = _rule(match_spec={"field": "command_text", "pattern": r"\bcat\b"})
    store = StubRuleStore(compiled=[rule])
    tagger = RuleEngineTagger(store)
    await tagger._engine._index.hydrate_from(store, predicate=_is_engine_owned)
    event = TaggerEvent(
        source_kind="command",
        source_id="cmd-1",
        attacker_uuid="att-1",
        identity_uuid=None,
        session_id="sess-1",
        decky_id="omega-decky",
        payload={
            "command_text": "cat /etc/shadow",
            "uid": "0",
            "user": "root",
            "src": "192.168.1.5",
            "pwd": "/root",
        },
    )
    tags = await tagger.tag(event)
    assert len(tags) == 1
    ev = tags[0].evidence
    assert ev["command_text"] == "cat /etc/shadow"
    assert ev["uid"] == "0"
    assert ev["user"] == "root"
    assert ev["src"] == "192.168.1.5"
    assert ev["pwd"] == "/root"


@pytest.mark.asyncio
async def test_engine_aux_fields_skip_missing_payload_keys() -> None:
    """Missing aux keys don't appear in evidence (no ``None`` values)."""
    rule = _rule(match_spec={"field": "command_text", "pattern": r"\bcat\b"})
    store = StubRuleStore(compiled=[rule])
    tagger = RuleEngineTagger(store)
    await tagger._engine._index.hydrate_from(store, predicate=_is_engine_owned)
    event = TaggerEvent(
        source_kind="command",
        source_id="cmd-1",
        attacker_uuid="att-1",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload={"command_text": "cat /etc/shadow"},
    )
    tags = await tagger.tag(event)
    ev = tags[0].evidence
    assert ev == {"command_text": "cat /etc/shadow"}


def test_rule_engine_tagger_is_in_iter_watchables() -> None:
    store = StubRuleStore()
    engine_tagger = RuleEngineTagger(store)
    composite = CompositeTagger(lifters=[engine_tagger])
    yielded = list(composite.iter_watchables())
    assert engine_tagger in yielded
