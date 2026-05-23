# SPDX-License-Identifier: AGPL-3.0-or-later
"""E.2.11 — Multi-mapping property tests.

Pins the fan-out semantics from ``development/TTP_TAGGING.md``
§"One event maps to many techniques":

* A synthetic event matched by N rules each emitting M techniques
  produces exactly N×M tag rows. Property-tested via Hypothesis.
* Re-running the engine on the same event produces ZERO new rows
  (idempotent UUID; replay-safe).
* The single-rule worked example: one rule emitting two techniques
  produces two distinct tag UUIDs, pinned as a fixture.

UUID-distinctness assertions exercise :func:`compute_tag_uuid`
directly and are GREEN today. Engine-level fan-out assertions
(``RuleEngine.evaluate()``) currently return ``[]`` from the empty
contract body; those are ``xfail(strict=True)`` until E.3.7 lands.
"""
from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from decnet.web.db.models.ttp import compute_tag_uuid


# ── UUID-distinctness (GREEN today) ─────────────────────────────────


def test_one_rule_two_techniques_distinct_uuids() -> None:
    """Worked example: a rule emitting (T1110, None) and (T1078, None)
    on the same source event produces two distinct tag UUIDs.

    Pinned as a fixture so a future "optimization" that collapses
    technique fan-out into a single row would trip the test.
    """
    u1 = compute_tag_uuid(
        source_kind="attacker_command",
        source_id="evt-42",
        rule_id="R0001",
        rule_version=1,
        technique_id="T1110",
        sub_technique_id=None,
    )
    u2 = compute_tag_uuid(
        source_kind="attacker_command",
        source_id="evt-42",
        rule_id="R0001",
        rule_version=1,
        technique_id="T1078",
        sub_technique_id=None,
    )
    assert u1 != u2


def test_sub_technique_distinguishes_uuid() -> None:
    """``T1110`` and ``T1110.001`` (its sub-technique) hash to
    different UUIDs — confirms the sub_technique_id input
    contributes to the digest."""
    parent = compute_tag_uuid(
        source_kind="attacker_command",
        source_id="evt-42",
        rule_id="R0001",
        rule_version=1,
        technique_id="T1110",
        sub_technique_id=None,
    )
    child = compute_tag_uuid(
        source_kind="attacker_command",
        source_id="evt-42",
        rule_id="R0001",
        rule_version=1,
        technique_id="T1110",
        sub_technique_id="001",
    )
    assert parent != child


@given(
    rule_ids=st.lists(
        st.from_regex(r"R[0-9]{4}", fullmatch=True),
        min_size=1,
        max_size=5,
        unique=True,
    ),
    technique_ids=st.lists(
        st.from_regex(r"T[0-9]{4}", fullmatch=True),
        min_size=1,
        max_size=5,
        unique=True,
    ),
)
@settings(max_examples=50, deadline=None)
def test_n_rules_m_techniques_n_times_m_distinct_uuids(
    rule_ids: list[str], technique_ids: list[str],
) -> None:
    """Property: N rules × M techniques on one event → N×M distinct
    tag UUIDs. The cartesian product of ``(rule_id, technique_id)``
    is the identity tuple, so all pairs hash distinctly."""
    uuids = {
        compute_tag_uuid(
            source_kind="attacker_command",
            source_id="evt-1",
            rule_id=r,
            rule_version=1,
            technique_id=t,
            sub_technique_id=None,
        )
        for r in rule_ids
        for t in technique_ids
    }
    assert len(uuids) == len(rule_ids) * len(technique_ids)


@given(
    source_kind=st.from_regex(r"[a-z_]{3,20}", fullmatch=True),
    source_id=st.text(min_size=1, max_size=40),
    rule_id=st.from_regex(r"R[0-9]{4}", fullmatch=True),
    rule_version=st.integers(min_value=1, max_value=999),
    technique_id=st.from_regex(r"T[0-9]{4}", fullmatch=True),
)
@settings(max_examples=100, deadline=None)
def test_uuid_is_deterministic_replay_safe(
    source_kind: str,
    source_id: str,
    rule_id: str,
    rule_version: int,
    technique_id: str,
) -> None:
    """Property: re-running ``compute_tag_uuid`` on the same inputs
    yields the same UUID. This is the load-bearing replay-safety
    invariant — the worker re-processing the same event must
    converge to the same tag set without writing duplicates."""
    first = compute_tag_uuid(
        source_kind=source_kind,
        source_id=source_id,
        rule_id=rule_id,
        rule_version=rule_version,
        technique_id=technique_id,
        sub_technique_id=None,
    )
    second = compute_tag_uuid(
        source_kind=source_kind,
        source_id=source_id,
        rule_id=rule_id,
        rule_version=rule_version,
        technique_id=technique_id,
        sub_technique_id=None,
    )
    assert first == second


# ── Engine fan-out (xfail until E.3.7) ──────────────────────────────


def test_engine_emits_n_times_m_rows() -> None:
    """End-to-end: a synthetic event matched by 3 rules each emitting
    2 techniques produces 6 tag rows from ``RuleEngine.evaluate()``.
    """
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

    rules = [
        CompiledRule(
            rule_id=f"R000{i}",
            rule_version=1,
            name=f"r{i}",
            applies_to=frozenset({"command"}),
            match_spec={"pattern": "hydra"},
            emits=(
                (f"T{1000 + 2 * i}", None, "TA0006", 0.85),
                (f"T{1001 + 2 * i}", None, "TA0006", 0.80),
            ),
            evidence_fields=(),
            state=RuleState(),
        )
        for i in range(3)
    ]
    eng = RuleEngine(store=_Stub())
    eng._by_kind = {"command": rules}
    event = TaggerEvent(
        source_kind="command",
        source_id="src1",
        attacker_uuid="att1",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload={"command_text": "hydra -l root ssh://1.2.3.4"},
    )
    out = asyncio.run(eng.evaluate(event))
    assert len(out) == 6


def test_engine_replay_produces_no_new_rows() -> None:
    """Idempotency at the engine level: ``evaluate(e)`` followed by
    ``evaluate(e)`` again yields tag rows with identical UUIDs, so
    the downstream ``insert_tags`` no-ops the second batch.
    """
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
        source_kind="command",
        source_id="src1",
        attacker_uuid="att1",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload={"command_text": "hydra -l root ssh://1.2.3.4"},
    )
    out1 = asyncio.run(eng.evaluate(event))
    out2 = asyncio.run(eng.evaluate(event))
    assert {t.uuid for t in out1} == {t.uuid for t in out2}
