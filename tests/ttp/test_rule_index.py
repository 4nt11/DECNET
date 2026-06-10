# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for :class:`decnet.ttp.impl._rule_index.RuleIndex`.

The dispatch index was extracted from :class:`RuleEngine` so the four
per-source lifters (E.3.9–E.3.13) can reuse the install / evict /
state-restamp atomic-swap protocol. These tests pin the contract
independently of the engine — a future regression in the engine
shouldn't be the only signal that the shared helper broke.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from decnet.ttp.impl._rule_index import RuleIndex
from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleChange, RuleState


def _rule(
    rule_id: str = "R0001",
    *,
    rule_version: int = 1,
    applies_to: frozenset[str] = frozenset({"command"}),
    state: RuleState | None = None,
    emits: tuple[tuple[str, str | None, str, float], ...] = (
        ("T1110", None, "TA0006", 0.85),
    ),
) -> CompiledRule:
    return CompiledRule(
        rule_id=rule_id,
        rule_version=rule_version,
        name="test",
        applies_to=applies_to,
        match_spec={"pattern": "x"},
        emits=emits,
        evidence_fields=(),
        state=state if state is not None else RuleState(),
    )


def test_install_and_lookup() -> None:
    idx = RuleIndex()
    rule = _rule()
    idx.install(rule)
    assert idx.get("R0001") is rule
    assert idx.by_kind("command") == [rule]
    assert idx.by_kind("email") == []


def test_install_replaces_same_rule_id() -> None:
    idx = RuleIndex()
    idx.install(_rule(rule_version=1))
    idx.install(_rule(rule_version=2))
    bucket = idx.by_kind("command")
    assert len(bucket) == 1
    assert bucket[0].rule_version == 2


def test_install_deletion_sentinel_evicts() -> None:
    idx = RuleIndex()
    idx.install(_rule())
    sentinel = CompiledRule(
        rule_id="R0001",
        rule_version=1,
        name="",
        applies_to=frozenset(),
        match_spec={},
        emits=(),
        evidence_fields=(),
        state=RuleState(),
    )
    idx.install(sentinel)
    assert idx.get("R0001") is None
    assert idx.by_kind("command") == []


def test_evict_unknown_is_noop() -> None:
    idx = RuleIndex()
    idx.evict("R_NOPE")  # must not raise


def test_apply_change_definition_installs() -> None:
    idx = RuleIndex()
    rule = _rule()
    idx.apply_change(
        RuleChange(change_kind="definition", rule_id="R0001", new_value=rule),
        RuleState,
    )
    assert idx.get("R0001") is rule


def test_apply_change_state_restamps_atomically() -> None:
    idx = RuleIndex()
    idx.install(_rule())
    new_state = RuleState(state="clipped", confidence_max=0.5)
    idx.apply_change(
        RuleChange(change_kind="state", rule_id="R0001", new_value=new_state),
        RuleState,
    )
    restamped = idx.get("R0001")
    assert restamped is not None
    assert restamped.state == new_state
    bucket = idx.by_kind("command")
    assert len(bucket) == 1
    assert bucket[0].state.confidence_max == 0.5


def test_apply_state_change_for_unknown_rule_is_noop() -> None:
    idx = RuleIndex()
    idx.apply_change(
        RuleChange(
            change_kind="state",
            rule_id="R_GHOST",
            new_value=RuleState(state="disabled"),
        ),
        RuleState,
    )
    assert idx.get("R_GHOST") is None


# ── Hydrate / watch via stub store ──────────────────────────────────


class _StubStore:
    def __init__(
        self,
        compiled: list[CompiledRule] | None = None,
        changes: list[RuleChange] | None = None,
    ) -> None:
        self._compiled = compiled or []
        self._changes = changes or []

    async def load_compiled(self) -> list[CompiledRule]:
        return list(self._compiled)

    async def get_state(self, _rule_id: str) -> RuleState:
        return RuleState()

    async def set_state(self, *_a: Any, **_kw: Any) -> None:
        return None

    def subscribe_changes(self) -> AsyncIterator[RuleChange]:
        changes = list(self._changes)

        async def _gen() -> AsyncIterator[RuleChange]:
            for change in changes:
                yield change

        return _gen()


def test_hydrate_from_installs_all() -> None:
    idx = RuleIndex()
    a = _rule("R_A")
    b = _rule("R_B", applies_to=frozenset({"email"}))
    store = _StubStore(compiled=[a, b])
    asyncio.run(idx.hydrate_from(store))
    assert idx.get("R_A") is a
    assert idx.get("R_B") is b


def test_hydrate_predicate_filters() -> None:
    idx = RuleIndex()
    a = _rule("R_A")  # match.kind defaults to {"pattern": "x"}
    b = _rule("R_B")
    store = _StubStore(compiled=[a, b])
    asyncio.run(
        idx.hydrate_from(store, predicate=lambda r: r.rule_id == "R_A")
    )
    assert idx.get("R_A") is a
    assert idx.get("R_B") is None


def test_watch_drains_definition_changes() -> None:
    idx = RuleIndex()
    a = _rule("R_A")
    b = _rule("R_B", applies_to=frozenset({"email"}))
    store = _StubStore(
        compiled=[],
        changes=[
            RuleChange(change_kind="definition", rule_id="R_A", new_value=a),
            RuleChange(change_kind="definition", rule_id="R_B", new_value=b),
        ],
    )
    asyncio.run(idx.watch(store))
    assert idx.get("R_A") is a
    assert idx.get("R_B") is b


def test_watch_predicate_evicts_unowned_definition_changes() -> None:
    """A rule whose YAML moves out of our predicate's claim set must be
    evicted from the index, not silently retained.
    """
    idx = RuleIndex()
    owned = _rule("R_A")
    unowned = _rule("R_B")
    idx.install(owned)
    idx.install(unowned)

    # Predicate now only owns R_A; R_B's incoming definition update
    # should evict it.
    new_b = _rule("R_B", rule_version=2)
    store = _StubStore(
        compiled=[],
        changes=[
            RuleChange(
                change_kind="definition", rule_id="R_B", new_value=new_b,
            ),
        ],
    )
    asyncio.run(idx.watch(store, predicate=lambda r: r.rule_id == "R_A"))
    assert idx.get("R_A") is owned
    assert idx.get("R_B") is None


def test_watch_state_change_for_owned_rule_applies() -> None:
    idx = RuleIndex()
    idx.install(_rule("R_A"))
    new_state = RuleState(state="disabled")
    store = _StubStore(
        compiled=[],
        changes=[
            RuleChange(
                change_kind="state", rule_id="R_A", new_value=new_state,
            ),
        ],
    )
    asyncio.run(idx.watch(store, predicate=lambda r: r.rule_id == "R_A"))
    restamped = idx.get("R_A")
    assert restamped is not None
    assert restamped.state.state == "disabled"


def test_watch_state_change_for_unowned_rule_skipped() -> None:
    idx = RuleIndex()
    # R_B was never installed (predicate excluded it). State change
    # for R_B must NOT install a phantom entry.
    store = _StubStore(
        compiled=[],
        changes=[
            RuleChange(
                change_kind="state",
                rule_id="R_B",
                new_value=RuleState(state="disabled"),
            ),
        ],
    )
    asyncio.run(idx.watch(store, predicate=lambda r: r.rule_id == "R_A"))
    assert idx.get("R_B") is None


def test_apply_change_continues_on_error(caplog: pytest.LogCaptureFixture) -> None:
    """A single bad change must not stall the watch loop."""
    idx = RuleIndex()
    # Force an exception by passing the wrong value type for definition.
    bad = RuleChange(
        change_kind="definition",
        rule_id="R_BAD",
        new_value=RuleState(),  # wrong type — apply_change ignores silently
    )
    good = _rule("R_GOOD")
    store = _StubStore(
        compiled=[],
        changes=[
            bad,
            RuleChange(
                change_kind="definition", rule_id="R_GOOD", new_value=good,
            ),
        ],
    )
    asyncio.run(idx.watch(store))
    assert idx.get("R_GOOD") is good
    assert idx.get("R_BAD") is None


def test_install_evicts_stale_kinds_on_reinstall() -> None:
    """BUG-4 regression: re-installing a rule with a narrower applies_to must
    remove the rule from kinds it no longer claims.

    Before the fix, install() only added the rule to new kind-buckets;
    it never cleaned up the old buckets. A rule installed for {A, B} then
    re-installed for {A} would remain in B's bucket indefinitely.
    """
    idx = RuleIndex()
    # First install: rule covers both "command" and "email" kinds.
    r1 = _rule("R_AB", applies_to=frozenset({"command", "email"}))
    idx.install(r1)
    assert idx.get("R_AB") is r1
    assert any(r.rule_id == "R_AB" for r in idx.by_kind("command"))
    assert any(r.rule_id == "R_AB" for r in idx.by_kind("email"))

    # Re-install with a narrower set: only "command" now.
    r2 = _rule("R_AB", rule_version=2, applies_to=frozenset({"command"}))
    idx.install(r2)

    assert idx.get("R_AB") is r2
    # Rule must still be in "command".
    assert any(r.rule_id == "R_AB" for r in idx.by_kind("command"))
    # BUG-4: rule must NO LONGER be in "email" — the stale entry must be evicted.
    assert not any(r.rule_id == "R_AB" for r in idx.by_kind("email")), (
        "Stale kind bucket 'email' still contains R_AB after re-install with "
        "applies_to={command}; eviction on reinstall is broken"
    )


def test_install_eviction_does_not_affect_other_rules_in_same_kind() -> None:
    """Evicting stale kinds for one rule must leave other rules in those kinds intact."""
    idx = RuleIndex()
    r_ab = _rule("R_AB", applies_to=frozenset({"command", "email"}))
    r_email = _rule("R_EMAIL_ONLY", applies_to=frozenset({"email"}))
    idx.install(r_ab)
    idx.install(r_email)

    # Re-install R_AB without "email".
    r_ab_v2 = _rule("R_AB", rule_version=2, applies_to=frozenset({"command"}))
    idx.install(r_ab_v2)

    # R_EMAIL_ONLY must still be in "email".
    assert any(r.rule_id == "R_EMAIL_ONLY" for r in idx.by_kind("email"))
    # R_AB must be gone from "email".
    assert not any(r.rule_id == "R_AB" for r in idx.by_kind("email"))


def test_expired_state_treated_as_disabled_by_is_active() -> None:
    """Sanity check on the helper used by both engine and lifters."""
    from decnet.ttp.impl._state import is_active

    expired = RuleState(
        state="enabled",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    assert is_active(expired) is False
    fresh = RuleState(
        state="enabled",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    assert is_active(fresh) is True


def test_apply_ceiling_only_clamps_clipped() -> None:
    from decnet.ttp.impl._state import apply_ceiling

    enabled = RuleState(state="enabled", confidence_max=0.5)
    assert apply_ceiling(0.9, enabled) == 0.9  # ceiling ignored unless clipped
    clipped = RuleState(state="clipped", confidence_max=0.5)
    assert apply_ceiling(0.9, clipped) == pytest.approx(0.45)
    clipped_no_max = RuleState(state="clipped", confidence_max=None)
    assert apply_ceiling(0.9, clipped_no_max) == 0.9
