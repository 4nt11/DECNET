"""E.2.14b — Cross-backend conformance for :class:`RuleStore`.

Both :class:`FilesystemRuleStore` and :class:`DatabaseRuleStore` must
satisfy the same observable contract. The :func:`rule_store` fixture
in :mod:`conftest` parametrizes every assertion in this module over
both backends.

Per ``development/TTP_TAGGING.md`` §E.2.14b:

* :meth:`load_compiled` over a known YAML corpus returns the same
  ``CompiledRule`` set from both backends (modulo state defaulting
  to enabled when no state row exists).
* :meth:`get_state` for an unknown ``rule_id`` returns the default
  ``RuleState(state="enabled", ...)`` — never raise, never return
  ``None``.
* :meth:`set_state` on one ``rule_id`` does not affect any other.
* :meth:`set_state` followed by :meth:`get_state` round-trips
  faithfully.
* :meth:`subscribe_changes` yields ONE :class:`RuleChange` per
  per-rule edit (5-rule edit → 5 events, never one batch of 5).
* ``expires_at`` in the past → :meth:`get_state` returns the
  default and emits a ``ttp.rule.state.{rule_id}`` auto-revert
  event.
* :meth:`set_state` failure (DB write error) raises rather than
  silently dropping — operational state changes are not a
  tolerated-absence path.

Filesystem-specific properties (inotify mask, dotfile filter,
atomic-swap concurrency) live in :mod:`test_filesystem`.
"""
from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleChange, RuleState, RuleStore


_RULE_YAML = """\
rule_id: {rule_id}
rule_version: 1
name: test rule
applies_to: [command]
match:
  pattern: 'hydra'
emits:
  - technique_id: T1110
"""


def _xfail_db_until_e36(rule_store: RuleStore) -> None:
    """Skip a parametrized run for the database backend.

    The conformance contract is identical across backends, but the
    DB backend's persistence path lands at E.3.6. Per-test xfail
    rather than a module-level skip so the FS-backend run still
    exercises the assertion today.
    """
    if type(rule_store).__name__ == "DatabaseRuleStore":
        pytest.xfail("impl phase E.3.6 — DatabaseRuleStore not implemented")


# ── Surface (GREEN today) ───────────────────────────────────────────


def test_store_implements_required_methods(rule_store: RuleStore) -> None:
    """Every backend implements all four ABC methods. Catches a
    refactor that accidentally drops a method body."""
    for name in ("load_compiled", "get_state", "set_state", "subscribe_changes"):
        assert hasattr(rule_store, name)


def test_async_methods_are_coroutines() -> None:
    """The three ``async def`` methods on the ABC are coroutine
    functions; ``subscribe_changes`` is a regular ``def`` returning
    an async iterator (per the doc's signature)."""
    for name in ("load_compiled", "get_state", "set_state"):
        member = getattr(RuleStore, name)
        assert inspect.iscoroutinefunction(member), (
            f"RuleStore.{name} must be `async def`"
        )


def test_rule_change_namedtuple_shape() -> None:
    """:class:`RuleChange` carries ``change_kind``, ``rule_id``,
    ``new_value`` — pinned so a future "improvement" that adds
    fields trips downstream consumers (the bus republisher, the
    engine's atomic swap path) deliberately rather than silently."""
    assert RuleChange._fields == ("change_kind", "rule_id", "new_value")


# ── Default state behavior ──────────────────────────────────────────


async def test_get_state_unknown_returns_default(rule_store: RuleStore) -> None:
    """``get_state`` for a never-set ``rule_id`` returns the default
    ``RuleState`` — never raises, never returns ``None``.

    GREEN for :class:`FilesystemRuleStore` (the impl already returns
    ``RuleState()`` for an empty cache; covered in the contract
    file). xfail for :class:`DatabaseRuleStore` until E.3.6 lands.
    """
    if type(rule_store).__name__ == "DatabaseRuleStore":
        pytest.xfail("impl phase E.3.6 — DatabaseRuleStore.get_state")
    state = await rule_store.get_state("R0001_unknown_rule")
    assert state == RuleState()
    assert state.state == "enabled"


# ── Behavioral conformance (xfail until E.3.5/E.3.6) ────────────────


async def test_load_compiled_corpus_identical_across_backends(
    rule_store: RuleStore, tmp_path: Path,
) -> None:
    """Both backends, given the same YAML corpus, return the same
    set of ``CompiledRule`` (modulo state defaulting). The doc's
    cross-backend property requires running the same fixture against
    both — pinned here as a single test that the parametrize fans
    out over both backends."""
    _xfail_db_until_e36(rule_store)
    rules_dir: Path = rule_store._rules_dir  # type: ignore[attr-defined]
    (rules_dir / "R0001.yaml").write_text(
        _RULE_YAML.format(rule_id="R0001"), encoding="utf-8",
    )
    (rules_dir / "R0002.yaml").write_text(
        _RULE_YAML.format(rule_id="R0002"), encoding="utf-8",
    )
    compiled = await rule_store.load_compiled()
    assert {c.rule_id for c in compiled} == {"R0001", "R0002"}
    for c in compiled:
        assert isinstance(c, CompiledRule)
        assert c.state == RuleState()
        assert c.applies_to == frozenset({"command"})
        assert c.emits == (("T1110", None),)


async def test_set_state_isolates_rules(rule_store: RuleStore) -> None:
    """``set_state(A, ...)`` does not perturb the state read by
    ``get_state(B)``."""
    _xfail_db_until_e36(rule_store)
    await rule_store.set_state(
        "R0001", RuleState(state="disabled", reason="A"), set_by="op",
    )
    other = await rule_store.get_state("R0002")
    assert other == RuleState()  # B untouched


async def test_set_state_then_get_state_round_trips(
    rule_store: RuleStore,
) -> None:
    """``set_state`` followed by ``get_state`` returns the value
    that was set. No translation, no field drop."""
    _xfail_db_until_e36(rule_store)
    new_state = RuleState(
        state="clipped", confidence_max=0.5, reason="probation",
    )
    await rule_store.set_state("R0001", new_state, set_by="op")
    got = await rule_store.get_state("R0001")
    assert got.state == "clipped"
    assert got.confidence_max == 0.5
    assert got.reason == "probation"
    assert got.set_by == "op"
    assert got.set_at is not None


async def test_subscribe_changes_per_rule_not_batched(
    rule_store: RuleStore,
) -> None:
    """A 5-rule edit produces 5 :class:`RuleChange` events from
    :meth:`subscribe_changes`, never a single event carrying 5
    entries. The bus per-rule fan-out
    (``ttp.rule.reloaded.{rule_id}``) inherits its granularity from
    this iterator."""
    _xfail_db_until_e36(rule_store)
    sub = rule_store.subscribe_changes()
    for i in range(5):
        await rule_store.set_state(
            f"R000{i}", RuleState(state="disabled"), set_by="op",
        )
    seen: list[RuleChange] = []
    for _ in range(5):
        seen.append(await asyncio.wait_for(sub.__anext__(), timeout=2.0))
    rule_ids = {ch.rule_id for ch in seen}
    assert rule_ids == {f"R000{i}" for i in range(5)}
    for ch in seen:
        assert ch.change_kind == "state"
        assert isinstance(ch.new_value, RuleState)


async def test_expired_state_reverts_to_default_and_emits(
    rule_store: RuleStore,
) -> None:
    """A ``RuleState`` with ``expires_at`` in the past returns the
    default from :meth:`get_state` AND emits a
    ``ttp.rule.state.{rule_id}`` auto-revert event."""
    _xfail_db_until_e36(rule_store)
    past = datetime.now(tz=timezone.utc) - timedelta(seconds=5)
    sub = rule_store.subscribe_changes()
    await rule_store.set_state(
        "R0001",
        RuleState(state="disabled", expires_at=past),
        set_by="op",
    )
    # Drain the set_state event we just produced.
    await asyncio.wait_for(sub.__anext__(), timeout=2.0)
    state = await rule_store.get_state("R0001")
    assert state == RuleState()
    revert = await asyncio.wait_for(sub.__anext__(), timeout=2.0)
    assert revert.change_kind == "state"
    assert revert.rule_id == "R0001"
    assert revert.new_value == RuleState()


async def test_set_state_failure_raises_not_silent(
    rule_store: RuleStore,
) -> None:
    """A backend failure during :meth:`set_state` (e.g. queue
    death) MUST raise rather than silently drop. Operational state
    changes are NOT a tolerated-absence path — state drift would be
    silent and dangerous."""
    _xfail_db_until_e36(rule_store)

    class _BoomQueue:
        async def put(self, _item: object) -> None:
            raise RuntimeError("simulated backend failure")

    # Inject a poisoned subscriber so the publish path raises.
    if not hasattr(rule_store, "_subscribers"):  # pragma: no cover
        pytest.skip("backend has no subscriber fan-out hook")
    rule_store._subscribers.append(_BoomQueue())
    with pytest.raises(RuntimeError, match="simulated backend failure"):
        await rule_store.set_state(
            "R0001", RuleState(state="disabled"), set_by="op",
        )
