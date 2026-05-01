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

import inspect

import pytest

from decnet.ttp.store.base import RuleChange, RuleState, RuleStore


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


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.5/E.3.6 — load_compiled lands with each "
    "backend's parse-and-compile implementation",
)
async def test_load_compiled_corpus_identical_across_backends(
    rule_store: RuleStore,
) -> None:
    """Both backends, given the same YAML corpus, return the same
    set of ``CompiledRule`` (modulo state defaulting). The doc's
    cross-backend property requires running the same fixture against
    both — pinned here as a single test that the parametrize fans
    out over both backends."""
    pytest.fail("load_compiled not yet implemented")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.5/E.3.6 — set_state lands with each "
    "backend's persistence implementation",
)
async def test_set_state_isolates_rules(rule_store: RuleStore) -> None:
    """``set_state(A, ...)`` does not perturb the state read by
    ``get_state(B)``. Catches a refactor that accidentally writes
    a global cache key."""
    pytest.fail("set_state not yet implemented")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.5/E.3.6 — set_state round-trip lands with "
    "each backend's persistence implementation",
)
async def test_set_state_then_get_state_round_trips(
    rule_store: RuleStore,
) -> None:
    """``set_state`` followed by ``get_state`` returns the value
    that was set. No translation, no field drop."""
    pytest.fail("set_state round-trip not yet implemented")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.5/E.3.6 — subscribe_changes incremental "
    "fan-out lands with each backend's watch implementation",
)
async def test_subscribe_changes_per_rule_not_batched(
    rule_store: RuleStore,
) -> None:
    """A 5-rule edit produces 5 :class:`RuleChange` events from
    :meth:`subscribe_changes`, never a single event carrying 5
    entries. The bus per-rule fan-out
    (``ttp.rule.reloaded.{rule_id}``) inherits its granularity from
    this iterator."""
    pytest.fail("subscribe_changes not yet implemented")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.5/E.3.6 — expires_at auto-revert + "
    "ttp.rule.state.{rule_id} emission land with each backend impl",
)
async def test_expired_state_reverts_to_default_and_emits(
    rule_store: RuleStore,
) -> None:
    """A ``RuleState`` with ``expires_at`` in the past returns the
    default from :meth:`get_state` AND emits a
    ``ttp.rule.state.{rule_id}`` auto-revert event."""
    pytest.fail("expires_at auto-revert not yet implemented")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.5/E.3.6 — set_state failure semantics "
    "(raise, never silently drop) land with each backend impl",
)
async def test_set_state_failure_raises_not_silent(
    rule_store: RuleStore,
) -> None:
    """A backend failure during :meth:`set_state` (e.g. DB write
    error, disk full) MUST raise rather than silently drop.
    Operational state changes are NOT a tolerated-absence path —
    state drift would be silent and dangerous."""
    pytest.fail("set_state failure semantics not yet implemented")
