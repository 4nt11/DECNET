"""E.2.14b — Database-specific RuleStore properties.

Per ``development/TTP_TAGGING.md`` §E.2.14b: the database backend's
tests run against BOTH SQLite and MySQL via the ``db_backends``
fixture in :mod:`tests.web.db.conftest`. Today the database store's
methods raise ``NotImplementedError`` so most assertions xfail.

The cross-backend conformance assertions (load_compiled equality,
get_state default, set_state isolation/round-trip,
subscribe_changes per-rule fan-out, expires_at auto-revert) live in
:mod:`test_conformance` and run against this backend automatically
via the parametrized ``rule_store`` fixture in :mod:`conftest`.

This module pins behavior that's *only* meaningful for the database
backend — specifically the propagation of state via the underlying
``ttp_rule_state`` table, which conformance tests exercise but don't
introspect at the SQL level.
"""
from __future__ import annotations

import inspect

import pytest

from decnet.ttp.store.impl.database import DatabaseRuleStore


def test_database_store_constructs_without_platform_guard() -> None:
    """Unlike the filesystem backend, the database store has no
    platform restriction — a macOS / Windows operator who set
    ``DECNET_TTP_RULE_STORE_TYPE=database`` MUST be able to import
    and construct the class without hitting an import-time error.
    Pinned because regressing this would re-block non-Linux
    contributors from running the suite at all."""
    store = DatabaseRuleStore()
    assert store is not None


def test_database_store_implements_abc() -> None:
    """All four ABC methods are defined on the concrete class —
    not inherited as abstract. Catches a refactor that accidentally
    drops a method body without removing the ``@abstractmethod``
    decorator from the ABC."""
    for name in ("load_compiled", "get_state", "set_state", "subscribe_changes"):
        member = getattr(DatabaseRuleStore, name)
        assert not getattr(member, "__isabstractmethod__", False)


def test_async_methods_are_coroutines() -> None:
    for name in ("load_compiled", "get_state", "set_state"):
        member = getattr(DatabaseRuleStore, name)
        assert inspect.iscoroutinefunction(member)


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.6 — DatabaseRuleStore needs to write "
    "into ttp_rule_state via the repository session; today the "
    "method body raises NotImplementedError",
)
async def test_set_state_writes_to_ttp_rule_state_table() -> None:
    """``set_state`` writes / upserts a row in the ``ttp_rule_state``
    table. After the write, a fresh ``DatabaseRuleStore`` instance
    sees the same value via :meth:`get_state` (state survives
    process restart — that's the whole point of the database
    backend over the filesystem one)."""
    pytest.fail("DatabaseRuleStore.set_state not yet implemented")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.6 — master-side filesystem→DB sync of "
    "ttp_rule lands with the swarm-mode wiring",
)
async def test_filesystem_to_db_sync_populates_ttp_rule() -> None:
    """In swarm mode, the master watches ``./rules/ttp/`` and
    syncs each YAML edit into the ``ttp_rule`` table; workers
    tail the DB. This test pins the half of the contract that
    only the database backend implements."""
    pytest.fail("master-side fs→DB sync not yet implemented")
