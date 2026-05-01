"""E.2.14b — Database-specific RuleStore properties.

Per ``development/TTP_TAGGING.md`` §E.2.14b: the database backend's
tests run against BOTH SQLite and MySQL via the ``db_backends``
fixture in :mod:`tests.web.db.conftest`.

The cross-backend conformance assertions (load_compiled equality,
get_state default, set_state isolation/round-trip,
subscribe_changes per-rule fan-out, expires_at auto-revert) live in
:mod:`test_conformance` and run against this backend automatically
via the parametrized ``rule_store`` fixture in :mod:`conftest`.

This module pins behavior that's *only* meaningful for the database
backend — specifically the propagation of state via the underlying
``ttp_rule_state`` table and the master-side filesystem→DB sync
helper.
"""
from __future__ import annotations

import inspect
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleState
from decnet.ttp.store.impl.database import DatabaseRuleStore
from decnet.web.db.models import TTPRule, TTPRuleState
from sqlalchemy import select as sa_select
from sqlmodel import col


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


@pytest_asyncio.fixture
async def db_store(tmp_path: Path) -> Any:
    from decnet.web.db.sqlite.repository import SQLiteRepository

    repo = SQLiteRepository(db_path=str(tmp_path / "ttp_db_store.db"))
    await repo.initialize()
    store = DatabaseRuleStore(repo=repo)
    try:
        yield store
    finally:
        try:
            await repo.engine.dispose()
        except Exception:  # noqa: BLE001
            pass


async def test_set_state_writes_to_ttp_rule_state_table(
    db_store: DatabaseRuleStore, tmp_path: Path,
) -> None:
    """``set_state`` writes / upserts a row in the ``ttp_rule_state``
    table. After the write, a fresh :class:`DatabaseRuleStore`
    instance pointing at the same DB sees the same value via
    :meth:`get_state` — state survives process restart, which is the
    whole point of the DB backend over the filesystem one."""
    await db_store.set_state(
        "R0001",
        RuleState(state="disabled", reason="probation"),
        set_by="anti",
    )
    repo = db_store._repo
    assert repo is not None
    async with repo._session() as session:  # type: ignore[attr-defined]
        row = (
            await session.execute(
                sa_select(TTPRuleState).where(
                    col(TTPRuleState.rule_id) == "R0001",
                ),
            )
        ).scalars().first()
    assert row is not None
    assert row.state == "disabled"
    assert row.reason == "probation"
    assert row.set_by == "anti"

    # Fresh store instance against the same engine — state survives.
    fresh = DatabaseRuleStore(repo=repo)
    state = await fresh.get_state("R0001")
    assert state.state == "disabled"
    assert state.reason == "probation"


async def test_filesystem_to_db_sync_populates_ttp_rule(
    db_store: DatabaseRuleStore, tmp_path: Path,
) -> None:
    """In swarm mode, the master watches ``./rules/ttp/`` and
    syncs each YAML edit into the ``ttp_rule`` table; workers
    tail the DB. This test pins the half of the contract that
    only the database backend implements: a CompiledRule fed to
    :meth:`upsert_rule` lands as a ``ttp_rule`` row whose
    ``yaml_content`` round-trips through :meth:`load_compiled`."""
    compiled = CompiledRule(
        rule_id="R0001",
        rule_version=1,
        name="brute force ssh",
        applies_to=frozenset({"command"}),
        match_spec={"pattern": "hydra"},
        emits=(("T1110", None, "TA0006", 0.85),),
        evidence_fields=("matched_tokens",),
        state=RuleState(),
    )
    await db_store.upsert_rule(
        compiled,
        source_path="./rules/ttp/R0001.yaml",
        updated_by="filesystem",
    )
    repo = db_store._repo
    assert repo is not None
    async with repo._session() as session:  # type: ignore[attr-defined]
        row = (
            await session.execute(
                sa_select(TTPRule).where(col(TTPRule.rule_id) == "R0001"),
            )
        ).scalars().first()
    assert row is not None
    assert row.rule_version == 1
    assert row.updated_by == "filesystem"
    # Round-trip through load_compiled.
    loaded = await db_store.load_compiled()
    assert len(loaded) == 1
    assert loaded[0].rule_id == "R0001"
    assert loaded[0].emits == (("T1110", None, "TA0006", 0.85),)


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="FilesystemRuleStore is Linux-only (inotify dep)",
)
async def test_sync_from_filesystem_propagates_changes(
    db_store: DatabaseRuleStore, tmp_path: Path,
) -> None:
    """The master-side helper :meth:`sync_from_filesystem` projects
    every :class:`RuleChange` from a :class:`FilesystemRuleStore`
    onto a ``ttp_rule`` upsert. Validates the swarm-mode
    bootstrap path: master watches disk, workers tail DB."""
    import asyncio  # noqa: PLC0415
    from decnet.ttp.store.impl.filesystem import FilesystemRuleStore  # noqa: PLC0415

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    fs_store = FilesystemRuleStore(rules_dir=rules_dir)

    sync_task = asyncio.create_task(
        db_store.sync_from_filesystem(fs_store, updated_by="git"),
    )
    try:
        async with fs_store:
            await asyncio.sleep(0.05)
            (rules_dir / "R0042.yaml").write_text(
                """rule_id: R0042
rule_version: 1
name: test
applies_to: [command]
match:
  pattern: 'whoami'
emits:
  - tactic: TA0007
    technique_id: T1033
    confidence: 0.85
""",
                encoding="utf-8",
            )
            # Give the sync task a moment to project the change.
            for _ in range(20):
                await asyncio.sleep(0.05)
                loaded = await db_store.load_compiled()
                if any(c.rule_id == "R0042" for c in loaded):
                    break
            else:
                pytest.fail("sync_from_filesystem did not project the edit")
            ids = {c.rule_id for c in loaded}
            assert "R0042" in ids
    finally:
        sync_task.cancel()
        try:
            await sync_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
