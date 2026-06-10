# SPDX-License-Identifier: AGPL-3.0-or-later
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
from datetime import datetime, timedelta, timezone
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


# ---------------------------------------------------------------------------
# BUG-13 regression: tail_db must not drop rules updated AT the watermark
# ---------------------------------------------------------------------------

_SHARED_YAML_TEMPLATE = """\
rule_id: {rule_id}
rule_version: 1
name: {name}
applies_to: [command]
match:
  pattern: 'test'
emits:
  - tactic: TA0007
    technique_id: T1033
    confidence: 0.85
"""


async def test_tail_db_same_timestamp_both_rules_emitted(
    db_store: DatabaseRuleStore, tmp_path: Path,
) -> None:
    """BUG-13 regression: two rules with the SAME updated_at timestamp are
    BOTH emitted by tail_db across the watermark boundary (none dropped).

    The pre-fix code used ``updated_at > watermark`` which silently
    dropped rules whose timestamp equalled the watermark.  The fix
    changes to ``>=`` and deduplicates by rule_id within the window,
    advancing the watermark by 1 µs after emitting to prevent re-emission.
    """
    import asyncio  # noqa: PLC0415

    # Pin a past watermark so both rules are in scope on the first poll.
    shared_ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    db_store._tail_watermark = shared_ts

    # Insert two TTPRule rows with identical updated_at.
    repo = db_store._repo
    assert repo is not None
    for rule_id, name in (("R1001", "rule one"), ("R1002", "rule two")):
        yaml_content = _SHARED_YAML_TEMPLATE.format(rule_id=rule_id, name=name)
        async with repo._session() as session:  # type: ignore[attr-defined]
            row = TTPRule(
                rule_id=rule_id,
                rule_version=1,
                source_path=f"./rules/ttp/{rule_id}.yaml",
                yaml_content=yaml_content,
                updated_at=shared_ts,
                updated_by="test",
            )
            session.add(row)
            await session.commit()

    # Patch _emit_change to capture rule_ids without touching subscribers.
    emitted_via_tail: set[str] = set()
    original_emit = db_store._emit_change

    async def _capture_emit(change, **kwargs):  # type: ignore[no-untyped-def]
        emitted_via_tail.add(change.rule_id)
        await original_emit(change, **kwargs)

    db_store._emit_change = _capture_emit  # type: ignore[assignment]
    db_store._stop.clear()

    # Run tail_db for one short cycle then stop.
    poll_task = asyncio.create_task(db_store.tail_db(poll_interval=0.01))
    await asyncio.sleep(0.08)
    db_store._stop.set()
    try:
        await asyncio.wait_for(poll_task, timeout=2.0)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        poll_task.cancel()

    assert "R1001" in emitted_via_tail, "R1001 must be emitted by tail_db"
    assert "R1002" in emitted_via_tail, "R1002 must be emitted by tail_db"
    # After emitting both rules at shared_ts, the seen-ids set must record
    # them so that a second poll at the same watermark skips re-emission.
    # The watermark itself stays at shared_ts (no newer rows existed) but
    # _tail_seen_ids acts as the dedup guard.
    assert "R1001" in db_store._tail_seen_ids, "R1001 must be in _tail_seen_ids"
    assert "R1002" in db_store._tail_seen_ids, "R1002 must be in _tail_seen_ids"

    # Simulate a second poll — the rules should NOT be re-emitted.
    emitted_via_tail.clear()
    db_store._stop.clear()
    poll_task2 = asyncio.create_task(db_store.tail_db(poll_interval=0.01))
    await asyncio.sleep(0.08)
    db_store._stop.set()
    try:
        await asyncio.wait_for(poll_task2, timeout=2.0)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        poll_task2.cancel()

    assert "R1001" not in emitted_via_tail, "R1001 must NOT be re-emitted on second poll"
    assert "R1002" not in emitted_via_tail, "R1002 must NOT be re-emitted on second poll"


async def test_tail_db_coarse_timestamp_late_rule_still_emitted(
    db_store: DatabaseRuleStore, tmp_path: Path,
) -> None:
    """BUG-13 (microsecond-advance regression): on coarse second-resolution
    timestamps (MySQL DATETIME) a rule saved at the SAME whole-second AFTER
    a poll must STILL be emitted on the next poll — not dropped.

    The defective fix advanced the watermark to ``max_ts + 1 µs`` after a
    poll. On second-resolution storage that bump lands inside the same
    whole-second bucket, so a row written later in that same second has
    ``updated_at < watermark`` and the ``>= watermark`` query silently drops
    it — reintroducing the same-timestamp bug.

    The correct fix keeps the watermark AT max_ts and relies solely on
    ``_tail_seen_ids`` for dedup. This test simulates coarse storage by
    writing every row at the identical whole-second timestamp.

    Red-before/green-after: with ``max_ts + 1 µs`` the second rule
    (written at the same whole second after the first poll) is dropped and
    this test fails; keeping the watermark at max_ts emits it.
    """
    import asyncio  # noqa: PLC0415

    coarse_ts = datetime(2024, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
    # Start the watermark strictly BEFORE the rows so the first poll takes
    # the advancing (max_ts > watermark) branch — the exact branch where the
    # defective +1 µs bump skips past same-second late arrivals.
    db_store._tail_watermark = coarse_ts - timedelta(seconds=5)

    repo = db_store._repo
    assert repo is not None

    async def _insert(rule_id: str) -> None:
        yaml_content = _SHARED_YAML_TEMPLATE.format(rule_id=rule_id, name=rule_id)
        async with repo._session() as session:  # type: ignore[attr-defined]
            session.add(TTPRule(
                rule_id=rule_id,
                rule_version=1,
                source_path=f"./rules/ttp/{rule_id}.yaml",
                yaml_content=yaml_content,
                updated_at=coarse_ts,  # identical whole-second timestamp
                updated_by="test",
            ))
            await session.commit()

    emitted: list[str] = []
    original_emit = db_store._emit_change

    async def _capture_emit(change, **kwargs):  # type: ignore[no-untyped-def]
        emitted.append(change.rule_id)
        await original_emit(change, **kwargs)

    db_store._emit_change = _capture_emit  # type: ignore[assignment]

    # First poll: only R2001 exists yet.
    await _insert("R2001")
    db_store._stop.clear()
    poll1 = asyncio.create_task(db_store.tail_db(poll_interval=0.01))
    await asyncio.sleep(0.05)
    db_store._stop.set()
    try:
        await asyncio.wait_for(poll1, timeout=2.0)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        poll1.cancel()

    assert "R2001" in emitted
    # Watermark stayed at the coarse second; seen-ids guards re-emission.
    assert db_store._tail_watermark == coarse_ts
    assert "R2001" in db_store._tail_seen_ids

    # A rule arrives LATER, in the same whole second (coarse resolution).
    emitted.clear()
    await _insert("R2002")
    db_store._stop.clear()
    poll2 = asyncio.create_task(db_store.tail_db(poll_interval=0.01))
    await asyncio.sleep(0.05)
    db_store._stop.set()
    try:
        await asyncio.wait_for(poll2, timeout=2.0)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        poll2.cancel()

    assert "R2002" in emitted, "late same-second rule must NOT be dropped"
    assert "R2001" not in emitted, "already-emitted rule must not re-fire"
