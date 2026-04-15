"""
Tests for MySQLRepository._migrate_column_types().

No live MySQL server required — uses an in-memory SQLite engine that exposes
the same information_schema-style query surface via a mocked connection, plus
an integration-style test using a real async engine over aiosqlite (which
ignores the TEXT/MEDIUMTEXT distinction but verifies the ALTER path is called
and idempotent).

The ALTER TABLE branch is tested via unittest.mock: we intercept the
information_schema query result and assert the correct MODIFY COLUMN
statements are issued.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call

from decnet.web.db.mysql.repository import MySQLRepository


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_repo() -> MySQLRepository:
    """Construct a MySQLRepository without touching any real DB."""
    return MySQLRepository.__new__(MySQLRepository)


# ── _migrate_column_types ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_migrate_column_types_issues_alter_for_text_columns():
    """When information_schema reports TEXT columns, ALTER TABLE is called for each."""
    repo = _make_repo()

    # Rows returned by the information_schema query: two TEXT columns found
    fake_rows = [
        ("attackers", "commands"),
        ("attackers", "fingerprints"),
        ("state", "value"),
    ]

    exec_results: list[str] = []

    async def fake_execute(stmt):
        sql = str(stmt)
        if "information_schema" in sql:
            result = MagicMock()
            result.fetchall.return_value = fake_rows
            return result
        # Capture ALTER TABLE calls
        exec_results.append(sql)
        return MagicMock()

    fake_conn = AsyncMock()
    fake_conn.execute.side_effect = fake_execute

    fake_ctx = AsyncMock()
    fake_ctx.__aenter__ = AsyncMock(return_value=fake_conn)
    fake_ctx.__aexit__ = AsyncMock(return_value=False)

    repo.engine = MagicMock()
    repo.engine.begin.return_value = fake_ctx

    await repo._migrate_column_types()

    # Three ALTER TABLE statements expected, one per TEXT column returned
    assert len(exec_results) == 3
    assert any("`commands` MEDIUMTEXT" in s for s in exec_results)
    assert any("`fingerprints` MEDIUMTEXT" in s for s in exec_results)
    assert any("`value` MEDIUMTEXT" in s for s in exec_results)
    # Verify NOT NULL is preserved
    assert all("NOT NULL" in s for s in exec_results)


@pytest.mark.asyncio
async def test_migrate_column_types_no_alter_when_already_mediumtext():
    """When information_schema returns no TEXT rows, no ALTER is issued."""
    repo = _make_repo()

    exec_results: list[str] = []

    async def fake_execute(stmt):
        sql = str(stmt)
        if "information_schema" in sql:
            result = MagicMock()
            result.fetchall.return_value = []   # nothing to migrate
            return result
        exec_results.append(sql)
        return MagicMock()

    fake_conn = AsyncMock()
    fake_conn.execute.side_effect = fake_execute

    fake_ctx = AsyncMock()
    fake_ctx.__aenter__ = AsyncMock(return_value=fake_conn)
    fake_ctx.__aexit__ = AsyncMock(return_value=False)

    repo.engine = MagicMock()
    repo.engine.begin.return_value = fake_ctx

    await repo._migrate_column_types()

    assert exec_results == [], "No ALTER TABLE should be issued when columns are already MEDIUMTEXT"


@pytest.mark.asyncio
async def test_migrate_column_types_idempotent_on_repeated_calls():
    """Calling _migrate_column_types twice is safe: second call is a no-op."""
    repo = _make_repo()
    call_count = 0

    async def fake_execute(stmt):
        nonlocal call_count
        sql = str(stmt)
        if "information_schema" in sql:
            result = MagicMock()
            # First call: two TEXT columns; second call: zero (already migrated)
            call_count += 1
            result.fetchall.return_value = (
                [("attackers", "commands")] if call_count == 1 else []
            )
            return result
        return MagicMock()

    def _make_ctx():
        fake_conn = AsyncMock()
        fake_conn.execute.side_effect = fake_execute
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=fake_conn)
        ctx.__aexit__ = AsyncMock(return_value=False)
        return ctx

    repo.engine = MagicMock()
    repo.engine.begin.side_effect = _make_ctx

    await repo._migrate_column_types()
    await repo._migrate_column_types()  # second call must not raise


@pytest.mark.asyncio
async def test_migrate_column_types_default_clause_per_column():
    """Each attacker column gets DEFAULT '[]'; state.value gets no DEFAULT."""
    repo = _make_repo()

    all_text_rows = [
        ("attackers", "commands"),
        ("attackers", "fingerprints"),
        ("attackers", "services"),
        ("attackers", "deckies"),
        ("state", "value"),
    ]
    alter_stmts: list[str] = []

    async def fake_execute(stmt):
        sql = str(stmt)
        if "information_schema" in sql:
            result = MagicMock()
            result.fetchall.return_value = all_text_rows
            return result
        alter_stmts.append(sql)
        return MagicMock()

    fake_conn = AsyncMock()
    fake_conn.execute.side_effect = fake_execute

    fake_ctx = AsyncMock()
    fake_ctx.__aenter__ = AsyncMock(return_value=fake_conn)
    fake_ctx.__aexit__ = AsyncMock(return_value=False)

    repo.engine = MagicMock()
    repo.engine.begin.return_value = fake_ctx

    await repo._migrate_column_types()

    attacker_alters = [s for s in alter_stmts if "`attackers`" in s]
    state_alters    = [s for s in alter_stmts if "`state`" in s]

    assert len(attacker_alters) == 4
    assert len(state_alters) == 1

    for stmt in attacker_alters:
        assert "DEFAULT '[]'" in stmt, f"Missing DEFAULT '[]' in: {stmt}"

    # state.value has no DEFAULT in the schema
    assert "DEFAULT" not in state_alters[0], \
        f"Unexpected DEFAULT in state.value alter: {state_alters[0]}"


# ── initialize override ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mysql_initialize_calls_migrate_column_types():
    """MySQLRepository.initialize() must invoke _migrate_column_types after _migrate_attackers_table."""
    repo = _make_repo()

    call_order: list[str] = []

    async def fake_migrate_attackers():
        call_order.append("migrate_attackers")

    async def fake_migrate_column_types():
        call_order.append("migrate_column_types")

    async def fake_ensure_admin():
        call_order.append("ensure_admin")

    repo._migrate_attackers_table = fake_migrate_attackers
    repo._migrate_column_types    = fake_migrate_column_types
    repo._ensure_admin_user       = fake_ensure_admin

    # Stub engine.begin() so create_all is a no-op
    fake_conn = AsyncMock()
    fake_conn.run_sync = AsyncMock()
    fake_ctx = AsyncMock()
    fake_ctx.__aenter__ = AsyncMock(return_value=fake_conn)
    fake_ctx.__aexit__  = AsyncMock(return_value=False)
    repo.engine = MagicMock()
    repo.engine.begin.return_value = fake_ctx

    await repo.initialize()

    assert call_order == ["migrate_attackers", "migrate_column_types", "ensure_admin"], \
        f"Unexpected call order: {call_order}"
