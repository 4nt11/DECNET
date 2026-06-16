# SPDX-License-Identifier: AGPL-3.0-or-later
"""Alembic wiring guards.

These pin the two halves of SQLModelRepository._apply_schema:
* real boots run `alembic upgrade head` (schema owned by migration history),
* tests (DECNET_TESTING=1) take the faster create_all path.

The first test also doubles as a drift guard: if someone adds a model table
but forgets to autogenerate a migration, `alembic upgrade head` won't create
it and this fails.
"""
from __future__ import annotations

import sqlite3

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

import decnet.web.db.models  # noqa: F401  (registers every table on metadata)
from decnet.web.db.migrate import run_migrations
from decnet.web.db.sqlite.repository import SQLiteRepository


def _table_names(db_path: str) -> set[str]:
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    finally:
        con.close()
    return {r[0] for r in rows}


async def test_migrations_create_every_model_table(tmp_path):
    """`alembic upgrade head` must materialise every SQLModel table —
    catches a model added without a corresponding migration."""
    db_path = str(tmp_path / "mig.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        await run_migrations(engine)
    finally:
        await engine.dispose()

    created = _table_names(db_path)
    expected = set(SQLModel.metadata.tables)
    missing = expected - created
    assert not missing, f"migration head is missing tables: {sorted(missing)}"
    assert "alembic_version" in created


async def test_real_boot_runs_alembic(tmp_path, monkeypatch):
    """With DECNET_TESTING unset, initialize() runs migrations and stamps
    the alembic_version table."""
    monkeypatch.delenv("DECNET_TESTING", raising=False)
    repo = SQLiteRepository(db_path=str(tmp_path / "boot.db"))
    try:
        await repo._apply_schema()
        async with repo.engine.begin() as conn:
            ver = (await conn.execute(text("SELECT version_num FROM alembic_version"))).fetchall()
    finally:
        await repo.engine.dispose()
    assert ver, "alembic_version not stamped — migrations did not run"


async def test_testing_mode_uses_create_all(tmp_path, monkeypatch):
    """Under DECNET_TESTING=1 the schema comes from create_all, so there is
    no alembic_version table (Alembic was skipped)."""
    monkeypatch.setenv("DECNET_TESTING", "1")
    db_path = str(tmp_path / "test.db")
    repo = SQLiteRepository(db_path=db_path)
    try:
        await repo._apply_schema()
    finally:
        await repo.engine.dispose()
    tables = _table_names(db_path)
    assert "attackers" in tables          # schema was created…
    assert "alembic_version" not in tables  # …but not via Alembic
