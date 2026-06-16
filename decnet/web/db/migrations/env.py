# SPDX-License-Identifier: AGPL-3.0-or-later
"""Alembic environment — async, dual-backend (sqlite | mysql).

Two entry shapes:

* **Programmatic** (app boot): :func:`decnet.web.db.migrate.run_migrations`
  passes the app's own sync ``Connection`` via ``config.attributes`` so the
  upgrade rides the existing engine — no second connection, no extra driver.
* **Standalone** (``alembic`` CLI: autogenerate, upgrade, history): builds its
  own async engine from ``DECNET_DB_TYPE``, mirroring ``db/factory.py``.
"""
from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy.engine import Connection
from sqlmodel import SQLModel

# Importing the models package registers every table on SQLModel.metadata,
# which is what autogenerate diffs against.
import decnet.web.db.models  # noqa: F401

config = context.config

# Standalone CLI runs configure logging from alembic.ini; the programmatic
# path builds a Config with no file, so guard on it.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = SQLModel.metadata


def _build_async_engine():
    """Standalone-only: pick an async engine the way db/factory.py does."""
    db_type = os.environ.get("DECNET_DB_TYPE", "sqlite").lower()
    if db_type == "sqlite":
        from decnet.config import _ROOT
        from decnet.web.db.sqlite.database import get_async_engine as sqlite_engine
        db_path = os.environ.get("DECNET_DB_PATH", str(_ROOT / "decnet.db"))
        return sqlite_engine(db_path)
    if db_type == "mysql":
        from decnet.web.db.mysql.database import get_async_engine as mysql_engine
        return mysql_engine()
    raise ValueError(f"Unsupported database type: {db_type}")


def _configure_and_run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # SQLite can't ALTER in place; batch mode rewrites the table so future
        # migrations (drop/alter column) work on both backends.
        render_as_batch=connection.dialect.name == "sqlite",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_standalone() -> None:
    engine = _build_async_engine()
    async with engine.connect() as connection:
        await connection.run_sync(_configure_and_run)
    await engine.dispose()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection", None)
    if connection is not None:
        # Programmatic: app handed us a live sync Connection (via run_sync).
        _configure_and_run(connection)
    else:
        asyncio.run(_run_standalone())


if context.is_offline_mode():
    # Offline (--sql) mode: emit DDL without a DB. Cheap to support and keeps
    # `alembic upgrade head --sql` working for operators who want to review SQL.
    context.configure(
        url=os.environ.get("DECNET_DB_URL"),
        target_metadata=target_metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    run_migrations_online()
