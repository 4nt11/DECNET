# SPDX-License-Identifier: AGPL-3.0-or-later
"""Programmatic Alembic upgrade, run at app boot for managed databases.

Real boots run ``alembic upgrade head`` so the schema is owned by the
versioned migration history. Test/ephemeral DBs skip this and use
``SQLModel.metadata.create_all`` instead (see
:meth:`SQLModelRepository._apply_schema`) — faster, and a throwaway DB never
needs an upgrade path.

The migration scripts live inside the package (``db/migrations``), so this
works from an installed wheel without depending on the repo-root
``alembic.ini`` (that file exists only for the ``alembic`` CLI).
"""
from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine

_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def _upgrade(connection: Connection) -> None:
    # No ini file: env.py skips fileConfig and reuses this connection
    # (passed via attributes) instead of building its own engine.
    cfg = Config()
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, "head")


async def run_migrations(engine: AsyncEngine) -> None:
    """Upgrade ``engine``'s database to the latest revision (alembic head)."""
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade)
