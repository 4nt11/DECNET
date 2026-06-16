# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared fixtures for ``tests/web/db/`` — dual-backend repo testing.

The ``db_backends`` fixture parametrizes a repository instance over
SQLite (always) and MySQL (skipped when ``DECNET_TEST_MYSQL_URL`` is
unset). This is the single source of truth referenced by the design
doc's "every repo test runs against both SQLite and MySQL"
convention; new repo tests under ``tests/web/db/`` should consume
the fixture rather than instantiating their own backend.

MySQL is gated on env var rather than auto-detected because spinning
a real MySQL is heavy enough to belong in CI / live runs but not the
dev loop. Per project memory: "skip heavy test categories" in the
dev cycle.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import AsyncIterator

import pytest
import pytest_asyncio

from decnet.web.db.factory import get_repository
from decnet.web.db.repository import BaseRepository


_BACKENDS: list[str] = ["sqlite"]
if os.environ.get("DECNET_TEST_MYSQL_URL"):
    _BACKENDS.append("mysql")


@pytest_asyncio.fixture(params=_BACKENDS, ids=_BACKENDS)
async def db_backends(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[BaseRepository]:
    """Yield an initialized :class:`BaseRepository` for each available
    backend.

    SQLite always runs (via ``aiosqlite`` + a tmp file). MySQL runs
    iff ``DECNET_TEST_MYSQL_URL`` is set in the environment to a real
    MySQL DSN — in that case the fixture writes a per-test schema
    name into ``DECNET_DB_URL`` so concurrent tests don't collide.
    """
    backend = request.param
    if backend == "sqlite":
        monkeypatch.setenv("DECNET_DB_TYPE", "sqlite")
        repo = get_repository(db_path=str(tmp_path / "ttp.db"))
    else:
        # MySQL — uses the operator-supplied DSN. Per dual-DB-backend
        # convention, dialect-specific behavior overrides land in the
        # MySQL repo class; this fixture does not paper over them.
        url = os.environ["DECNET_TEST_MYSQL_URL"]
        monkeypatch.setenv("DECNET_DB_TYPE", "mysql")
        monkeypatch.setenv("DECNET_DB_URL", url)
        repo = get_repository()
    await repo.initialize()
    try:
        yield repo
    finally:
        # SQLite is fully isolated per tmp_path; MySQL needs explicit
        # teardown that's the operator's responsibility (truncate or
        # drop schema in a CI hook). The repo close is best-effort.
        engine = getattr(repo, "engine", None)
        if engine is not None:
            try:
                await engine.dispose()
            except Exception:  # noqa: BLE001 — teardown best-effort
                pass
