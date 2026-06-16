# SPDX-License-Identifier: AGPL-3.0-or-later
"""Parametrized ``rule_store`` fixture for E.2.14b.

The conformance contract from ``development/TTP_TAGGING.md`` §E.2.14b:
both backends — :class:`FilesystemRuleStore` and
:class:`DatabaseRuleStore` — must satisfy the same observable
behavior. Tests that consume :func:`rule_store` are run twice, once
per backend.

Filesystem is skipped on non-Linux (it raises ``RuntimeError`` from
``__init__`` on macOS / Windows because the inotify dep is
Linux-only).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import AsyncIterator

import pytest
import pytest_asyncio

from decnet.ttp.store.base import RuleStore
from decnet.ttp.store.impl.database import DatabaseRuleStore
from decnet.ttp.store.impl.filesystem import FilesystemRuleStore
from decnet.web.db.models import TTPRule


async def _seed_rule_filesystem(
    store: FilesystemRuleStore, rule_id: str, yaml_text: str,
) -> None:
    rules_dir: Path = store._rules_dir
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / f"{rule_id}.yaml").write_text(yaml_text, encoding="utf-8")


async def _seed_rule_database(
    store: DatabaseRuleStore, rule_id: str, yaml_text: str,
) -> None:
    # Direct ``ttp_rule`` insert — bypass the master sync helper to
    # keep tests deterministic. Mirrors what a swarm master would have
    # written into the table.
    repo = await store._ensure_repo()
    async with repo._session() as session:  # type: ignore[attr-defined]
        from datetime import datetime, timezone  # noqa: PLC0415

        session.add(TTPRule(
            rule_id=rule_id,
            rule_version=1,
            source_path=f"./rules/ttp/{rule_id}.yaml",
            yaml_content=yaml_text,
            updated_at=datetime.now(timezone.utc),
            updated_by="test",
        ))
        await session.commit()


async def seed_rule(store: RuleStore, rule_id: str, yaml_text: str) -> None:
    """Backend-aware test helper: write a rule into the store.

    Filesystem store: drop a YAML file under ``_rules_dir``.
    Database store: insert a ``ttp_rule`` row directly.
    """
    if isinstance(store, FilesystemRuleStore):
        await _seed_rule_filesystem(store, rule_id, yaml_text)
    elif isinstance(store, DatabaseRuleStore):
        await _seed_rule_database(store, rule_id, yaml_text)
    else:  # pragma: no cover
        raise TypeError(f"unknown rule store backend: {type(store).__name__}")


@pytest_asyncio.fixture(
    params=["filesystem", "database"],
    ids=["filesystem", "database"],
)
async def rule_store(
    request: pytest.FixtureRequest, tmp_path: Path,
) -> AsyncIterator[RuleStore]:
    """Yield a fresh :class:`RuleStore` instance per parametrization.

    The filesystem backend is constructed against a ``tmp_path``
    rules dir so tests never touch the real ``./rules/``. The
    database backend gets a per-test SQLite repo (initialized with
    ``metadata.create_all``) so each test sees an empty
    ``ttp_rule`` / ``ttp_rule_state`` pair.
    """
    backend = request.param
    if backend == "filesystem":
        if sys.platform != "linux":
            pytest.skip("FilesystemRuleStore requires Linux (inotify)")
        yield FilesystemRuleStore(rules_dir=tmp_path)
    else:
        from decnet.web.db.sqlite.repository import SQLiteRepository  # noqa: PLC0415

        repo = SQLiteRepository(db_path=str(tmp_path / "ttp_store.db"))
        await repo.initialize()
        store = DatabaseRuleStore(repo=repo)
        # Mirror FS store's ``_rules_dir`` attr so cross-backend tests
        # that need to drop sample YAML on disk have somewhere to put
        # it; the DB-backend tests that need rule definitions either
        # write to ``ttp_rule`` directly or call ``upsert_rule``.
        store._rules_dir = tmp_path  # type: ignore[attr-defined]
        try:
            yield store
        finally:
            try:
                await repo.engine.dispose()
            except Exception:  # noqa: BLE001 — teardown best-effort
                pass
