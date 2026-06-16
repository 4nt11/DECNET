# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Tests for _ensure_admin_user env-drift self-healing.

Scenario: DECNET_ADMIN_PASSWORD changes between runs while the SQLite DB
persists on disk. Previously _ensure_admin_user was strictly insert-if-missing,
so the stale hash from the first seed locked out every subsequent login.

Contract: if the admin still has must_change_password=True (they never
finalized their own password), the stored hash re-syncs from the env.
Once the admin picks a real password, we never touch it.
"""
import pytest

from decnet.web.auth import verify_password
from decnet.web.db.sqlite.repository import SQLiteRepository


@pytest.mark.asyncio
async def test_admin_seeded_on_empty_db(tmp_path, monkeypatch):
    monkeypatch.setattr("decnet.web.db.sqlmodel_repo.DECNET_ADMIN_PASSWORD", "first")
    repo = SQLiteRepository(db_path=str(tmp_path / "t.db"))
    await repo.initialize()
    user = await repo.get_user_by_username("admin")
    assert user is not None
    assert verify_password("first", user["password_hash"])
    assert user["must_change_password"] is True or user["must_change_password"] == 1


@pytest.mark.asyncio
async def test_admin_password_resyncs_when_not_finalized(tmp_path, monkeypatch):
    db = str(tmp_path / "t.db")

    monkeypatch.setattr("decnet.web.db.sqlmodel_repo.DECNET_ADMIN_PASSWORD", "first")
    r1 = SQLiteRepository(db_path=db)
    await r1.initialize()

    monkeypatch.setattr("decnet.web.db.sqlmodel_repo.DECNET_ADMIN_PASSWORD", "second")
    r2 = SQLiteRepository(db_path=db)
    await r2.initialize()

    user = await r2.get_user_by_username("admin")
    assert verify_password("second", user["password_hash"])
    assert not verify_password("first", user["password_hash"])


@pytest.mark.asyncio
async def test_finalized_admin_password_is_preserved(tmp_path, monkeypatch):
    db = str(tmp_path / "t.db")

    monkeypatch.setattr("decnet.web.db.sqlmodel_repo.DECNET_ADMIN_PASSWORD", "seed")
    r1 = SQLiteRepository(db_path=db)
    await r1.initialize()
    admin = await r1.get_user_by_username("admin")
    # Simulate the admin finalising their password via the change-password flow.
    from decnet.web.auth import get_password_hash
    await r1.update_user_password(
        admin["uuid"], get_password_hash("chosen"), must_change_password=False
    )

    monkeypatch.setattr("decnet.web.db.sqlmodel_repo.DECNET_ADMIN_PASSWORD", "different")
    r2 = SQLiteRepository(db_path=db)
    await r2.initialize()

    user = await r2.get_user_by_username("admin")
    assert verify_password("chosen", user["password_hash"])
    assert not verify_password("different", user["password_hash"])
