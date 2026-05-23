# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for the repository factory — dispatch on DECNET_DB_TYPE.
"""
import pytest

from decnet.web.db.factory import get_repository
from decnet.web.db.sqlite.repository import SQLiteRepository
from decnet.web.db.mysql.repository import MySQLRepository


def test_factory_defaults_to_sqlite(monkeypatch, tmp_path):
    monkeypatch.delenv("DECNET_DB_TYPE", raising=False)
    repo = get_repository(db_path=str(tmp_path / "t.db"))
    assert isinstance(repo, SQLiteRepository)


def test_factory_sqlite_explicit(monkeypatch, tmp_path):
    monkeypatch.setenv("DECNET_DB_TYPE", "sqlite")
    repo = get_repository(db_path=str(tmp_path / "t.db"))
    assert isinstance(repo, SQLiteRepository)


def test_factory_mysql_branch(monkeypatch):
    """MySQL branch must import and instantiate without a live server.

    Engine creation is lazy in SQLAlchemy — no socket is opened until the
    first query — so the repository constructs cleanly here.
    """
    monkeypatch.setenv("DECNET_DB_TYPE", "mysql")
    monkeypatch.setenv("DECNET_DB_URL", "mysql+asyncmy://u:p@127.0.0.1:3306/x")
    repo = get_repository()
    assert isinstance(repo, MySQLRepository)


def test_factory_is_case_insensitive(monkeypatch, tmp_path):
    monkeypatch.setenv("DECNET_DB_TYPE", "SQLite")
    repo = get_repository(db_path=str(tmp_path / "t.db"))
    assert isinstance(repo, SQLiteRepository)


def test_factory_rejects_unknown_type(monkeypatch):
    monkeypatch.setenv("DECNET_DB_TYPE", "cassandra")
    with pytest.raises(ValueError, match="Unsupported database type"):
        get_repository()
