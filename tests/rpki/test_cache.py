# SPDX-License-Identifier: AGPL-3.0-or-later
"""SQLite RPKI cache tests."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from decnet.rpki.cache import TTL_S, get, open_db, prune, put


@pytest.fixture()
def db(tmp_path: Path):
    return open_db(tmp_path / "rpki.db")


def test_miss_returns_none(db) -> None:
    assert get(db, "8.8.8.8") is None


def test_put_then_get_returns_entry(db) -> None:
    put(db, "8.8.8.8", 15169, "valid", "8.8.8.0/24")
    result = get(db, "8.8.8.8")
    assert result == ("valid", "8.8.8.0/24")


def test_get_returns_none_prefix_when_stored_null(db) -> None:
    put(db, "1.2.3.4", 64496, "not-found", None)
    status, prefix = get(db, "1.2.3.4")
    assert status == "not-found"
    assert prefix is None


def test_expired_entry_returns_none(db, monkeypatch: pytest.MonkeyPatch) -> None:
    put(db, "8.8.8.8", 15169, "valid", "8.8.8.0/24")
    future = time.time() + TTL_S + 1
    monkeypatch.setattr("decnet.rpki.cache.time.time", lambda: future)
    assert get(db, "8.8.8.8") is None


def test_replace_updates_entry(db) -> None:
    put(db, "8.8.8.8", 15169, "valid", "8.8.8.0/24")
    put(db, "8.8.8.8", 15169, "invalid", "8.8.8.0/24")
    status, _ = get(db, "8.8.8.8")
    assert status == "invalid"


def test_prune_removes_stale_rows(db, monkeypatch: pytest.MonkeyPatch) -> None:
    put(db, "1.1.1.1", 13335, "valid", "1.1.1.0/24")
    put(db, "2.2.2.2", 3215, "invalid", "2.0.0.0/8")
    future = time.time() + TTL_S + 1
    monkeypatch.setattr("decnet.rpki.cache.time.time", lambda: future)
    count = prune(db)
    assert count == 2
    # After prune, both gone
    assert get(db, "1.1.1.1") is None
    assert get(db, "2.2.2.2") is None


def test_prune_keeps_fresh_rows(db) -> None:
    put(db, "8.8.8.8", 15169, "valid", "8.8.8.0/24")
    count = prune(db)
    assert count == 0
    assert get(db, "8.8.8.8") is not None
