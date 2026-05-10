"""Round-trip tests for the three PR2 fingerprint columns on AttackerIdentity.

Verifies:
* ``ja4h_hashes``, ``ja4_quic_hashes``, ``http_versions_seen`` exist as
  Optional[str] fields on the model (type-level, GREEN today).
* A full SQLite round-trip stores and retrieves non-None values correctly.
* Columns default to None and don't affect existing columns.
"""
from __future__ import annotations

import json
import uuid as _uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, get_type_hints

import pytest
import pytest_asyncio

from decnet.web.db.factory import get_repository
from decnet.web.db.models.attackers import AttackerIdentity


# ── Field presence (type-level, GREEN today) ─────────────────────────


def test_ja4h_hashes_field_is_optional_str() -> None:
    hints = get_type_hints(AttackerIdentity)
    # Optional[str] == Union[str, None], repr varies by Python version
    assert "ja4h_hashes" in hints
    h = hints["ja4h_hashes"]
    assert h == Optional[str], f"unexpected type: {h}"


def test_ja4_quic_hashes_field_is_optional_str() -> None:
    hints = get_type_hints(AttackerIdentity)
    assert "ja4_quic_hashes" in hints
    h = hints["ja4_quic_hashes"]
    assert h == Optional[str], f"unexpected type: {h}"


def test_http_versions_seen_field_is_optional_str() -> None:
    hints = get_type_hints(AttackerIdentity)
    assert "http_versions_seen" in hints
    h = hints["http_versions_seen"]
    assert h == Optional[str], f"unexpected type: {h}"


def test_new_columns_default_to_none() -> None:
    row = AttackerIdentity(uuid=str(_uuid.uuid4()))
    assert row.ja4h_hashes is None
    assert row.ja4_quic_hashes is None
    assert row.http_versions_seen is None


# ── SQLite round-trip ─────────────────────────────────────────────────


@pytest_asyncio.fixture()
async def repo(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DECNET_DB_TYPE", "sqlite")
    r = get_repository(db_path=str(tmp_path / "fp_col_test.db"))
    await r.initialize()
    try:
        yield r
    finally:
        engine = getattr(r, "engine", None)
        if engine is not None:
            try:
                await engine.dispose()
            except Exception:
                pass


def _identity(extra: dict | None = None) -> AttackerIdentity:
    base = {
        "uuid": str(_uuid.uuid4()),
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    if extra:
        base.update(extra)
    return AttackerIdentity(**base)


@pytest.mark.asyncio
async def test_ja4h_hashes_round_trip(repo) -> None:
    value = json.dumps(["GE11nn0000_02_abc_000", "GE20nn0000_04_def_000"])
    row = _identity({"ja4h_hashes": value})
    async with repo._session() as session:
        session.add(row)
        await session.commit()
    async with repo._session() as session:
        fetched = await session.get(AttackerIdentity, row.uuid)
    assert fetched is not None
    assert fetched.ja4h_hashes == value
    assert json.loads(fetched.ja4h_hashes) == json.loads(value)


@pytest.mark.asyncio
async def test_ja4_quic_hashes_round_trip(repo) -> None:
    value = json.dumps(["q13d0310h2_002f_0403_h3"])
    row = _identity({"ja4_quic_hashes": value})
    async with repo._session() as session:
        session.add(row)
        await session.commit()
    async with repo._session() as session:
        fetched = await session.get(AttackerIdentity, row.uuid)
    assert fetched is not None
    assert fetched.ja4_quic_hashes == value


@pytest.mark.asyncio
async def test_http_versions_seen_round_trip(repo) -> None:
    value = "h1\nh2\nh3"
    row = _identity({"http_versions_seen": value})
    async with repo._session() as session:
        session.add(row)
        await session.commit()
    async with repo._session() as session:
        fetched = await session.get(AttackerIdentity, row.uuid)
    assert fetched is not None
    assert fetched.http_versions_seen == value


@pytest.mark.asyncio
async def test_new_columns_nullable_when_not_set(repo) -> None:
    row = _identity()  # no fp columns set
    async with repo._session() as session:
        session.add(row)
        await session.commit()
    async with repo._session() as session:
        fetched = await session.get(AttackerIdentity, row.uuid)
    assert fetched is not None
    assert fetched.ja4h_hashes is None
    assert fetched.ja4_quic_hashes is None
    assert fetched.http_versions_seen is None


@pytest.mark.asyncio
async def test_existing_columns_unaffected(repo) -> None:
    ja3 = json.dumps(["abc123"])
    row = _identity({"ja3_hashes": ja3, "ja4h_hashes": json.dumps(["fp1"])})
    async with repo._session() as session:
        session.add(row)
        await session.commit()
    async with repo._session() as session:
        fetched = await session.get(AttackerIdentity, row.uuid)
    assert fetched is not None
    assert fetched.ja3_hashes == ja3
    assert fetched.ja4h_hashes == json.dumps(["fp1"])
    assert fetched.ja4_quic_hashes is None
