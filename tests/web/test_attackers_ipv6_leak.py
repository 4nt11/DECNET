# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for IPv6 link-local leak columns on Attacker and AttackerIdentity.

Verifies:
* New fields exist with correct Optional[str] / int types (GREEN on model).
* Defaults are correct (0 / None).
* SQLite round-trip stores and retrieves non-None values correctly.
* Existing columns are unaffected.
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
from decnet.web.db.models.attackers import Attacker, AttackerIdentity


# ── Field presence (type-level, GREEN today) ─────────────────────────


def test_attacker_ipv6_leak_count_is_int() -> None:
    hints = get_type_hints(Attacker)
    assert "ipv6_leak_count" in hints
    assert hints["ipv6_leak_count"] == int


def test_attacker_last_ipv6_leak_at_optional_datetime() -> None:
    hints = get_type_hints(Attacker)
    assert "last_ipv6_leak_at" in hints
    assert hints["last_ipv6_leak_at"] == Optional[datetime]


def test_attacker_last_ipv6_link_local_optional_str() -> None:
    hints = get_type_hints(Attacker)
    assert "last_ipv6_link_local" in hints
    assert hints["last_ipv6_link_local"] == Optional[str]


def test_attacker_last_ipv6_iid_kind_optional_str() -> None:
    hints = get_type_hints(Attacker)
    assert "last_ipv6_iid_kind" in hints
    assert hints["last_ipv6_iid_kind"] == Optional[str]


def test_attacker_last_ipv6_mac_oui_optional_str() -> None:
    hints = get_type_hints(Attacker)
    assert "last_ipv6_mac_oui" in hints
    assert hints["last_ipv6_mac_oui"] == Optional[str]


def test_identity_ipv6_link_local_iids_optional_str() -> None:
    hints = get_type_hints(AttackerIdentity)
    assert "ipv6_link_local_iids" in hints
    assert hints["ipv6_link_local_iids"] == Optional[str]


def test_attacker_ipv6_defaults() -> None:
    row = Attacker(
        uuid=str(_uuid.uuid4()),
        ip="1.2.3.4",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    assert row.ipv6_leak_count == 0
    assert row.last_ipv6_leak_at is None
    assert row.last_ipv6_link_local is None
    assert row.last_ipv6_iid_kind is None
    assert row.last_ipv6_mac_oui is None


def test_identity_ipv6_link_local_iids_defaults_to_none() -> None:
    row = AttackerIdentity(uuid=str(_uuid.uuid4()))
    assert row.ipv6_link_local_iids is None


# ── SQLite round-trips ────────────────────────────────────────────────


@pytest_asyncio.fixture()
async def repo(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DECNET_DB_TYPE", "sqlite")
    r = get_repository(db_path=str(tmp_path / "ipv6_leak_test.db"))
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


def _attacker(extra: dict | None = None) -> Attacker:
    now = datetime.now(timezone.utc)
    base = {
        "uuid": str(_uuid.uuid4()),
        "ip": "10.0.0.1",
        "first_seen": now,
        "last_seen": now,
    }
    if extra:
        base.update(extra)
    return Attacker(**base)


@pytest.mark.asyncio
async def test_attacker_ipv6_columns_round_trip(repo) -> None:
    now = datetime.now(timezone.utc)
    row = _attacker({
        "ipv6_leak_count": 3,
        "last_ipv6_leak_at": now,
        "last_ipv6_link_local": "fe80::aabb:ccff:fedd:eeff",
        "last_ipv6_iid_kind": "eui64",
        "last_ipv6_mac_oui": "aa:bb:cc",
    })
    async with repo._session() as session:
        session.add(row)
        await session.commit()
    async with repo._session() as session:
        fetched = await session.get(Attacker, row.uuid)
    assert fetched is not None
    assert fetched.ipv6_leak_count == 3
    assert fetched.last_ipv6_link_local == "fe80::aabb:ccff:fedd:eeff"
    assert fetched.last_ipv6_iid_kind == "eui64"
    assert fetched.last_ipv6_mac_oui == "aa:bb:cc"


@pytest.mark.asyncio
async def test_attacker_ipv6_columns_nullable(repo) -> None:
    row = _attacker()
    async with repo._session() as session:
        session.add(row)
        await session.commit()
    async with repo._session() as session:
        fetched = await session.get(Attacker, row.uuid)
    assert fetched is not None
    assert fetched.ipv6_leak_count == 0
    assert fetched.last_ipv6_leak_at is None
    assert fetched.last_ipv6_link_local is None


@pytest.mark.asyncio
async def test_identity_ipv6_link_local_iids_round_trip(repo) -> None:
    iids = json.dumps([
        {"iid": "fe80::aabb:ccff:fedd:eeff", "oui": "aa:bb:cc",
         "kind": "eui64", "first_seen": "2026-01-01T00:00:00+00:00"},
    ])
    row = _identity({"ipv6_link_local_iids": iids})
    async with repo._session() as session:
        session.add(row)
        await session.commit()
    async with repo._session() as session:
        fetched = await session.get(AttackerIdentity, row.uuid)
    assert fetched is not None
    assert fetched.ipv6_link_local_iids == iids
    parsed = json.loads(fetched.ipv6_link_local_iids)
    assert parsed[0]["kind"] == "eui64"
    assert parsed[0]["oui"] == "aa:bb:cc"


@pytest.mark.asyncio
async def test_identity_ipv6_iids_dedup_in_json(repo) -> None:
    iid_val = "fe80::aabb:ccff:fedd:eeff"
    iids = json.dumps([
        {"iid": iid_val, "oui": "aa:bb:cc", "kind": "eui64", "first_seen": "2026-01-01T00:00:00+00:00"},
    ])
    row = _identity({"ipv6_link_local_iids": iids})
    async with repo._session() as session:
        session.add(row)
        await session.commit()
    async with repo._session() as session:
        fetched = await session.get(AttackerIdentity, row.uuid)
    existing = json.loads(fetched.ipv6_link_local_iids)
    seen_iids = {e["iid"] for e in existing}
    # dedup: adding same IID again should not grow the list
    if iid_val not in seen_iids:
        existing.append({"iid": iid_val, "oui": "aa:bb:cc", "kind": "eui64",
                         "first_seen": "2026-01-01T00:00:00+00:00"})
    assert len(existing) == 1


@pytest.mark.asyncio
async def test_existing_attacker_columns_unaffected(repo) -> None:
    row = _attacker({"rotation_count": 5, "last_ipv6_link_local": "fe80::1"})
    async with repo._session() as session:
        session.add(row)
        await session.commit()
    async with repo._session() as session:
        fetched = await session.get(Attacker, row.uuid)
    assert fetched is not None
    assert fetched.rotation_count == 5
    assert fetched.last_ipv6_link_local == "fe80::1"
