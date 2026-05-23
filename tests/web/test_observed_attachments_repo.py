# SPDX-License-Identifier: AGPL-3.0-or-later
"""Repo tests for ``observed_attachments`` upsert (DEBT-046).

The table is the per-hash sibling of ``attacker_intel`` — every
attachment hash crossing a decky lands here, with metadata accumulated
across observations.
"""
from __future__ import annotations

import pytest

from decnet.web.db.sqlite.repository import SQLiteRepository

_HASH_A = "a" * 64
_HASH_B = "b" * 64


async def _make_repo(tmp_path) -> SQLiteRepository:
    r = SQLiteRepository(db_path=str(tmp_path / "obs.db"))
    await r.initialize()
    return r


@pytest.mark.asyncio
async def test_first_observation_creates_row(tmp_path):
    repo = await _make_repo(tmp_path)
    uuid = await repo.upsert_observed_attachment(
        sha256=_HASH_A.upper(),  # provider may pass mixed-case
        decky_uuid="d-1",
        attacker_uuid="atk-1",
        extension="DOCX",
        subject="Invoice",
        mal_hash_match=False,
        mal_hash_match_provider="malwarebazaar",
    )
    assert uuid

    from decnet.web.db.models import ObservedAttachment
    from sqlalchemy import select
    async with repo._session() as session:
        row = (
            await session.execute(
                select(ObservedAttachment).where(
                    ObservedAttachment.sha256 == _HASH_A,
                ),
            )
        ).scalar_one()
    assert row.sha256 == _HASH_A  # lowercased
    assert row.observation_count == 1
    assert row.first_seen_decky_uuid == "d-1"
    assert row.first_seen_attacker_uuid == "atk-1"
    assert row.last_seen_attacker_uuid == "atk-1"
    assert row.extensions == ["docx"]
    assert row.first_subject == "Invoice"
    assert row.mal_hash_match is False
    assert row.mal_hash_match_provider == "malwarebazaar"
    assert row.mal_hash_match_at is not None


@pytest.mark.asyncio
async def test_re_observation_increments_and_updates_last_seen(tmp_path):
    repo = await _make_repo(tmp_path)
    await repo.upsert_observed_attachment(
        sha256=_HASH_A, decky_uuid="d-1", attacker_uuid="atk-1",
        extension="docx", subject="Old subject",
        mal_hash_match=None, mal_hash_match_provider=None,
    )
    await repo.upsert_observed_attachment(
        sha256=_HASH_A, decky_uuid="d-2", attacker_uuid="atk-2",
        extension="docx", subject="New subject",
        mal_hash_match=None, mal_hash_match_provider=None,
    )

    from decnet.web.db.models import ObservedAttachment
    from sqlalchemy import select
    async with repo._session() as session:
        row = (
            await session.execute(
                select(ObservedAttachment).where(
                    ObservedAttachment.sha256 == _HASH_A,
                ),
            )
        ).scalar_one()
    assert row.observation_count == 2
    # First-seen anchors stay pinned; last-seen attacker rolls forward.
    assert row.first_seen_decky_uuid == "d-1"
    assert row.first_seen_attacker_uuid == "atk-1"
    assert row.last_seen_attacker_uuid == "atk-2"
    # Subject is the FIRST subject; not overwritten.
    assert row.first_subject == "Old subject"
    # Extension already known — no duplicate.
    assert row.extensions == ["docx"]


@pytest.mark.asyncio
async def test_distinct_extension_appends_deduped(tmp_path):
    repo = await _make_repo(tmp_path)
    await repo.upsert_observed_attachment(
        sha256=_HASH_A, decky_uuid="d", attacker_uuid="a",
        extension="docx", subject=None,
        mal_hash_match=None, mal_hash_match_provider=None,
    )
    await repo.upsert_observed_attachment(
        sha256=_HASH_A, decky_uuid="d", attacker_uuid="a",
        extension="DOC",  # different ext, mixed case
        subject=None, mal_hash_match=None, mal_hash_match_provider=None,
    )
    await repo.upsert_observed_attachment(
        sha256=_HASH_A, decky_uuid="d", attacker_uuid="a",
        extension="doc",  # repeat → no-op
        subject=None, mal_hash_match=None, mal_hash_match_provider=None,
    )

    from decnet.web.db.models import ObservedAttachment
    from sqlalchemy import select
    async with repo._session() as session:
        row = (
            await session.execute(
                select(ObservedAttachment).where(
                    ObservedAttachment.sha256 == _HASH_A,
                ),
            )
        ).scalar_one()
    assert sorted(row.extensions) == ["doc", "docx"]


@pytest.mark.asyncio
async def test_verdict_true_is_sticky(tmp_path):
    """Once any provider says True, subsequent None/False observations
    don't downgrade. A hash a feed later forgets is still a hash that
    feed once flagged."""
    repo = await _make_repo(tmp_path)
    await repo.upsert_observed_attachment(
        sha256=_HASH_A, decky_uuid="d", attacker_uuid="a",
        extension=None, subject=None,
        mal_hash_match=True, mal_hash_match_provider="malwarebazaar",
    )
    await repo.upsert_observed_attachment(
        sha256=_HASH_A, decky_uuid="d", attacker_uuid="a",
        extension=None, subject=None,
        mal_hash_match=False, mal_hash_match_provider="malwarebazaar",
    )
    await repo.upsert_observed_attachment(
        sha256=_HASH_A, decky_uuid="d", attacker_uuid="a",
        extension=None, subject=None,
        mal_hash_match=None, mal_hash_match_provider=None,
    )

    from decnet.web.db.models import ObservedAttachment
    from sqlalchemy import select
    async with repo._session() as session:
        row = (
            await session.execute(
                select(ObservedAttachment).where(
                    ObservedAttachment.sha256 == _HASH_A,
                ),
            )
        ).scalar_one()
    assert row.mal_hash_match is True
    assert row.mal_hash_match_provider == "malwarebazaar"


@pytest.mark.asyncio
async def test_verdict_none_then_true_writes_through(tmp_path):
    repo = await _make_repo(tmp_path)
    await repo.upsert_observed_attachment(
        sha256=_HASH_B, decky_uuid="d", attacker_uuid="a",
        extension=None, subject=None,
        mal_hash_match=None, mal_hash_match_provider=None,
    )
    await repo.upsert_observed_attachment(
        sha256=_HASH_B, decky_uuid="d", attacker_uuid="a",
        extension=None, subject=None,
        mal_hash_match=True, mal_hash_match_provider="malwarebazaar",
    )

    from decnet.web.db.models import ObservedAttachment
    from sqlalchemy import select
    async with repo._session() as session:
        row = (
            await session.execute(
                select(ObservedAttachment).where(
                    ObservedAttachment.sha256 == _HASH_B,
                ),
            )
        ).scalar_one()
    assert row.mal_hash_match is True
    assert row.mal_hash_match_provider == "malwarebazaar"
