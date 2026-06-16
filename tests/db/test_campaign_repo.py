# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the Campaign clustering repo methods on SQLModelRepository."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "campaigns.db"))
    await r.initialize()
    return r


async def _create_identity(repo, uuid: str, **kwargs) -> str:
    now = datetime.now(timezone.utc)
    return await repo.create_attacker_identity({
        "uuid": uuid,
        "first_seen_at": kwargs.get("first_seen_at", now),
        "last_seen_at": kwargs.get("last_seen_at", now),
        "ja3_hashes": kwargs.get("ja3_hashes"),
        "hassh_hashes": kwargs.get("hassh_hashes"),
        "payload_simhashes": kwargs.get("payload_simhashes"),
        "c2_endpoints": kwargs.get("c2_endpoints"),
    })


@pytest.mark.asyncio
async def test_create_and_get_campaign(repo):
    await repo.create_campaign({"uuid": "c1", "confidence": 0.8})
    row = await repo.get_campaign_by_uuid("c1")
    assert row is not None
    assert row["uuid"] == "c1"
    assert row["confidence"] == 0.8
    assert row["merged_into_uuid"] is None


@pytest.mark.asyncio
async def test_get_campaign_follows_merge_chain(repo):
    await repo.create_campaign({"uuid": "c1"})
    await repo.create_campaign({"uuid": "c2"})
    await repo.update_campaign_merged_into("c2", "c1")

    # Querying the loser returns the winner.
    row = await repo.get_campaign_by_uuid("c2")
    assert row["uuid"] == "c1"


@pytest.mark.asyncio
async def test_list_and_count_excludes_merged_out(repo):
    await repo.create_campaign({"uuid": "c1"})
    await repo.create_campaign({"uuid": "c2"})
    await repo.update_campaign_merged_into("c2", "c1")

    listed = await repo.list_campaigns()
    assert {c["uuid"] for c in listed} == {"c1"}
    assert await repo.count_campaigns() == 1


@pytest.mark.asyncio
async def test_list_all_campaigns_includes_merged_out(repo):
    await repo.create_campaign({"uuid": "c1"})
    await repo.create_campaign({"uuid": "c2"})
    await repo.update_campaign_merged_into("c2", "c1")

    all_campaigns = await repo.list_all_campaigns()
    assert {c["uuid"] for c in all_campaigns} == {"c1", "c2"}


@pytest.mark.asyncio
async def test_get_unknown_campaign_returns_none(repo):
    assert await repo.get_campaign_by_uuid("nope") is None


@pytest.mark.asyncio
async def test_update_campaign_merged_into_can_revoke(repo):
    await repo.create_campaign({"uuid": "c1"})
    await repo.create_campaign({"uuid": "c2"})
    await repo.update_campaign_merged_into("c2", "c1")
    # Revoke
    await repo.update_campaign_merged_into("c2", None)

    row = await repo.get_campaign_by_uuid("c2")
    assert row["uuid"] == "c2"
    assert row["merged_into_uuid"] is None


@pytest.mark.asyncio
async def test_set_identity_campaign_id_links_and_unlinks(repo):
    await repo.create_campaign({"uuid": "c1"})
    await _create_identity(repo, "i1")

    await repo.set_identity_campaign_id("i1", "c1")
    linked = await repo.list_identities_for_campaign("c1")
    assert {i["uuid"] for i in linked} == {"i1"}
    assert await repo.count_identities_for_campaign("c1") == 1

    await repo.set_identity_campaign_id("i1", None)
    assert await repo.count_identities_for_campaign("c1") == 0


@pytest.mark.asyncio
async def test_list_identities_for_clustering_projects_expected_fields(repo):
    await _create_identity(
        repo, "i1",
        ja3_hashes='["ja3-a"]',
        hassh_hashes='["hassh-a"]',
        payload_simhashes='["dead"]',
        c2_endpoints='["1.2.3.4:443"]',
    )
    rows = await repo.list_identities_for_clustering()
    assert len(rows) == 1
    row = rows[0]
    assert row["uuid"] == "i1"
    assert row["ja3_hashes"] == '["ja3-a"]'
    assert row["hassh_hashes"] == '["hassh-a"]'
    assert row["payload_simhashes"] == '["dead"]'
    assert row["c2_endpoints"] == '["1.2.3.4:443"]'
    assert row["campaign_id"] is None
    assert row["merged_into_uuid"] is None
    assert row["first_seen_at"] is not None


@pytest.mark.asyncio
async def test_list_identities_for_clustering_respects_limit(repo):
    for n in range(3):
        await _create_identity(repo, f"i{n}")
    assert len(await repo.list_identities_for_clustering(limit=2)) == 2
    assert len(await repo.list_identities_for_clustering()) == 3


@pytest.mark.asyncio
async def test_list_identities_for_campaign_paginates(repo):
    await repo.create_campaign({"uuid": "c1"})
    for n in range(3):
        await _create_identity(repo, f"i{n}")
        await repo.set_identity_campaign_id(f"i{n}", "c1")

    page = await repo.list_identities_for_campaign("c1", limit=2, offset=0)
    assert len(page) == 2
    page2 = await repo.list_identities_for_campaign("c1", limit=2, offset=2)
    assert len(page2) == 1
