# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the campaign-clustering read API.

Mirrors :mod:`tests.web.test_api_identities` for the layer above.
The campaign clusterer is a separate worker; these tests cover the
read-only API which ships in the same wave. Empty-table behaviour,
soft-merge resolution, and pagination forwarding are the headline
cases.
"""
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException


def _campaign_row(
    uuid: str = "c-uuid-1",
    merged_into_uuid: str | None = None,
    identity_count: int = 0,
) -> dict:
    now = datetime(2026, 4, 26, tzinfo=timezone.utc).isoformat()
    return {
        "uuid": uuid,
        "schema_version": 1,
        "first_seen_at": None,
        "last_seen_at": None,
        "created_at": now,
        "updated_at": now,
        "confidence": None,
        "identity_count": identity_count,
        "ja3_hashes": None,
        "hassh_hashes": None,
        "payload_simhashes": None,
        "c2_endpoints": None,
        "merged_into_uuid": merged_into_uuid,
        "notes": None,
    }


def _identity_row(uuid: str, campaign_id: str | None) -> dict:
    return {
        "uuid": uuid,
        "schema_version": 1,
        "campaign_id": campaign_id,
        "merged_into_uuid": None,
    }


# ─── GET /campaigns ──────────────────────────────────────────────────────────


class TestListCampaigns:
    @pytest.mark.asyncio
    async def test_empty_table_returns_zero_total(self):
        from decnet.web.router.campaigns.api_list_campaigns import list_campaigns

        with patch(
            "decnet.web.router.campaigns.api_list_campaigns.repo"
        ) as mock_repo:
            mock_repo.list_campaigns = AsyncMock(return_value=[])
            mock_repo.count_campaigns = AsyncMock(return_value=0)

            result = await list_campaigns(
                limit=50, offset=0, user={"uuid": "u", "role": "viewer"}
            )

        assert result == {"total": 0, "limit": 50, "offset": 0, "data": []}

    @pytest.mark.asyncio
    async def test_returns_seeded_data(self):
        from decnet.web.router.campaigns.api_list_campaigns import list_campaigns

        rows = [_campaign_row(f"c-{n}") for n in range(3)]
        with patch(
            "decnet.web.router.campaigns.api_list_campaigns.repo"
        ) as mock_repo:
            mock_repo.list_campaigns = AsyncMock(return_value=rows)
            mock_repo.count_campaigns = AsyncMock(return_value=3)

            result = await list_campaigns(
                limit=50, offset=0, user={"uuid": "u", "role": "viewer"}
            )

        assert result["total"] == 3
        assert [r["uuid"] for r in result["data"]] == ["c-0", "c-1", "c-2"]

    @pytest.mark.asyncio
    async def test_pagination_args_forwarded(self):
        from decnet.web.router.campaigns.api_list_campaigns import list_campaigns

        with patch(
            "decnet.web.router.campaigns.api_list_campaigns.repo"
        ) as mock_repo:
            mock_repo.list_campaigns = AsyncMock(return_value=[])
            mock_repo.count_campaigns = AsyncMock(return_value=0)

            await list_campaigns(
                limit=10, offset=20, user={"uuid": "u", "role": "viewer"}
            )

        mock_repo.list_campaigns.assert_awaited_once_with(limit=10, offset=20)


# ─── GET /campaigns/{uuid} ───────────────────────────────────────────────────


class TestGetCampaignDetail:
    @pytest.mark.asyncio
    async def test_404_on_missing_uuid(self):
        from decnet.web.router.campaigns.api_get_campaign_detail import (
            get_campaign_detail,
        )

        with patch(
            "decnet.web.router.campaigns.api_get_campaign_detail.repo"
        ) as mock_repo:
            mock_repo.get_campaign_by_uuid = AsyncMock(return_value=None)

            with pytest.raises(HTTPException) as exc:
                await get_campaign_detail(
                    uuid="ghost", user={"uuid": "u", "role": "viewer"}
                )
            assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_returns_campaign_with_live_identity_count(self):
        from decnet.web.router.campaigns.api_get_campaign_detail import (
            get_campaign_detail,
        )

        campaign = _campaign_row("c-real", identity_count=2)
        with patch(
            "decnet.web.router.campaigns.api_get_campaign_detail.repo"
        ) as mock_repo:
            mock_repo.get_campaign_by_uuid = AsyncMock(return_value=campaign)
            mock_repo.count_identities_for_campaign = AsyncMock(return_value=5)

            result = await get_campaign_detail(
                uuid="c-real", user={"uuid": "u", "role": "viewer"}
            )

        assert result["uuid"] == "c-real"
        assert result["identity_count_live"] == 5
        assert result["identity_count"] == 2


# ─── GET /campaigns/{uuid}/identities ────────────────────────────────────────


class TestListCampaignIdentities:
    @pytest.mark.asyncio
    async def test_404_when_campaign_missing(self):
        from decnet.web.router.campaigns.api_list_campaign_identities import (
            list_campaign_identities,
        )

        with patch(
            "decnet.web.router.campaigns.api_list_campaign_identities.repo"
        ) as mock_repo:
            mock_repo.get_campaign_by_uuid = AsyncMock(return_value=None)

            with pytest.raises(HTTPException) as exc:
                await list_campaign_identities(
                    uuid="ghost", limit=50, offset=0,
                    user={"uuid": "u", "role": "viewer"},
                )
            assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_returns_identities_for_existing_campaign(self):
        from decnet.web.router.campaigns.api_list_campaign_identities import (
            list_campaign_identities,
        )

        campaign = _campaign_row("c-real")
        idents = [
            _identity_row("i-1", "c-real"),
            _identity_row("i-2", "c-real"),
        ]
        with patch(
            "decnet.web.router.campaigns.api_list_campaign_identities.repo"
        ) as mock_repo:
            mock_repo.get_campaign_by_uuid = AsyncMock(return_value=campaign)
            mock_repo.list_identities_for_campaign = AsyncMock(return_value=idents)
            mock_repo.count_identities_for_campaign = AsyncMock(return_value=2)

            result = await list_campaign_identities(
                uuid="c-real", limit=50, offset=0,
                user={"uuid": "u", "role": "viewer"},
            )

        assert result["total"] == 2
        assert [r["uuid"] for r in result["data"]] == ["i-1", "i-2"]

    @pytest.mark.asyncio
    async def test_merged_uuid_resolves_to_winners_identities(self):
        """Soft-merged campaigns: identities are listed under the winner."""
        from decnet.web.router.campaigns.api_list_campaign_identities import (
            list_campaign_identities,
        )

        winner = _campaign_row("c-winner")
        with patch(
            "decnet.web.router.campaigns.api_list_campaign_identities.repo"
        ) as mock_repo:
            mock_repo.get_campaign_by_uuid = AsyncMock(return_value=winner)
            mock_repo.list_identities_for_campaign = AsyncMock(return_value=[])
            mock_repo.count_identities_for_campaign = AsyncMock(return_value=0)

            await list_campaign_identities(
                uuid="c-loser", limit=50, offset=0,
                user={"uuid": "u", "role": "viewer"},
            )

        mock_repo.list_identities_for_campaign.assert_awaited_once_with(
            "c-winner", limit=50, offset=0,
        )


# ─── Repo-level integration ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_repo_methods_against_empty_schema(tmp_path):
    from decnet.web.db.factory import get_repository

    repo = get_repository(db_path=str(tmp_path / "campaigns.db"))
    await repo.initialize()

    assert await repo.list_campaigns(limit=50, offset=0) == []
    assert await repo.count_campaigns() == 0
    assert await repo.get_campaign_by_uuid("anything") is None
    assert await repo.list_identities_for_campaign("anything") == []
    assert await repo.count_identities_for_campaign("anything") == 0


@pytest.mark.asyncio
async def test_repo_follows_campaign_merge_chain(tmp_path):
    from decnet.web.db.factory import get_repository

    repo = get_repository(db_path=str(tmp_path / "merge.db"))
    await repo.initialize()
    await repo.create_campaign({"uuid": "winner-uuid"})
    await repo.create_campaign(
        {"uuid": "loser-uuid", "merged_into_uuid": "winner-uuid"}
    )

    resolved = await repo.get_campaign_by_uuid("loser-uuid")
    assert resolved is not None
    assert resolved["uuid"] == "winner-uuid"

    direct = await repo.get_campaign_by_uuid("winner-uuid")
    assert direct["uuid"] == "winner-uuid"
    assert direct["merged_into_uuid"] is None
