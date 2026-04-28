"""
Tests for the identity-resolution read API.

The clusterer that populates identities is a separate downstream effort
(see development/IDENTITY_RESOLUTION.md); these tests cover the
read-only API that ships first. The identities table is empty at
deployment time, so the headline cases are:

* GET /identities returns {total: 0, data: []} cleanly
* GET /identities/{uuid} returns 404 cleanly
* GET /identities/{uuid}/observations returns 404 if identity missing
* with seeded data, the routes return what the repository returns
* a soft-merged identity (merged_into_uuid set) resolves to the winner
"""
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _identity_row(
    uuid: str = "id-uuid-1",
    merged_into_uuid: str | None = None,
    observation_count: int = 0,
) -> dict:
    now = datetime(2026, 4, 26, tzinfo=timezone.utc).isoformat()
    return {
        "uuid": uuid,
        "schema_version": 1,
        "campaign_id": None,
        "first_seen_at": None,
        "last_seen_at": None,
        "created_at": now,
        "updated_at": now,
        "confidence": None,
        "observation_count": observation_count,
        "ja3_hashes": None,
        "hassh_hashes": None,
        "payload_simhashes": None,
        "c2_endpoints": None,
        "kd_digraph_simhash": None,
        "merged_into_uuid": merged_into_uuid,
        "notes": None,
    }


def _observation_row(uuid: str, identity_id: str | None) -> dict:
    return {
        "uuid": uuid,
        "ip": "203.0.113.7",
        "identity_id": identity_id,
        "first_seen": datetime(2026, 4, 1, tzinfo=timezone.utc).isoformat(),
        "last_seen": datetime(2026, 4, 26, tzinfo=timezone.utc).isoformat(),
        "event_count": 5,
    }


# ─── GET /identities ─────────────────────────────────────────────────────────


class TestListIdentities:
    @pytest.mark.asyncio
    async def test_empty_table_returns_zero_total(self):
        from decnet.web.router.identities.api_list_identities import list_identities

        with patch(
            "decnet.web.router.identities.api_list_identities.repo"
        ) as mock_repo:
            mock_repo.list_identities = AsyncMock(return_value=[])
            mock_repo.count_identities = AsyncMock(return_value=0)

            result = await list_identities(
                limit=50, offset=0, user={"uuid": "u", "role": "viewer"}
            )

        assert result == {"total": 0, "limit": 50, "offset": 0, "data": []}

    @pytest.mark.asyncio
    async def test_returns_seeded_data(self):
        from decnet.web.router.identities.api_list_identities import list_identities

        rows = [_identity_row(f"id-{n}") for n in range(3)]
        with patch(
            "decnet.web.router.identities.api_list_identities.repo"
        ) as mock_repo:
            mock_repo.list_identities = AsyncMock(return_value=rows)
            mock_repo.count_identities = AsyncMock(return_value=3)

            result = await list_identities(
                limit=50, offset=0, user={"uuid": "u", "role": "viewer"}
            )

        assert result["total"] == 3
        assert [r["uuid"] for r in result["data"]] == ["id-0", "id-1", "id-2"]

    @pytest.mark.asyncio
    async def test_pagination_args_forwarded(self):
        from decnet.web.router.identities.api_list_identities import list_identities

        with patch(
            "decnet.web.router.identities.api_list_identities.repo"
        ) as mock_repo:
            mock_repo.list_identities = AsyncMock(return_value=[])
            mock_repo.count_identities = AsyncMock(return_value=0)

            await list_identities(
                limit=10, offset=20, user={"uuid": "u", "role": "viewer"}
            )

        mock_repo.list_identities.assert_awaited_once_with(limit=10, offset=20)


# ─── GET /identities/{uuid} ──────────────────────────────────────────────────


class TestGetIdentityDetail:
    @pytest.mark.asyncio
    async def test_404_on_missing_uuid(self):
        from decnet.web.router.identities.api_get_identity_detail import (
            get_identity_detail,
        )

        with patch(
            "decnet.web.router.identities.api_get_identity_detail.repo"
        ) as mock_repo:
            mock_repo.get_identity_by_uuid = AsyncMock(return_value=None)

            with pytest.raises(HTTPException) as exc:
                await get_identity_detail(
                    uuid="ghost", user={"uuid": "u", "role": "viewer"}
                )
            assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_returns_identity_with_live_observation_count(self):
        from decnet.web.router.identities.api_get_identity_detail import (
            get_identity_detail,
        )

        identity = _identity_row("id-real", observation_count=2)
        with patch(
            "decnet.web.router.identities.api_get_identity_detail.repo"
        ) as mock_repo:
            mock_repo.get_identity_by_uuid = AsyncMock(return_value=identity)
            # Live count overrides the (potentially stale) denormalized
            # observation_count on the row.
            mock_repo.count_observations_for_identity = AsyncMock(return_value=5)

            result = await get_identity_detail(
                uuid="id-real", user={"uuid": "u", "role": "viewer"}
            )

        assert result["uuid"] == "id-real"
        assert result["observation_count_live"] == 5
        # Original denormalized count is preserved on the row.
        assert result["observation_count"] == 2


# ─── GET /identities/{uuid}/observations ─────────────────────────────────────


class TestListIdentityObservations:
    @pytest.mark.asyncio
    async def test_404_when_identity_missing(self):
        from decnet.web.router.identities.api_list_identity_observations import (
            list_identity_observations,
        )

        with patch(
            "decnet.web.router.identities.api_list_identity_observations.repo"
        ) as mock_repo:
            mock_repo.get_identity_by_uuid = AsyncMock(return_value=None)

            with pytest.raises(HTTPException) as exc:
                await list_identity_observations(
                    uuid="ghost",
                    limit=50,
                    offset=0,
                    user={"uuid": "u", "role": "viewer"},
                )
            assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_returns_observations_for_existing_identity(self):
        from decnet.web.router.identities.api_list_identity_observations import (
            list_identity_observations,
        )

        identity = _identity_row("id-real")
        observations = [
            _observation_row("att-1", identity_id="id-real"),
            _observation_row("att-2", identity_id="id-real"),
        ]
        with patch(
            "decnet.web.router.identities.api_list_identity_observations.repo"
        ) as mock_repo:
            mock_repo.get_identity_by_uuid = AsyncMock(return_value=identity)
            mock_repo.list_observations_for_identity = AsyncMock(
                return_value=observations
            )
            mock_repo.count_observations_for_identity = AsyncMock(return_value=2)

            result = await list_identity_observations(
                uuid="id-real",
                limit=50,
                offset=0,
                user={"uuid": "u", "role": "viewer"},
            )

        assert result["total"] == 2
        assert [r["uuid"] for r in result["data"]] == ["att-1", "att-2"]

    @pytest.mark.asyncio
    async def test_merged_uuid_resolves_to_winners_observations(self):
        """
        When the user requests observations for a soft-merged identity,
        get_identity_by_uuid follows the merged_into chain and returns
        the winner. The endpoint MUST list observations under the
        winner's UUID, not the loser's. Otherwise an operator linking
        through cached merge events sees an empty page.
        """
        from decnet.web.router.identities.api_list_identity_observations import (
            list_identity_observations,
        )

        # Repo returns the WINNER row even though we asked for the loser's uuid.
        winner = _identity_row("id-winner")
        with patch(
            "decnet.web.router.identities.api_list_identity_observations.repo"
        ) as mock_repo:
            mock_repo.get_identity_by_uuid = AsyncMock(return_value=winner)
            mock_repo.list_observations_for_identity = AsyncMock(return_value=[])
            mock_repo.count_observations_for_identity = AsyncMock(return_value=0)

            await list_identity_observations(
                uuid="id-loser",
                limit=50,
                offset=0,
                user={"uuid": "u", "role": "viewer"},
            )

        # Critical assertion: list_observations_for_identity is called
        # with the winner's UUID, not the requested (loser's) one.
        mock_repo.list_observations_for_identity.assert_awaited_once_with(
            "id-winner", limit=50, offset=0
        )


# ─── Repo-level integration: empty schema returns expected shapes ────────────


@pytest.mark.asyncio
async def test_repo_methods_against_empty_schema(tmp_path):
    """
    With a freshly initialized SQLite database (no rows), every read
    method returns the expected empty/None response. Smoke-tests the
    repository layer without going through the FastAPI route layer.
    """
    from decnet.web.db.sqlite.repository import SQLiteRepository
    from decnet.web.db.sqlite.database import init_db

    db_path = str(tmp_path / "ids.db")
    init_db(db_path)
    repo = SQLiteRepository(db_path=db_path)

    assert await repo.list_identities(limit=50, offset=0) == []
    assert await repo.count_identities() == 0
    assert await repo.get_identity_by_uuid("anything") is None
    assert await repo.list_observations_for_identity("anything") == []
    assert await repo.count_observations_for_identity("anything") == 0


@pytest.mark.asyncio
async def test_repo_follows_merged_into_chain(tmp_path):
    """
    get_identity_by_uuid must transparently follow merged_into_uuid to
    surface the canonical winner. This is the contract the endpoint
    relies on for soft-merged identity resolution.
    """
    from decnet.web.db.models import AttackerIdentity
    from decnet.web.db.sqlite.database import init_db
    from decnet.web.db.sqlite.repository import SQLiteRepository
    from sqlmodel import Session
    from decnet.web.db.sqlite.database import get_sync_engine

    db_path = str(tmp_path / "merge.db")
    init_db(db_path)

    # Insert two identities via direct SQL: a winner and a loser whose
    # merged_into_uuid points at the winner.
    engine = get_sync_engine(db_path)
    with Session(engine) as session:
        winner = AttackerIdentity(uuid="winner-uuid")
        loser = AttackerIdentity(uuid="loser-uuid", merged_into_uuid="winner-uuid")
        session.add(winner)
        session.add(loser)
        session.commit()

    repo = SQLiteRepository(db_path=db_path)
    resolved = await repo.get_identity_by_uuid("loser-uuid")
    assert resolved is not None
    assert resolved["uuid"] == "winner-uuid", (
        "get_identity_by_uuid must follow merged_into_uuid to the winner"
    )

    # And the winner queried directly resolves to itself.
    direct = await repo.get_identity_by_uuid("winner-uuid")
    assert direct["uuid"] == "winner-uuid"
    assert direct["merged_into_uuid"] is None
