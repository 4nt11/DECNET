"""
Tests for the attacker profile API routes.

Covers:
- GET /attackers: paginated list, search, sort_by
- GET /attackers/{uuid}: single profile detail, 404 on missing UUID
- Auth enforcement on both endpoints
"""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from decnet.web.auth import create_access_token


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _auth_request(uuid: str = "test-user-uuid") -> MagicMock:
    token = create_access_token({"uuid": uuid})
    req = MagicMock()
    req.headers = {"Authorization": f"Bearer {token}"}
    return req


def _sample_attacker(uuid: str = "att-uuid-1", ip: str = "1.2.3.4") -> dict:
    return {
        "uuid": uuid,
        "ip": ip,
        "first_seen": datetime(2026, 4, 1, tzinfo=timezone.utc).isoformat(),
        "last_seen": datetime(2026, 4, 10, tzinfo=timezone.utc).isoformat(),
        "event_count": 42,
        "service_count": 3,
        "decky_count": 2,
        "services": ["ssh", "http", "ftp"],
        "deckies": ["decky-01", "decky-02"],
        "traversal_path": "decky-01 → decky-02",
        "is_traversal": True,
        "bounty_count": 5,
        "credential_count": 2,
        "fingerprints": [{"type": "ja3", "hash": "abc"}],
        "commands": [{"service": "ssh", "decky": "decky-01", "command": "id", "timestamp": "2026-04-01T10:00:00"}],
        "updated_at": datetime(2026, 4, 10, tzinfo=timezone.utc).isoformat(),
    }


# ─── GET /attackers ──────────────────────────────────────────────────────────

class TestGetAttackers:
    @pytest.mark.asyncio
    async def test_returns_paginated_response(self):
        from decnet.web.router.attackers.api_get_attackers import get_attackers

        sample = _sample_attacker()
        with patch("decnet.web.router.attackers.api_get_attackers.repo") as mock_repo:
            mock_repo.get_attackers = AsyncMock(return_value=[sample])
            mock_repo.get_total_attackers = AsyncMock(return_value=1)

            result = await get_attackers(
                limit=50, offset=0, search=None, sort_by="recent",
                current_user="test-user",
            )

        assert result["total"] == 1
        assert result["limit"] == 50
        assert result["offset"] == 0
        assert len(result["data"]) == 1
        assert result["data"][0]["uuid"] == "att-uuid-1"

    @pytest.mark.asyncio
    async def test_search_parameter_forwarded(self):
        from decnet.web.router.attackers.api_get_attackers import get_attackers

        with patch("decnet.web.router.attackers.api_get_attackers.repo") as mock_repo:
            mock_repo.get_attackers = AsyncMock(return_value=[])
            mock_repo.get_total_attackers = AsyncMock(return_value=0)

            await get_attackers(
                limit=50, offset=0, search="192.168", sort_by="recent",
                current_user="test-user",
            )

        mock_repo.get_attackers.assert_awaited_once_with(
            limit=50, offset=0, search="192.168", sort_by="recent", service=None,
        )
        mock_repo.get_total_attackers.assert_awaited_once_with(search="192.168", service=None)

    @pytest.mark.asyncio
    async def test_null_search_normalized(self):
        from decnet.web.router.attackers.api_get_attackers import get_attackers

        with patch("decnet.web.router.attackers.api_get_attackers.repo") as mock_repo:
            mock_repo.get_attackers = AsyncMock(return_value=[])
            mock_repo.get_total_attackers = AsyncMock(return_value=0)

            await get_attackers(
                limit=50, offset=0, search="null", sort_by="recent",
                current_user="test-user",
            )

        mock_repo.get_attackers.assert_awaited_once_with(
            limit=50, offset=0, search=None, sort_by="recent", service=None,
        )

    @pytest.mark.asyncio
    async def test_sort_by_active(self):
        from decnet.web.router.attackers.api_get_attackers import get_attackers

        with patch("decnet.web.router.attackers.api_get_attackers.repo") as mock_repo:
            mock_repo.get_attackers = AsyncMock(return_value=[])
            mock_repo.get_total_attackers = AsyncMock(return_value=0)

            await get_attackers(
                limit=50, offset=0, search=None, sort_by="active",
                current_user="test-user",
            )

        mock_repo.get_attackers.assert_awaited_once_with(
            limit=50, offset=0, search=None, sort_by="active", service=None,
        )

    @pytest.mark.asyncio
    async def test_empty_search_normalized_to_none(self):
        from decnet.web.router.attackers.api_get_attackers import get_attackers

        with patch("decnet.web.router.attackers.api_get_attackers.repo") as mock_repo:
            mock_repo.get_attackers = AsyncMock(return_value=[])
            mock_repo.get_total_attackers = AsyncMock(return_value=0)

            await get_attackers(
                limit=50, offset=0, search="", sort_by="recent",
                current_user="test-user",
            )

        mock_repo.get_attackers.assert_awaited_once_with(
            limit=50, offset=0, search=None, sort_by="recent", service=None,
        )

    @pytest.mark.asyncio
    async def test_service_filter_forwarded(self):
        from decnet.web.router.attackers.api_get_attackers import get_attackers

        with patch("decnet.web.router.attackers.api_get_attackers.repo") as mock_repo:
            mock_repo.get_attackers = AsyncMock(return_value=[])
            mock_repo.get_total_attackers = AsyncMock(return_value=0)

            await get_attackers(
                limit=50, offset=0, search=None, sort_by="recent",
                service="https", current_user="test-user",
            )

        mock_repo.get_attackers.assert_awaited_once_with(
            limit=50, offset=0, search=None, sort_by="recent", service="https",
        )
        mock_repo.get_total_attackers.assert_awaited_once_with(search=None, service="https")


# ─── GET /attackers/{uuid} ───────────────────────────────────────────────────

class TestGetAttackerDetail:
    @pytest.mark.asyncio
    async def test_returns_attacker_by_uuid(self):
        from decnet.web.router.attackers.api_get_attacker_detail import get_attacker_detail

        sample = _sample_attacker()
        with patch("decnet.web.router.attackers.api_get_attacker_detail.repo") as mock_repo:
            mock_repo.get_attacker_by_uuid = AsyncMock(return_value=sample)

            result = await get_attacker_detail(uuid="att-uuid-1", current_user="test-user")

        assert result["uuid"] == "att-uuid-1"
        assert result["ip"] == "1.2.3.4"
        assert result["is_traversal"] is True
        assert isinstance(result["commands"], list)

    @pytest.mark.asyncio
    async def test_404_on_unknown_uuid(self):
        from decnet.web.router.attackers.api_get_attacker_detail import get_attacker_detail

        with patch("decnet.web.router.attackers.api_get_attacker_detail.repo") as mock_repo:
            mock_repo.get_attacker_by_uuid = AsyncMock(return_value=None)

            with pytest.raises(HTTPException) as exc_info:
                await get_attacker_detail(uuid="nonexistent", current_user="test-user")

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_deserialized_json_fields(self):
        from decnet.web.router.attackers.api_get_attacker_detail import get_attacker_detail

        sample = _sample_attacker()
        with patch("decnet.web.router.attackers.api_get_attacker_detail.repo") as mock_repo:
            mock_repo.get_attacker_by_uuid = AsyncMock(return_value=sample)

            result = await get_attacker_detail(uuid="att-uuid-1", current_user="test-user")

        assert isinstance(result["services"], list)
        assert isinstance(result["deckies"], list)
        assert isinstance(result["fingerprints"], list)
        assert isinstance(result["commands"], list)


# ─── Auth enforcement ────────────────────────────────────────────────────────

class TestAttackersAuth:
    @pytest.mark.asyncio
    async def test_list_requires_auth(self):
        """get_current_user dependency raises 401 when called without valid token."""
        from decnet.web.dependencies import get_current_user

        req = MagicMock()
        req.headers = {}

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(req)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_detail_requires_auth(self):
        from decnet.web.dependencies import get_current_user

        req = MagicMock()
        req.headers = {"Authorization": "Bearer bad-token"}

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(req)
        assert exc_info.value.status_code == 401
