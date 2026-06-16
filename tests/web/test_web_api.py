# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Tests for decnet/web/api.py lifespan and decnet/web/dependencies.py auth helpers.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from decnet.web.auth import create_access_token


# ── get_current_user ──────────────────────────────────────────────────────────

class TestGetCurrentUser:
    @pytest.mark.asyncio
    async def test_valid_token(self):
        # Post token-revocation, get_current_user resolves the user and checks
        # the denylist, so a valid token must carry a jti, name a live user, and
        # not be revoked.
        from decnet.web import dependencies as deps
        from decnet.web.dependencies import get_current_user
        deps._reset_user_cache()
        token = create_access_token({"uuid": "test-uuid-123", "jti": "jti-1"})
        request = MagicMock()
        request.headers = {"Authorization": f"Bearer {token}"}
        user = {
            "uuid": "test-uuid-123", "role": "viewer",
            "must_change_password": False, "tokens_valid_from": None,
        }
        with patch.object(deps.repo, "get_user_by_uuid", AsyncMock(return_value=user)), \
             patch.object(deps.repo, "is_token_revoked", AsyncMock(return_value=False)):
            result = await get_current_user(request)
        assert result == "test-uuid-123"

    @pytest.mark.asyncio
    async def test_no_auth_header(self):
        from fastapi import HTTPException
        from decnet.web.dependencies import get_current_user
        request = MagicMock()
        request.headers = {}
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(request)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_jwt(self):
        from fastapi import HTTPException
        from decnet.web.dependencies import get_current_user
        request = MagicMock()
        request.headers = {"Authorization": "Bearer invalid-token"}
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(request)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_uuid_in_payload(self):
        from fastapi import HTTPException
        from decnet.web.dependencies import get_current_user
        token = create_access_token({"sub": "no-uuid-field"})
        request = MagicMock()
        request.headers = {"Authorization": f"Bearer {token}"}
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(request)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_bearer_prefix_required(self):
        from fastapi import HTTPException
        from decnet.web.dependencies import get_current_user
        token = create_access_token({"uuid": "test-uuid"})
        request = MagicMock()
        request.headers = {"Authorization": f"Token {token}"}
        with pytest.raises(HTTPException):
            await get_current_user(request)


# ── web/api.py lifespan ──────────────────────────────────────────────────────

class TestLifespan:
    @pytest.mark.asyncio
    async def test_lifespan_startup_and_shutdown(self):
        from decnet.web.api import lifespan
        mock_app = MagicMock()
        mock_repo = MagicMock()
        mock_repo.initialize = AsyncMock()

        with patch("decnet.web.api.repo", mock_repo):
            with patch("decnet.web.api.log_ingestion_worker", return_value=asyncio.sleep(0)):
                with patch("decnet.web.api.log_collector_worker", return_value=asyncio.sleep(0)):
                    with patch("decnet.web.api.attacker_profile_worker", return_value=asyncio.sleep(0)):
                        with patch("decnet.web.api.tarpit_watcher_worker", return_value=asyncio.sleep(0)):
                            async with lifespan(mock_app):
                                mock_repo.initialize.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_lifespan_db_retry(self):
        from decnet.web.api import lifespan
        mock_app = MagicMock()
        mock_repo = MagicMock()
        _call_count: int = 0

        async def _failing_init():
            nonlocal _call_count
            _call_count += 1
            if _call_count < 3:
                raise Exception("DB locked")

        mock_repo.initialize = _failing_init

        with patch("decnet.web.api.repo", mock_repo):
            # Patch only the local _retry_sleep binding — patching
            # `asyncio.sleep` globally would starve the heartbeat loop's
            # own sleep and leak the task past the test's lifetime.
            with patch("decnet.web.api._retry_sleep", new_callable=AsyncMock):
                with patch("decnet.web.api.log_ingestion_worker", return_value=asyncio.sleep(0)):
                    with patch("decnet.web.api.log_collector_worker", return_value=asyncio.sleep(0)):
                        with patch("decnet.web.api.attacker_profile_worker", return_value=asyncio.sleep(0)):
                            with patch("decnet.web.api.tarpit_watcher_worker", return_value=asyncio.sleep(0)):
                                async with lifespan(mock_app):
                                    assert _call_count == 3
