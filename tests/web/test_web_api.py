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
        from decnet.web.dependencies import get_current_user
        token = create_access_token({"uuid": "test-uuid-123"})
        request = MagicMock()
        request.headers = {"Authorization": f"Bearer {token}"}
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


# ── get_stream_user ───────────────────────────────────────────────────────────

class TestGetStreamUser:
    @pytest.mark.asyncio
    async def test_bearer_header(self):
        from decnet.web.dependencies import get_stream_user
        token = create_access_token({"uuid": "stream-uuid"})
        request = MagicMock()
        request.headers = {"Authorization": f"Bearer {token}"}
        result = await get_stream_user(request, token=None)
        assert result == "stream-uuid"

    @pytest.mark.asyncio
    async def test_query_param_fallback(self):
        from decnet.web.dependencies import get_stream_user
        token = create_access_token({"uuid": "query-uuid"})
        request = MagicMock()
        request.headers = {}
        result = await get_stream_user(request, token=token)
        assert result == "query-uuid"

    @pytest.mark.asyncio
    async def test_no_token_raises(self):
        from fastapi import HTTPException
        from decnet.web.dependencies import get_stream_user
        request = MagicMock()
        request.headers = {}
        with pytest.raises(HTTPException) as exc_info:
            await get_stream_user(request, token=None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_token_raises(self):
        from fastapi import HTTPException
        from decnet.web.dependencies import get_stream_user
        request = MagicMock()
        request.headers = {}
        with pytest.raises(HTTPException):
            await get_stream_user(request, token="bad-token")

    @pytest.mark.asyncio
    async def test_missing_uuid_raises(self):
        from fastapi import HTTPException
        from decnet.web.dependencies import get_stream_user
        token = create_access_token({"sub": "no-uuid"})
        request = MagicMock()
        request.headers = {"Authorization": f"Bearer {token}"}
        with pytest.raises(HTTPException):
            await get_stream_user(request, token=None)


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
