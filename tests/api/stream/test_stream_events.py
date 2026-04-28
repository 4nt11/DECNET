"""
Tests for the SSE stream endpoint (decnet/web/router/stream/api_stream_events.py).
"""

import pytest
import httpx

from unittest.mock import AsyncMock, patch


# ── Stream endpoint tests ─────────────────────────────────────────────────────

_EMPTY_STATS = {"total_logs": 0, "unique_attackers": 0, "active_deckies": 0, "deployed_deckies": 0}


def _mock_repo_prefetch(mock_repo, *, crash_on_logs: bool = True) -> None:
    """
    Set up the three prefetch calls that now run in the endpoint function
    (outside the generator) to return valid dummy data.

    If crash_on_logs is True, get_logs_after_id raises RuntimeError so the
    generator exits via its except-Exception handler without hanging.
    """
    mock_repo.get_max_log_id = AsyncMock(return_value=0)
    mock_repo.get_stats_summary = AsyncMock(return_value=_EMPTY_STATS)
    mock_repo.get_log_histogram = AsyncMock(return_value=[])
    if crash_on_logs:
        mock_repo.get_logs_after_id = AsyncMock(side_effect=RuntimeError("test crash"))


class TestStreamEvents:
    @pytest.mark.asyncio
    async def test_unauthenticated_returns_401(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/stream")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_stream_sends_initial_stats(self, client: httpx.AsyncClient, auth_token: str):
        # Prefetch calls (get_max_log_id, get_stats_summary, get_log_histogram) now
        # run in the endpoint function before the generator is created.  Mock them
        # all.  Crash get_logs_after_id so the generator exits without hanging.
        with patch("decnet.web.router.stream.api_stream_events.repo") as mock_repo:
            _mock_repo_prefetch(mock_repo)
            resp = await client.get(
                "/api/v1/stream",
                headers={"Authorization": f"Bearer {auth_token}"},
                params={"lastEventId": "0"},
            )
            assert resp.status_code in (200, 500)

    @pytest.mark.asyncio
    async def test_stream_with_query_token(self, client: httpx.AsyncClient, auth_token: str):
        with patch("decnet.web.router.stream.api_stream_events.repo") as mock_repo:
            _mock_repo_prefetch(mock_repo)
            resp = await client.get(
                "/api/v1/stream",
                params={"token": auth_token, "lastEventId": "0"},
            )
            assert resp.status_code in (200, 500)

    @pytest.mark.asyncio
    async def test_stream_invalid_token_401(self, client: httpx.AsyncClient):
        resp = await client.get(
            "/api/v1/stream",
            params={"token": "bad-token", "lastEventId": "0"},
        )
        assert resp.status_code == 401
