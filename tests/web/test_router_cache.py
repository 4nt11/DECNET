# SPDX-License-Identifier: AGPL-3.0-or-later
"""
TTL-cache contract for /stats, /logs total count, and /attackers total count.

Under concurrent load N callers should collapse to 1 repo hit per TTL
window. Tests patch the repo — no real DB.
"""
import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from decnet.web.router.stats import api_get_stats
from decnet.web.router.logs import api_get_logs
from decnet.web.router.attackers import api_get_attackers


@pytest.fixture(autouse=True)
def _reset_router_caches():
    api_get_stats._reset_stats_cache()
    api_get_logs._reset_total_cache()
    api_get_attackers._reset_total_cache()
    yield
    api_get_stats._reset_stats_cache()
    api_get_logs._reset_total_cache()
    api_get_attackers._reset_total_cache()


# ── /stats whole-response cache ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stats_cache_collapses_concurrent_calls():
    api_get_stats._reset_stats_cache()
    payload = {"total_logs": 42, "unique_attackers": 7, "active_deckies": 3, "deployed_deckies": 3}
    with patch.object(api_get_stats, "repo") as mock_repo:
        mock_repo.get_stats_summary = AsyncMock(return_value=payload)
        results = await asyncio.gather(*[api_get_stats._get_stats_cached() for _ in range(50)])
    assert all(r == payload for r in results)
    assert mock_repo.get_stats_summary.await_count == 1


@pytest.mark.asyncio
async def test_stats_cache_expires_after_ttl(monkeypatch):
    api_get_stats._reset_stats_cache()
    clock = {"t": 0.0}
    monkeypatch.setattr(api_get_stats.time, "monotonic", lambda: clock["t"])
    with patch.object(api_get_stats, "repo") as mock_repo:
        mock_repo.get_stats_summary = AsyncMock(return_value={"total_logs": 1, "unique_attackers": 0, "active_deckies": 0, "deployed_deckies": 0})
        await api_get_stats._get_stats_cached()
        clock["t"] = 100.0  # past TTL
        await api_get_stats._get_stats_cached()
    assert mock_repo.get_stats_summary.await_count == 2


# ── /logs total-count cache ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_logs_total_cache_collapses_concurrent_calls():
    api_get_logs._reset_total_cache()
    with patch.object(api_get_logs, "repo") as mock_repo:
        mock_repo.get_total_logs = AsyncMock(return_value=1234)
        results = await asyncio.gather(*[api_get_logs._get_total_logs_cached() for _ in range(50)])
    assert all(r == 1234 for r in results)
    assert mock_repo.get_total_logs.await_count == 1


@pytest.mark.asyncio
async def test_logs_filtered_count_bypasses_cache():
    """When a filter is provided, the endpoint must hit repo every time."""
    api_get_logs._reset_total_cache()
    with patch.object(api_get_logs, "repo") as mock_repo:
        mock_repo.get_logs = AsyncMock(return_value=[])
        mock_repo.get_total_logs = AsyncMock(return_value=0)
        for _ in range(3):
            await api_get_logs.get_logs(
                limit=50, offset=0, search="needle", start_time=None, end_time=None,
                user={"uuid": "u", "role": "viewer"},
            )
    # 3 filtered calls → 3 repo hits, all with search=needle
    assert mock_repo.get_total_logs.await_count == 3
    for call in mock_repo.get_total_logs.await_args_list:
        assert call.kwargs["search"] == "needle"


# ── /attackers total-count cache ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_attackers_total_cache_collapses_concurrent_calls():
    api_get_attackers._reset_total_cache()
    with patch.object(api_get_attackers, "repo") as mock_repo:
        mock_repo.get_total_attackers = AsyncMock(return_value=99)
        results = await asyncio.gather(*[api_get_attackers._get_total_attackers_cached() for _ in range(50)])
    assert all(r == 99 for r in results)
    assert mock_repo.get_total_attackers.await_count == 1


@pytest.mark.asyncio
async def test_attackers_filtered_count_bypasses_cache():
    api_get_attackers._reset_total_cache()
    with patch.object(api_get_attackers, "repo") as mock_repo:
        mock_repo.get_attackers = AsyncMock(return_value=[])
        mock_repo.get_total_attackers = AsyncMock(return_value=0)
        mock_repo.get_behaviors_for_ips = AsyncMock(return_value={})
        for _ in range(3):
            await api_get_attackers.get_attackers(
                limit=50, offset=0, search="10.", sort_by="recent", service=None,
                user={"uuid": "u", "role": "viewer"},
            )
    assert mock_repo.get_total_attackers.await_count == 3
    for call in mock_repo.get_total_attackers.await_args_list:
        assert call.kwargs["search"] == "10."
