# SPDX-License-Identifier: AGPL-3.0-or-later
"""
TTL-cache contract: under concurrent load, N callers collapse to 1 repo hit
per TTL window. Tests use fake repo objects — no real DB.
"""
import asyncio
from unittest.mock import patch

import pytest

from decnet.web.router.health import api_get_health
from decnet.web.router.config import api_get_config


class _FakeRepo:
    def __init__(self):
        self.total_logs_calls = 0
        self.state_calls = 0

    async def get_total_logs(self):
        self.total_logs_calls += 1
        return 0

    async def get_state(self, name: str):
        self.state_calls += 1
        return {"name": name}


@pytest.mark.asyncio
async def test_db_cache_collapses_concurrent_calls():
    api_get_health._reset_db_cache()
    fake = _FakeRepo()
    with patch.object(api_get_health, "repo", fake):
        results = await asyncio.gather(*[api_get_health._check_database_cached() for _ in range(50)])
    assert all(r.status == "ok" for r in results)
    assert fake.total_logs_calls == 1


@pytest.mark.asyncio
async def test_db_cache_expires_after_ttl(monkeypatch):
    api_get_health._reset_db_cache()
    monkeypatch.setattr(api_get_health, "_DB_CHECK_INTERVAL", 0.05)
    fake = _FakeRepo()
    with patch.object(api_get_health, "repo", fake):
        await api_get_health._check_database_cached()
        await asyncio.sleep(0.1)
        await api_get_health._check_database_cached()
    assert fake.total_logs_calls == 2


@pytest.mark.asyncio
async def test_config_state_cache_collapses_concurrent_calls():
    api_get_config._reset_state_cache()
    fake = _FakeRepo()
    with patch.object(api_get_config, "repo", fake):
        results = await asyncio.gather(*[api_get_config._get_state_cached("config_limits") for _ in range(30)])
    assert all(r == {"name": "config_limits"} for r in results)
    assert fake.state_calls == 1


@pytest.mark.asyncio
async def test_config_state_cache_per_key():
    api_get_config._reset_state_cache()
    fake = _FakeRepo()
    with patch.object(api_get_config, "repo", fake):
        await api_get_config._get_state_cached("config_limits")
        await api_get_config._get_state_cached("config_globals")
    assert fake.state_calls == 2
