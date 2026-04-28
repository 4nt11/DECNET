"""The orchestrator pulls operator-tuned weights from realism_config.

§3c contract: the planner reads in-memory module globals, but the
operator's tuning lives in the DB (admin PUT /api/v1/realism/config).
The orchestrator worker bridges the two by calling
``_refresh_realism_config(repo)`` at startup and every Nth tick.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from decnet.orchestrator.worker import _refresh_realism_config
from decnet.realism import planner


@pytest.fixture(autouse=True)
def _reset_planner():
    yield
    planner.reset_to_defaults()


@pytest.mark.asyncio
async def test_refresh_no_row_keeps_defaults():
    repo = AsyncMock()
    repo.get_realism_config = AsyncMock(return_value=None)
    await _refresh_realism_config(repo)
    assert planner.current_payload()["canary_probability"] == pytest.approx(0.03)


@pytest.mark.asyncio
async def test_refresh_applies_stored_payload():
    repo = AsyncMock()
    repo.get_realism_config = AsyncMock(return_value={
        "key": "weights",
        "value": json.dumps({"canary_probability": 0.12}),
    })
    await _refresh_realism_config(repo)
    assert planner.current_payload()["canary_probability"] == pytest.approx(0.12)


@pytest.mark.asyncio
async def test_refresh_swallows_db_error():
    """A wedged DB must not bring down the orchestrator's tick loop."""
    repo = AsyncMock()
    repo.get_realism_config = AsyncMock(side_effect=RuntimeError("boom"))
    await _refresh_realism_config(repo)  # does not raise
    # planner unchanged
    assert planner.current_payload()["canary_probability"] == pytest.approx(0.03)


@pytest.mark.asyncio
async def test_refresh_swallows_malformed_json():
    repo = AsyncMock()
    repo.get_realism_config = AsyncMock(return_value={
        "key": "weights",
        "value": "not-json",
    })
    await _refresh_realism_config(repo)
    assert planner.current_payload()["canary_probability"] == pytest.approx(0.03)


@pytest.mark.asyncio
async def test_refresh_swallows_invalid_payload():
    repo = AsyncMock()
    repo.get_realism_config = AsyncMock(return_value={
        "key": "weights",
        "value": json.dumps({"canary_probability": 9.0}),
    })
    await _refresh_realism_config(repo)
    # Planner config not corrupted by a bad refresh.
    assert planner.current_payload()["canary_probability"] == pytest.approx(0.03)
