# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/orchestrator/events/stats — failure-count badge endpoint (DEBT-042)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from decnet.web.api import app

_V1 = "/api/v1/orchestrator"


@pytest.mark.anyio
async def test_stats_unauthenticated_401():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test",
    ) as ac:
        r = await ac.get(f"{_V1}/events/stats?since=1h&success=false")
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_stats_returns_failure_count_with_window():
    from decnet.web.router.orchestrator.api_event_stats import (
        orchestrator_event_stats,
    )

    with patch(
        "decnet.web.router.orchestrator.api_event_stats.repo"
    ) as mock_repo:
        mock_repo.count_orchestrator_failures = AsyncMock(return_value=7)

        result = await orchestrator_event_stats(
            since="1h", success=False, kind=None,
            user={"uuid": "u", "role": "viewer"},
        )

    assert result["count"] == 7
    assert result["since"] == "1h"
    assert result["success"] is False
    assert result["kind"] is None

    # Window must be "now - 1h", not 5h or 30s. Tolerance of 5 seconds
    # for the test execution.
    call = mock_repo.count_orchestrator_failures.await_args
    since_ts = call.kwargs["since_ts"]
    expected = datetime.now(timezone.utc) - timedelta(hours=1)
    assert abs((since_ts - expected).total_seconds()) < 5


@pytest.mark.asyncio
async def test_stats_forwards_kind_filter():
    from decnet.web.router.orchestrator.api_event_stats import (
        orchestrator_event_stats,
    )

    with patch(
        "decnet.web.router.orchestrator.api_event_stats.repo"
    ) as mock_repo:
        mock_repo.count_orchestrator_failures = AsyncMock(return_value=2)

        await orchestrator_event_stats(
            since="15m", success=False, kind="email",
            user={"uuid": "u", "role": "viewer"},
        )

    assert mock_repo.count_orchestrator_failures.await_args.kwargs["kind"] == "email"


@pytest.mark.asyncio
async def test_stats_rejects_success_true():
    """Only success=false is supported on this surface today; everything
    else is rejected so the endpoint isn't accidentally repurposed
    before the next consumer is properly designed."""
    from fastapi import HTTPException

    from decnet.web.router.orchestrator.api_event_stats import (
        orchestrator_event_stats,
    )

    with pytest.raises(HTTPException) as exc:
        await orchestrator_event_stats(
            since="1h", success=True, kind=None,
            user={"uuid": "u", "role": "viewer"},
        )
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_stats_rejects_success_unset():
    from fastapi import HTTPException

    from decnet.web.router.orchestrator.api_event_stats import (
        orchestrator_event_stats,
    )

    with pytest.raises(HTTPException) as exc:
        await orchestrator_event_stats(
            since="1h", success=None, kind=None,
            user={"uuid": "u", "role": "viewer"},
        )
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_stats_rejects_malformed_since():
    from fastapi import HTTPException

    from decnet.web.router.orchestrator.api_event_stats import (
        orchestrator_event_stats,
    )

    with pytest.raises(HTTPException) as exc:
        await orchestrator_event_stats(
            since="garbage", success=False, kind=None,
            user={"uuid": "u", "role": "viewer"},
        )
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_stats_rejects_window_over_max():
    from fastapi import HTTPException

    from decnet.web.router.orchestrator.api_event_stats import (
        orchestrator_event_stats,
    )

    with pytest.raises(HTTPException) as exc:
        await orchestrator_event_stats(
            since="30d", success=False, kind=None,
            user={"uuid": "u", "role": "viewer"},
        )
    assert exc.value.status_code == 422
