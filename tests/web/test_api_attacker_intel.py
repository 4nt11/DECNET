"""Tests for GET /api/v1/attackers/{uuid}/intel."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException


@pytest.mark.asyncio
async def test_returns_cached_intel_row():
    from decnet.web.router.attackers.api_get_attacker_intel import (
        get_attacker_intel,
    )

    fake_row = {
        "attacker_uuid": "att-uuid-xyz",
        "attacker_ip": "1.2.3.4",
        "aggregate_verdict": "malicious",
        "greynoise_classification": "malicious",
        "abuseipdb_score": 92,
        "feodo_listed": True,
        "threatfox_listed": False,
    }
    with patch(
        "decnet.web.router.attackers.api_get_attacker_intel.repo"
    ) as mock_repo:
        mock_repo.get_attacker_intel_by_uuid = AsyncMock(return_value=fake_row)
        result = await get_attacker_intel(
            uuid="att-uuid-xyz",
            user={"uuid": "viewer", "role": "viewer"},
        )
    assert result["attacker_uuid"] == "att-uuid-xyz"
    assert result["aggregate_verdict"] == "malicious"
    assert result["abuseipdb_score"] == 92


@pytest.mark.asyncio
async def test_404_when_no_row_cached():
    from decnet.web.router.attackers.api_get_attacker_intel import (
        get_attacker_intel,
    )

    with patch(
        "decnet.web.router.attackers.api_get_attacker_intel.repo"
    ) as mock_repo:
        mock_repo.get_attacker_intel_by_uuid = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as excinfo:
            await get_attacker_intel(
                uuid="missing-uuid",
                user={"uuid": "viewer", "role": "viewer"},
            )
    assert excinfo.value.status_code == 404
    assert "No intel cached" in excinfo.value.detail
