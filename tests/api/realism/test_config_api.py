# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET/PUT /api/v1/realism/config — operator-tunable weights."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from decnet.realism import planner


@pytest.fixture(autouse=True)
def _reset_planner():
    import decnet.web.router.realism.api_config as _api_config
    _api_config._hydrated = False
    yield
    planner.reset_to_defaults()
    _api_config._hydrated = False


@pytest.mark.asyncio
async def test_get_returns_defaults_when_no_row():
    from decnet.web.router.realism.api_config import get_config

    with patch("decnet.web.router.realism.api_config.repo") as mock_repo:
        mock_repo.get_realism_config = AsyncMock(return_value=None)

        result = await get_config(user={"uuid": "u", "role": "viewer"})

    assert result["canary_probability"] == pytest.approx(0.03)
    assert result["user_class_weights"]


@pytest.mark.asyncio
async def test_get_hydrates_from_db_row():
    from decnet.web.router.realism.api_config import get_config

    stored = json.dumps({"canary_probability": 0.10})
    with patch("decnet.web.router.realism.api_config.repo") as mock_repo:
        mock_repo.get_realism_config = AsyncMock(
            return_value={"key": "weights", "value": stored},
        )
        result = await get_config(user={"uuid": "u", "role": "viewer"})

    assert result["canary_probability"] == pytest.approx(0.10)


@pytest.mark.asyncio
async def test_get_serves_defaults_when_stored_payload_invalid():
    """Stored JSON parsed but failed planner validation: log + serve
    defaults rather than 500."""
    from decnet.web.router.realism.api_config import get_config

    stored = json.dumps({"canary_probability": 9.0})
    with patch("decnet.web.router.realism.api_config.repo") as mock_repo:
        mock_repo.get_realism_config = AsyncMock(
            return_value={"key": "weights", "value": stored},
        )
        result = await get_config(user={"uuid": "u", "role": "viewer"})

    assert result["canary_probability"] == pytest.approx(0.03)


@pytest.mark.asyncio
async def test_put_persists_and_returns_snapshot():
    from decnet.web.router.realism.api_config import put_config

    with patch("decnet.web.router.realism.api_config.repo") as mock_repo:
        mock_repo.set_realism_config = AsyncMock()

        result = await put_config(
            body={"canary_probability": 0.20},
            user={"uuid": "u", "role": "admin", "username": "anti"},
        )

    assert result["canary_probability"] == pytest.approx(0.20)
    mock_repo.set_realism_config.assert_awaited_once()
    args, _ = mock_repo.set_realism_config.call_args
    assert args[0] == "weights"
    persisted = json.loads(args[1])
    assert persisted["canary_probability"] == pytest.approx(0.20)


@pytest.mark.asyncio
async def test_put_returns_400_on_invalid_payload():
    from decnet.web.router.realism.api_config import put_config

    with patch("decnet.web.router.realism.api_config.repo") as mock_repo:
        mock_repo.set_realism_config = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await put_config(
                body={"canary_probability": 9.0},
                user={"uuid": "u", "role": "admin", "username": "anti"},
            )

    assert exc.value.status_code == 400
    # No DB write on validation failure.
    mock_repo.set_realism_config.assert_not_called()


@pytest.mark.asyncio
async def test_put_rejects_non_dict_body():
    from decnet.web.router.realism.api_config import put_config

    with pytest.raises(HTTPException) as exc:
        await put_config(
            body=[1, 2, 3],  # type: ignore[arg-type]
            user={"uuid": "u", "role": "admin", "username": "anti"},
        )
    assert exc.value.status_code == 400
