"""GET /api/v1/realism/synthetic-files — paginated browser API."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from decnet.web.db.models.realism import SYNTHETIC_FILE_BODY_LIMIT


def _row(**over):
    base = {
        "uuid": "sf-1",
        "decky_uuid": "d-1",
        "path": "/home/admin/notes.txt",
        "persona": "admin",
        "content_class": "note",
        "created_at": "2026-04-27T10:00:00+00:00",
        "last_modified": "2026-04-27T10:00:00+00:00",
        "edit_count": 0,
        "content_hash": "deadbeef" * 8,
        "last_body": "hello world",
    }
    base.update(over)
    return base


@pytest.mark.asyncio
async def test_list_returns_paginated_envelope():
    from decnet.web.router.realism.api_synthetic_files import (
        list_synthetic_files,
    )

    rows = [_row(uuid=f"sf-{i}") for i in range(3)]
    with patch(
        "decnet.web.router.realism.api_synthetic_files.repo"
    ) as mock_repo:
        mock_repo.list_synthetic_files = AsyncMock(return_value=rows)
        mock_repo.count_synthetic_files = AsyncMock(return_value=3)

        result = await list_synthetic_files(
            limit=50, offset=0,
            decky_uuid=None, persona=None, content_class=None,
            user={"uuid": "u", "role": "viewer"},
        )

    assert result["total"] == 3
    assert result["limit"] == 50
    assert result["offset"] == 0
    assert len(result["data"]) == 3
    # List view drops the body to keep the payload small.
    for r in result["data"]:
        assert "last_body" not in r


@pytest.mark.asyncio
async def test_list_forwards_filters_to_repo():
    from decnet.web.router.realism.api_synthetic_files import (
        list_synthetic_files,
    )

    with patch(
        "decnet.web.router.realism.api_synthetic_files.repo"
    ) as mock_repo:
        mock_repo.list_synthetic_files = AsyncMock(return_value=[])
        mock_repo.count_synthetic_files = AsyncMock(return_value=0)

        await list_synthetic_files(
            limit=10, offset=20,
            decky_uuid="d-7", persona="alice", content_class="todo",
            user={"uuid": "u", "role": "viewer"},
        )

    mock_repo.list_synthetic_files.assert_awaited_once_with(
        decky_uuid="d-7", persona="alice", content_class="todo",
        limit=10, offset=20,
    )
    mock_repo.count_synthetic_files.assert_awaited_once_with(
        decky_uuid="d-7", persona="alice", content_class="todo",
    )


@pytest.mark.asyncio
async def test_get_detail_returns_body_with_truncated_false():
    from decnet.web.router.realism.api_synthetic_files import (
        get_synthetic_file,
    )

    with patch(
        "decnet.web.router.realism.api_synthetic_files.repo"
    ) as mock_repo:
        mock_repo.get_synthetic_file = AsyncMock(return_value=_row(
            last_body="short body",
        ))

        result = await get_synthetic_file(
            uuid="sf-1",
            user={"uuid": "u", "role": "viewer"},
        )

    assert result["last_body"] == "short body"
    assert result["truncated"] is False


@pytest.mark.asyncio
async def test_get_detail_marks_truncated_when_at_cap():
    from decnet.web.router.realism.api_synthetic_files import (
        get_synthetic_file,
    )

    body = "X" * SYNTHETIC_FILE_BODY_LIMIT
    with patch(
        "decnet.web.router.realism.api_synthetic_files.repo"
    ) as mock_repo:
        mock_repo.get_synthetic_file = AsyncMock(return_value=_row(
            last_body=body,
        ))

        result = await get_synthetic_file(
            uuid="sf-1",
            user={"uuid": "u", "role": "viewer"},
        )

    assert len(result["last_body"]) == SYNTHETIC_FILE_BODY_LIMIT
    assert result["truncated"] is True


@pytest.mark.asyncio
async def test_get_detail_404_when_missing():
    from decnet.web.router.realism.api_synthetic_files import (
        get_synthetic_file,
    )

    with patch(
        "decnet.web.router.realism.api_synthetic_files.repo"
    ) as mock_repo:
        mock_repo.get_synthetic_file = AsyncMock(return_value=None)

        with pytest.raises(HTTPException) as exc:
            await get_synthetic_file(
                uuid="missing",
                user={"uuid": "u", "role": "viewer"},
            )

    assert exc.value.status_code == 404
