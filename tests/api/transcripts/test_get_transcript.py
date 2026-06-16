# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Tests for GET /api/v1/transcripts/{decky}/{sid}.

Covers admin-gating, path traversal rejection, pagination over a shared
JSONL day-shard, truncation-sentinel surfacing, and the mtime-keyed LRU
index cache.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest


_DECKY = "decky-test-01"
_SID_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
_SID_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
_SHARD_NAME = "sessions-2026-04-18.jsonl"


def _write_shard(root, decky, service, shard_name, lines):
    d = root / decky / service / "transcripts"
    d.mkdir(parents=True, exist_ok=True)
    path = d / shard_name
    with path.open("w") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")
    return path


def _log_row(sid, decky, service, shard_path):
    return {
        "id": 1,
        "timestamp": "2026-04-18T02:22:56+00:00",
        "decky": decky,
        "service": service,
        "event_type": "session_recorded",
        "attacker_ip": "1.2.3.4",
        "raw_line": "",
        "msg": "",
        "fields": json.dumps({
            "sid": sid,
            "service": service,
            "shard_path": shard_path,
        }),
    }


@pytest.fixture
def shard(tmp_path, monkeypatch):
    root = tmp_path / "artifacts"
    lines_a = [
        {"sid": _SID_A, "hdr": {"version": 2, "width": 80, "height": 24, "timestamp": 0}},
        {"sid": _SID_A, "t": 0.1, "ch": "o", "d": "hello\n"},
        {"sid": _SID_A, "t": 0.2, "ch": "i", "d": "exit\n"},
    ]
    lines_b = [
        {"sid": _SID_B, "hdr": {"version": 2, "width": 80, "height": 24, "timestamp": 1}},
        {"sid": _SID_B, "t": 0.1, "ch": "o", "d": "second\n"},
        {"sid": _SID_B, "trunc": True},
    ]
    # Interleave so the shard resembles real concurrent appends.
    shard_path = _write_shard(root, _DECKY, "ssh", _SHARD_NAME,
                              [lines_a[0], lines_b[0], lines_a[1], lines_b[1], lines_b[2], lines_a[2]])

    from decnet.artifacts import shards as _shards
    from decnet.web.router.transcripts import api_get_transcript
    monkeypatch.setattr(_shards, "ARTIFACTS_ROOT", root)
    monkeypatch.setattr(api_get_transcript, "ARTIFACTS_ROOT", root)
    _shards._INDEX_CACHE.clear()
    return shard_path


async def test_admin_reads_events(client: httpx.AsyncClient, auth_token: str, shard):
    row = _log_row(_SID_A, _DECKY, "ssh", str(shard))
    with patch("decnet.web.router.transcripts.api_get_transcript.repo") as mock_repo:
        mock_repo.get_session_log = AsyncMock(return_value=row)
        res = await client.get(
            f"/api/v1/transcripts/{_DECKY}/{_SID_A}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["sid"] == _SID_A
    assert body["service"] == "ssh"
    assert body["header"]["width"] == 80
    assert len(body["events"]) == 2
    assert body["truncated"] is False
    assert body["total"] == 2


async def test_truncated_sentinel_surfaces(client: httpx.AsyncClient, auth_token: str, shard):
    row = _log_row(_SID_B, _DECKY, "ssh", str(shard))
    with patch("decnet.web.router.transcripts.api_get_transcript.repo") as mock_repo:
        mock_repo.get_session_log = AsyncMock(return_value=row)
        res = await client.get(
            f"/api/v1/transcripts/{_DECKY}/{_SID_B}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
    assert res.status_code == 200
    body = res.json()
    assert body["truncated"] is True
    assert len(body["events"]) == 1


async def test_paging_offset_limit(client: httpx.AsyncClient, auth_token: str, shard):
    row = _log_row(_SID_A, _DECKY, "ssh", str(shard))
    with patch("decnet.web.router.transcripts.api_get_transcript.repo") as mock_repo:
        mock_repo.get_session_log = AsyncMock(return_value=row)
        res = await client.get(
            f"/api/v1/transcripts/{_DECKY}/{_SID_A}?offset=1&limit=1",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
    assert res.status_code == 200
    body = res.json()
    assert body["offset"] == 1
    assert body["limit"] == 1
    assert len(body["events"]) == 1
    assert body["has_more"] is False


async def test_viewer_forbidden(client: httpx.AsyncClient, viewer_token: str, shard):
    row = _log_row(_SID_A, _DECKY, "ssh", str(shard))
    with patch("decnet.web.router.transcripts.api_get_transcript.repo") as mock_repo:
        mock_repo.get_session_log = AsyncMock(return_value=row)
        res = await client.get(
            f"/api/v1/transcripts/{_DECKY}/{_SID_A}",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
    assert res.status_code == 403


async def test_unauthenticated_rejected(client: httpx.AsyncClient, shard):
    res = await client.get(f"/api/v1/transcripts/{_DECKY}/{_SID_A}")
    assert res.status_code == 401


async def test_404_when_sid_not_in_log(client: httpx.AsyncClient, auth_token: str, shard):
    with patch("decnet.web.router.transcripts.api_get_transcript.repo") as mock_repo:
        mock_repo.get_session_log = AsyncMock(return_value=None)
        res = await client.get(
            f"/api/v1/transcripts/{_DECKY}/{_SID_A}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
    assert res.status_code == 404


async def test_invalid_sid_rejected(client: httpx.AsyncClient, auth_token: str, shard):
    res = await client.get(
        f"/api/v1/transcripts/{_DECKY}/not-a-uuid",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code == 400


async def test_decky_mismatch_rejected(client: httpx.AsyncClient, auth_token: str, shard):
    # Log row claims a different decky than the URL — don't trust the URL.
    row = _log_row(_SID_A, "other-decky", "ssh", str(shard))
    with patch("decnet.web.router.transcripts.api_get_transcript.repo") as mock_repo:
        mock_repo.get_session_log = AsyncMock(return_value=row)
        res = await client.get(
            f"/api/v1/transcripts/{_DECKY}/{_SID_A}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
    assert res.status_code == 404


async def test_forged_shard_path_is_ignored_in_favour_of_scan(
    client: httpx.AsyncClient, auth_token: str, shard,
):
    # A Log row with a shard_path basename that doesn't match
    # sessions-YYYY-MM-DD is silently ignored — the handler falls back
    # to scanning the decky's transcripts dir for a shard containing
    # the sid. The security invariant holds either way: only files
    # whose basename matches _SHARD_BASENAME_RE are ever opened, and
    # they always resolve under ARTIFACTS_ROOT/decky/<service>/
    # transcripts/.
    row = _log_row(_SID_A, _DECKY, "ssh", "/etc/passwd")
    with patch("decnet.web.router.transcripts.api_get_transcript.repo") as mock_repo:
        mock_repo.get_session_log = AsyncMock(return_value=row)
        res = await client.get(
            f"/api/v1/transcripts/{_DECKY}/{_SID_A}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
    # Fallback located the real shard and returned it. /etc/passwd was
    # never opened (different basename shape, wrong dir).
    assert res.status_code == 200
    body = res.json()
    assert body["sid"] == _SID_A
    # Sanity: the events came from the test shard, not from a system
    # file — our fixture events have string `d` fields that /etc/passwd
    # would never reproduce.
    assert all(isinstance(evt[2], str) for evt in body["events"])


async def test_limit_ceiling_enforced(client: httpx.AsyncClient, auth_token: str, shard):
    res = await client.get(
        f"/api/v1/transcripts/{_DECKY}/{_SID_A}?limit=999999",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # FastAPI Query validator returns 422 on range violations.
    assert res.status_code == 422
