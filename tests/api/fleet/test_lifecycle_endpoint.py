# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /deckies/lifecycle?ids=… — poll endpoint for the wizard."""
from __future__ import annotations

import httpx
import pytest

from decnet.web.dependencies import repo


@pytest.mark.anyio
async def test_get_lifecycle_unauthenticated_returns_401(client: httpx.AsyncClient):
    resp = await client.get("/api/v1/deckies/lifecycle", params={"ids": "x"})
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_get_lifecycle_missing_ids_returns_validation_error(
    client: httpx.AsyncClient, auth_token: str,
):
    """No ?ids= → validation rejection (Starlette short-circuits with 400
    for the body-parse path; either 400 or 422 is acceptable contract)."""
    resp = await client.get(
        "/api/v1/deckies/lifecycle",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code in (400, 422)


@pytest.mark.anyio
async def test_get_lifecycle_returns_matching_rows(
    client: httpx.AsyncClient, auth_token: str,
):
    a = await repo.create_lifecycle({"decky_name": "d1", "operation": "deploy"})
    b = await repo.create_lifecycle({"decky_name": "d2", "operation": "mutate"})
    await repo.update_lifecycle(a, {"status": "running"})

    resp = await client.get(
        "/api/v1/deckies/lifecycle",
        params=[("ids", a), ("ids", b)],
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200, resp.text
    rows = resp.json()["rows"]
    assert len(rows) == 2
    by_id = {r["id"]: r for r in rows}
    assert by_id[a]["status"] == "running"
    assert by_id[a]["operation"] == "deploy"
    assert by_id[b]["status"] == "pending"
    assert by_id[b]["operation"] == "mutate"


@pytest.mark.anyio
async def test_get_lifecycle_unknown_id_silently_omitted(
    client: httpx.AsyncClient, auth_token: str,
):
    a = await repo.create_lifecycle({"decky_name": "d1", "operation": "deploy"})
    resp = await client.get(
        "/api/v1/deckies/lifecycle",
        params=[("ids", a), ("ids", "no-such-id")],
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    rows = resp.json()["rows"]
    assert len(rows) == 1
    assert rows[0]["id"] == a


@pytest.mark.anyio
async def test_startup_sweep_marks_stale_rows_failed():
    """The sweep stamps reason='master restarted during operation' on
    any non-terminal row older than the cutoff."""
    from datetime import datetime, timedelta, timezone
    lid = await repo.create_lifecycle({"decky_name": "stale", "operation": "deploy"})
    # Backdate started_at into the past so the sweep picks it up.
    await repo.update_lifecycle(
        lid, {"started_at": datetime.now(timezone.utc) - timedelta(hours=2)},
    )
    swept = await repo.sweep_stale_lifecycle(
        datetime.now(timezone.utc) - timedelta(hours=1),
        reason="master restarted during operation",
    )
    assert swept >= 1
    rows = await repo.get_lifecycle_by_ids([lid])
    assert rows[0]["status"] == "failed"
    assert rows[0]["error"] == "master restarted during operation"
