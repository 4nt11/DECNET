# SPDX-License-Identifier: AGPL-3.0-or-later
"""POST /api/v1/swarm-updates/push-self — updater-only upgrade path."""
from __future__ import annotations

import pytest


@pytest.mark.anyio
async def test_push_self_only_calls_update_self(client, auth_token, add_host, fake_updater):
    await add_host("alpha")

    resp = await client.post(
        "/api/v1/swarm-updates/push-self",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"all": True},
    )
    assert resp.status_code == 200
    assert resp.json()["results"][0]["status"] == "self-updated"
    methods = [m for _, m, _ in fake_updater["client"].calls]
    assert "update" not in methods
    assert "update_self" in methods


@pytest.mark.anyio
async def test_push_self_reports_failure(client, auth_token, add_host, fake_updater):
    await add_host("alpha")
    Resp = fake_updater["Response"]
    fake_updater["client"].update_self_responses = {
        "alpha": Resp(500, {"error": "pip failed", "stderr": "no module named typer"}),
    }

    resp = await client.post(
        "/api/v1/swarm-updates/push-self",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"all": True},
    )
    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["status"] == "self-failed"
    assert result["http_status"] == 500
    assert "typer" in (result["stderr"] or "")


@pytest.mark.anyio
async def test_push_self_treats_connection_drop_as_success(
    client, auth_token, add_host, fake_updater, connection_drop_exc,
):
    await add_host("alpha")
    fake_updater["client"].update_self_responses = {"alpha": connection_drop_exc}

    resp = await client.post(
        "/api/v1/swarm-updates/push-self",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"all": True},
    )
    assert resp.status_code == 200
    assert resp.json()["results"][0]["status"] == "self-updated"


@pytest.mark.anyio
async def test_viewer_is_forbidden(client, viewer_token, add_host, fake_updater):
    await add_host("alpha")
    resp = await client.post(
        "/api/v1/swarm-updates/push-self",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"all": True},
    )
    assert resp.status_code == 403
