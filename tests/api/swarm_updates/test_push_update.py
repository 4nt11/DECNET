# SPDX-License-Identifier: AGPL-3.0-or-later
"""POST /api/v1/swarm-updates/push — happy paths, rollback, validation."""
from __future__ import annotations

import pytest


@pytest.mark.anyio
async def test_push_to_single_host_success(client, auth_token, add_host, fake_updater):
    h = await add_host("alpha")

    resp = await client.post(
        "/api/v1/swarm-updates/push",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"host_uuids": [h["uuid"]]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["sha"] == "deadbeef"
    assert body["tarball_bytes"] == len(b"tarball-bytes")
    assert body["results"][0]["status"] == "updated"
    assert body["results"][0]["host_name"] == "alpha"


@pytest.mark.anyio
async def test_push_reports_rollback_on_409(client, auth_token, add_host, fake_updater):
    h = await add_host("alpha")
    Resp = fake_updater["Response"]
    fake_updater["client"].update_responses = {
        "alpha": Resp(409, {"error": "probe timed out", "stderr": "boom", "rolled_back": True}),
    }

    resp = await client.post(
        "/api/v1/swarm-updates/push",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"host_uuids": [h["uuid"]]},
    )
    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["status"] == "rolled-back"
    assert result["http_status"] == 409
    assert result["stderr"] == "boom"


@pytest.mark.anyio
async def test_push_all_aggregates_mixed_results(client, auth_token, add_host, fake_updater):
    await add_host("alpha", "10.0.0.1")
    await add_host("beta", "10.0.0.2")
    Resp = fake_updater["Response"]
    fake_updater["client"].update_responses = {
        "alpha": Resp(200, {"probe": "ok"}),
        "beta": RuntimeError("connect timeout"),
    }

    resp = await client.post(
        "/api/v1/swarm-updates/push",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"all": True},
    )
    assert resp.status_code == 200
    statuses = {r["host_name"]: r["status"] for r in resp.json()["results"]}
    assert statuses == {"alpha": "updated", "beta": "failed"}


@pytest.mark.anyio
async def test_tarball_built_once_across_multi_host_push(
    client, auth_token, add_host, fake_updater, monkeypatch,
):
    await add_host("alpha", "10.0.0.1")
    await add_host("beta", "10.0.0.2")
    calls = {"count": 0}

    def counted(root, extra_excludes=None):
        calls["count"] += 1
        return b"tarball-bytes"

    monkeypatch.setattr(
        "decnet.web.router.swarm_updates.api_push_update.tar_working_tree", counted,
    )

    resp = await client.post(
        "/api/v1/swarm-updates/push",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"all": True},
    )
    assert resp.status_code == 200
    assert calls["count"] == 1


@pytest.mark.anyio
async def test_include_self_only_runs_update_self_on_success(
    client, auth_token, add_host, fake_updater,
):
    await add_host("alpha", "10.0.0.1")
    await add_host("beta", "10.0.0.2")
    Resp = fake_updater["Response"]
    fake_updater["client"].update_responses = {
        "alpha": Resp(200, {"probe": "ok"}),
        "beta": Resp(409, {"error": "bad", "rolled_back": True}),
    }

    resp = await client.post(
        "/api/v1/swarm-updates/push",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"all": True, "include_self": True},
    )
    assert resp.status_code == 200
    results = {r["host_name"]: r for r in resp.json()["results"]}
    assert results["alpha"]["status"] == "self-updated"
    assert results["beta"]["status"] == "rolled-back"
    # update_self must NOT have been called on beta (rolled-back agent).
    methods_called = [(name, m) for name, m, _ in fake_updater["client"].calls]
    assert ("beta", "update_self") not in methods_called
    assert ("alpha", "update_self") in methods_called


@pytest.mark.anyio
async def test_include_self_tolerates_expected_connection_drop(
    client, auth_token, add_host, fake_updater, connection_drop_exc,
):
    await add_host("alpha", "10.0.0.1")
    fake_updater["client"].update_self_responses = {
        "alpha": connection_drop_exc,
    }

    resp = await client.post(
        "/api/v1/swarm-updates/push",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"all": True, "include_self": True},
    )
    assert resp.status_code == 200
    assert resp.json()["results"][0]["status"] == "self-updated"


@pytest.mark.anyio
async def test_host_and_all_are_mutually_exclusive(
    client, auth_token, add_host, fake_updater,
):
    h = await add_host("alpha")

    resp = await client.post(
        "/api/v1/swarm-updates/push",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"host_uuids": [h["uuid"]], "all": True},
    )
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_neither_host_nor_all_rejected(client, auth_token, fake_updater):
    resp = await client.post(
        "/api/v1/swarm-updates/push",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={},
    )
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_unknown_host_uuid_returns_404(client, auth_token, fake_updater):
    resp = await client.post(
        "/api/v1/swarm-updates/push",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"host_uuids": ["nonexistent"]},
    )
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_viewer_is_forbidden(client, viewer_token, add_host, fake_updater):
    h = await add_host("alpha")
    resp = await client.post(
        "/api/v1/swarm-updates/push",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"host_uuids": [h["uuid"]]},
    )
    assert resp.status_code == 403
