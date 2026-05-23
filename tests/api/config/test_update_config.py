# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest


@pytest.mark.anyio
async def test_update_deployment_limit_admin(client, auth_token):
    resp = await client.put(
        "/api/v1/config/deployment-limit",
        json={"deployment_limit": 50},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "Deployment limit updated"


@pytest.mark.anyio
async def test_update_deployment_limit_out_of_range(client, auth_token):
    resp = await client.put(
        "/api/v1/config/deployment-limit",
        json={"deployment_limit": 0},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 422

    resp = await client.put(
        "/api/v1/config/deployment-limit",
        json={"deployment_limit": 501},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_update_deployment_limit_viewer_forbidden(client, auth_token, viewer_token):
    resp = await client.put(
        "/api/v1/config/deployment-limit",
        json={"deployment_limit": 50},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_update_global_mutation_interval_admin(client, auth_token):
    resp = await client.put(
        "/api/v1/config/global-mutation-interval",
        json={"global_mutation_interval": "7d"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "Global mutation interval updated"


@pytest.mark.anyio
async def test_update_global_mutation_interval_invalid(client, auth_token):
    resp = await client.put(
        "/api/v1/config/global-mutation-interval",
        json={"global_mutation_interval": "abc"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 422

    resp = await client.put(
        "/api/v1/config/global-mutation-interval",
        json={"global_mutation_interval": "0m"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_update_global_mutation_interval_viewer_forbidden(client, auth_token, viewer_token):
    resp = await client.put(
        "/api/v1/config/global-mutation-interval",
        json={"global_mutation_interval": "7d"},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403
