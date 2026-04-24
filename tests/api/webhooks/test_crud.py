"""CRUD tests for /api/v1/webhooks — admin-gated subscription management."""
from __future__ import annotations

import httpx
import pytest


PATH = "/api/v1/webhooks/"


@pytest.mark.asyncio
async def test_create_requires_patterns(client: httpx.AsyncClient, auth_token: str):
    res = await client.post(
        PATH,
        json={"name": "wh1", "url": "https://example.com/x"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code == 400, res.text


@pytest.mark.asyncio
async def test_create_expands_simple_events(
    client: httpx.AsyncClient, auth_token: str
):
    res = await client.post(
        PATH,
        json={
            "name": "wh-simple",
            "url": "https://example.com/x",
            "simple_events": ["AttackerDetail"],
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["topic_patterns"] == ["attacker.>"]
    # Create-path carries the secret for copy-out.
    assert body["secret"]
    assert len(body["secret"]) >= 16


@pytest.mark.asyncio
async def test_list_strips_secret(client: httpx.AsyncClient, auth_token: str):
    await client.post(
        PATH,
        json={
            "name": "wh-list",
            "url": "https://example.com/x",
            "topic_patterns": ["system.>"],
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    res = await client.get(
        PATH, headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res.status_code == 200
    rows = res.json()
    assert len(rows) >= 1
    for r in rows:
        assert "secret" not in r


@pytest.mark.asyncio
async def test_get_single_strips_secret(
    client: httpx.AsyncClient, auth_token: str
):
    create = await client.post(
        PATH,
        json={
            "name": "wh-one",
            "url": "https://example.com/x",
            "topic_patterns": ["decky.*.state"],
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    uuid = create.json()["uuid"]

    res = await client.get(
        PATH + uuid, headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res.status_code == 200
    assert "secret" not in res.json()


@pytest.mark.asyncio
async def test_duplicate_name_conflicts(
    client: httpx.AsyncClient, auth_token: str
):
    payload = {
        "name": "wh-dup",
        "url": "https://example.com/x",
        "topic_patterns": ["system.>"],
    }
    first = await client.post(
        PATH, json=payload, headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert first.status_code == 201
    second = await client.post(
        PATH, json=payload, headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_patch_merges_patterns(
    client: httpx.AsyncClient, auth_token: str
):
    create = await client.post(
        PATH,
        json={
            "name": "wh-patch",
            "url": "https://example.com/x",
            "simple_events": ["AttackerDetail"],
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    uuid = create.json()["uuid"]
    res = await client.patch(
        PATH + uuid,
        json={"topic_patterns": ["custom.>"]},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code == 200
    # simple_events was NOT passed → it's None → only raw patterns survive.
    assert res.json()["topic_patterns"] == ["custom.>"]


@pytest.mark.asyncio
async def test_patch_refuses_empty_patterns(
    client: httpx.AsyncClient, auth_token: str
):
    create = await client.post(
        PATH,
        json={
            "name": "wh-empty",
            "url": "https://example.com/x",
            "simple_events": ["AttackerDetail"],
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    uuid = create.json()["uuid"]
    res = await client.patch(
        PATH + uuid,
        json={"simple_events": [], "topic_patterns": []},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_delete_returns_message(
    client: httpx.AsyncClient, auth_token: str
):
    create = await client.post(
        PATH,
        json={
            "name": "wh-del",
            "url": "https://example.com/x",
            "topic_patterns": ["system.>"],
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    uuid = create.json()["uuid"]
    res = await client.delete(
        PATH + uuid, headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res.status_code == 200
    assert res.json() == {"message": "Webhook deleted"}
    # Second delete → 404.
    res2 = await client.delete(
        PATH + uuid, headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res2.status_code == 404


@pytest.mark.asyncio
async def test_http_url_warns_but_accepts(
    client: httpx.AsyncClient, auth_token: str
):
    """Plain http:// is allowed (operator-trust posture per WH-03) but
    surfaces a non-blocking advisory in the response's warnings list."""
    res = await client.post(
        PATH,
        json={
            "name": "wh-http",
            "url": "http://insecure.local/inbound",
            "topic_patterns": ["system.>"],
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert any("insecure_url" in w for w in body["warnings"])


@pytest.mark.asyncio
async def test_https_url_has_no_warning(
    client: httpx.AsyncClient, auth_token: str
):
    res = await client.post(
        PATH,
        json={
            "name": "wh-https",
            "url": "https://secure.example/inbound",
            "topic_patterns": ["system.>"],
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code == 201
    assert res.json()["warnings"] == []


@pytest.mark.asyncio
async def test_reenabling_clears_circuit_trip(
    client: httpx.AsyncClient, auth_token: str
):
    """Re-enabling via PATCH clears auto_disabled_at + consecutive_failures.

    Simulates the full circuit-breaker lifecycle: create → tripped (via
    direct DB write, since we can't easily force N worker failures in an
    API-only test) → re-enable via PATCH → verify state cleared.
    """
    from datetime import datetime, timezone
    from decnet.web.dependencies import repo

    create = await client.post(
        PATH,
        json={
            "name": "wh-trip",
            "url": "https://example.com/x",
            "topic_patterns": ["system.>"],
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert create.status_code == 201
    uuid = create.json()["uuid"]

    # Simulate the circuit tripping — direct repo call.
    now = datetime.now(timezone.utc)
    await repo.record_webhook_failure(uuid, now, "503 service unavailable")
    await repo.record_webhook_failure(uuid, now, "503 service unavailable")
    await repo.trip_webhook_circuit(uuid, now)

    pre = await client.get(
        f"{PATH}{uuid}", headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert pre.json()["enabled"] is False
    assert pre.json()["auto_disabled_at"] is not None
    assert pre.json()["consecutive_failures"] >= 1

    # Re-enable via PATCH — should clear trip + counter + last_error.
    res = await client.patch(
        f"{PATH}{uuid}",
        json={"enabled": True},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["enabled"] is True
    assert body["auto_disabled_at"] is None
    assert body["consecutive_failures"] == 0
    assert body["last_error"] is None


@pytest.mark.asyncio
async def test_viewer_forbidden(client: httpx.AsyncClient, viewer_token: str):
    res = await client.get(
        PATH, headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_rejected(client: httpx.AsyncClient):
    res = await client.get(PATH)
    assert res.status_code == 401
