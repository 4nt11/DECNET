# SPDX-License-Identifier: AGPL-3.0-or-later
"""POST /swarm/hosts/{uuid}/teardown — per-host and per-decky remote teardown."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import pytest

from decnet.web.router.swarm_mgmt import api_teardown_host as mod


class _FakeAgent:
    def __init__(self, *a, **kw):
        _FakeAgent.calls.append(("init", kw.get("host", a[0] if a else None)))
        self._host = kw.get("host", a[0] if a else None)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def teardown(self, decky_id: Optional[str] = None) -> dict:
        _FakeAgent.calls.append(("teardown", decky_id))
        return {"status": "torn_down", "decky_id": decky_id}


class _FailingAgent(_FakeAgent):
    async def teardown(self, decky_id: Optional[str] = None) -> dict:
        raise RuntimeError("network unreachable")


@pytest.fixture
def fake_agent(monkeypatch):
    _FakeAgent.calls = []
    monkeypatch.setattr(mod, "AgentClient", _FakeAgent)
    return _FakeAgent


@pytest.fixture
def failing_agent(monkeypatch):
    _FailingAgent.calls = []
    monkeypatch.setattr(mod, "AgentClient", _FailingAgent)
    return _FailingAgent


async def _seed_host(repo, *, name="worker-a", uuid="h-1") -> str:
    await repo.add_swarm_host({
        "uuid": uuid,
        "name": name,
        "address": "10.0.0.9",
        "agent_port": 8765,
        "status": "active",
        "client_cert_fingerprint": "f" * 64,
        "cert_bundle_path": "",
        "use_ipvlan": False,
        "enrolled_at": datetime.now(timezone.utc),
        "last_heartbeat": None,
    })
    return uuid


async def _seed_shard(repo, *, host_uuid: str, decky_name: str) -> None:
    await repo.upsert_decky_shard({
        "decky_name": decky_name,
        "host_uuid": host_uuid,
        "services": json.dumps(["ssh"]),
        "state": "running",
        "last_error": None,
        "updated_at": datetime.now(timezone.utc),
    })


@pytest.mark.anyio
async def test_teardown_all_deckies_on_host(client, auth_token, fake_agent):
    from decnet.web.dependencies import repo
    uuid = await _seed_host(repo, name="tear-all", uuid="tear-all-uuid")
    await _seed_shard(repo, host_uuid=uuid, decky_name="decky1")
    await _seed_shard(repo, host_uuid=uuid, decky_name="decky2")

    resp = await client.post(
        f"/api/v1/swarm/hosts/{uuid}/teardown",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={},
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["accepted"] is True
    assert body["decky_id"] is None

    await mod.drain_pending()

    assert ("teardown", None) in fake_agent.calls
    remaining = await repo.list_decky_shards(uuid)
    assert remaining == []


@pytest.mark.anyio
async def test_teardown_single_decky(client, auth_token, fake_agent):
    from decnet.web.dependencies import repo
    uuid = await _seed_host(repo, name="tear-one", uuid="tear-one-uuid")
    await _seed_shard(repo, host_uuid=uuid, decky_name="decky-keep")
    await _seed_shard(repo, host_uuid=uuid, decky_name="decky-drop")

    resp = await client.post(
        f"/api/v1/swarm/hosts/{uuid}/teardown",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"decky_id": "decky-drop"},
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["decky_id"] == "decky-drop"

    await mod.drain_pending()

    assert ("teardown", "decky-drop") in fake_agent.calls
    remaining = {s["decky_name"] for s in await repo.list_decky_shards(uuid)}
    assert remaining == {"decky-keep"}


@pytest.mark.anyio
async def test_teardown_returns_immediately_and_marks_tearing_down(
    client, auth_token, monkeypatch
):
    """The 202 must fire before the background agent call completes —
    otherwise multiple queued teardowns still serialize on the UI."""
    import asyncio as _asyncio
    from decnet.web.dependencies import repo

    gate = _asyncio.Event()

    class _SlowAgent(_FakeAgent):
        async def teardown(self, decky_id=None):
            await gate.wait()
            return {"status": "torn_down"}

    monkeypatch.setattr(mod, "AgentClient", _SlowAgent)

    uuid = await _seed_host(repo, name="slow", uuid="slow-uuid")
    await _seed_shard(repo, host_uuid=uuid, decky_name="decky-slow")

    resp = await client.post(
        f"/api/v1/swarm/hosts/{uuid}/teardown",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"decky_id": "decky-slow"},
    )
    assert resp.status_code == 202

    # Agent is still blocked — shard should be in 'tearing_down', not gone.
    shards = {s["decky_name"]: s for s in await repo.list_decky_shards(uuid)}
    assert shards["decky-slow"]["state"] == "tearing_down"

    gate.set()
    await mod.drain_pending()

    remaining = {s["decky_name"] for s in await repo.list_decky_shards(uuid)}
    assert remaining == set()


@pytest.mark.anyio
async def test_teardown_unknown_host_404(client, auth_token, fake_agent):
    resp = await client.post(
        "/api/v1/swarm/hosts/does-not-exist/teardown",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={},
    )
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_teardown_agent_failure_marks_shard_failed(
    client, auth_token, failing_agent
):
    """Background-task failure: the shard must NOT be deleted and its
    state flips to teardown_failed with the error recorded so the UI
    surfaces it."""
    from decnet.web.dependencies import repo
    uuid = await _seed_host(repo, name="tear-fail", uuid="tear-fail-uuid")
    await _seed_shard(repo, host_uuid=uuid, decky_name="survivor")

    resp = await client.post(
        f"/api/v1/swarm/hosts/{uuid}/teardown",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={},
    )
    # Acceptance is unconditional — the failure happens in the background.
    assert resp.status_code == 202

    await mod.drain_pending()

    shards = {s["decky_name"]: s for s in await repo.list_decky_shards(uuid)}
    assert "survivor" in shards
    assert shards["survivor"]["state"] == "teardown_failed"
    assert "network unreachable" in (shards["survivor"]["last_error"] or "")


@pytest.mark.anyio
async def test_teardown_non_admin_forbidden(client, viewer_token, fake_agent):
    from decnet.web.dependencies import repo
    uuid = await _seed_host(repo, name="tear-guard", uuid="tear-guard-uuid")
    resp = await client.post(
        f"/api/v1/swarm/hosts/{uuid}/teardown",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_teardown_no_auth_401(client, fake_agent):
    resp = await client.post(
        "/api/v1/swarm/hosts/whatever/teardown",
        json={},
    )
    assert resp.status_code == 401
