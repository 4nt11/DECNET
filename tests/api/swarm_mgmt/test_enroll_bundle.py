"""Agent-enrollment bundle flow: POST → .sh → .tgz (one-shot, TTL, races)."""
from __future__ import annotations

import asyncio
import io
import pathlib
import tarfile
from datetime import datetime, timedelta, timezone

import pytest

from decnet.swarm import pki
from decnet.web.router.swarm_mgmt import api_enroll_bundle as mod


@pytest.fixture(autouse=True)
def isolate_bundle_state(tmp_path: pathlib.Path, monkeypatch):
    """Point BUNDLE_DIR + CA into tmp, clear the in-memory registry."""
    monkeypatch.setattr(mod, "BUNDLE_DIR", tmp_path / "bundles")
    monkeypatch.setattr(pki, "DEFAULT_CA_DIR", tmp_path / "ca")
    mod._BUNDLES.clear()
    if mod._SWEEPER_TASK is not None and not mod._SWEEPER_TASK.done():
        mod._SWEEPER_TASK.cancel()
    mod._SWEEPER_TASK = None
    yield
    # Cleanup sweeper task between tests so they don't accumulate.
    if mod._SWEEPER_TASK is not None and not mod._SWEEPER_TASK.done():
        mod._SWEEPER_TASK.cancel()
    mod._SWEEPER_TASK = None


async def _post(client, auth_token, **overrides):
    body = {
        "master_host": "10.0.0.50",
        "agent_name": "worker-a",
        "agent_host": "10.0.0.100",
        "with_updater": True,
    }
    body.update(overrides)
    return await client.post(
        "/api/v1/swarm/enroll-bundle",
        headers={"Authorization": f"Bearer {auth_token}"},
        json=body,
    )


@pytest.mark.anyio
async def test_create_bundle_returns_one_liner(client, auth_token):
    resp = await _post(client, auth_token)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["token"]
    assert body["host_uuid"]
    assert body["command"].startswith("curl -fsSL ")
    assert body["command"].endswith(" | sudo bash")
    assert "&&" not in body["command"]  # single pipe, no chaining
    assert body["token"] in body["command"]
    expires = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    assert timedelta(minutes=4) < expires - now <= timedelta(minutes=5)


@pytest.mark.anyio
async def test_bundle_urls_use_master_host_not_request_base(client, auth_token):
    """URLs baked into the bootstrap must target the operator-supplied
    master_host, not the dashboard's request.base_url (which may be loopback
    behind a proxy)."""
    resp = await _post(client, auth_token, master_host="10.20.30.40", agent_name="urltest")
    assert resp.status_code == 201
    body = resp.json()
    assert "10.20.30.40" in body["command"]
    assert "127.0.0.1" not in body["command"]
    assert "testserver" not in body["command"]

    token = body["token"]
    sh = (await client.get(f"/api/v1/swarm/enroll-bundle/{token}.sh")).text
    assert "10.20.30.40" in sh
    assert "127.0.0.1" not in sh
    assert "testserver" not in sh


@pytest.mark.anyio
async def test_duplicate_agent_name_409(client, auth_token):
    r1 = await _post(client, auth_token, agent_name="dup-node")
    assert r1.status_code == 201
    r2 = await _post(client, auth_token, agent_name="dup-node")
    assert r2.status_code == 409


@pytest.mark.anyio
async def test_non_admin_forbidden(client, viewer_token):
    resp = await _post(client, viewer_token)
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_no_auth_401(client):
    resp = await client.post(
        "/api/v1/swarm/enroll-bundle",
        json={"master_host": "10.0.0.50", "agent_name": "worker-a", "agent_host": "10.0.0.100"},
    )
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_host_row_uses_agent_host_not_master_host(client, auth_token):
    """SwarmHosts table should show the worker's own address, not the master's."""
    from decnet.web.dependencies import repo
    resp = await _post(client, auth_token, agent_name="addr-test",
                       master_host="192.168.1.5", agent_host="192.168.1.23")
    row = await repo.get_swarm_host_by_uuid(resp.json()["host_uuid"])
    assert row["address"] == "192.168.1.23"


@pytest.mark.anyio
async def test_updater_opt_out_excludes_updater_artifacts(client, auth_token):
    import io, tarfile
    token = (await _post(client, auth_token, agent_name="noup", with_updater=False)).json()["token"]
    resp = await client.get(f"/api/v1/swarm/enroll-bundle/{token}.tgz")
    tf = tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz")
    names = set(tf.getnames())
    assert not any(n.startswith("home/.decnet/updater/") for n in names)
    sh_token = (await _post(client, auth_token, agent_name="noup2", with_updater=False)).json()["token"]
    sh = (await client.get(f"/api/v1/swarm/enroll-bundle/{sh_token}.sh")).text
    assert 'WITH_UPDATER="false"' in sh


@pytest.mark.anyio
async def test_updater_opt_in_ships_cert_and_starts_daemon(client, auth_token):
    import io, tarfile
    token = (await _post(client, auth_token, agent_name="up", with_updater=True)).json()["token"]
    resp = await client.get(f"/api/v1/swarm/enroll-bundle/{token}.tgz")
    tf = tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz")
    names = set(tf.getnames())
    assert "home/.decnet/updater/updater.crt" in names
    assert "home/.decnet/updater/updater.key" in names
    key_info = tf.getmember("home/.decnet/updater/updater.key")
    assert (key_info.mode & 0o777) == 0o600
    sh_token = (await _post(client, auth_token, agent_name="up2", with_updater=True)).json()["token"]
    sh = (await client.get(f"/api/v1/swarm/enroll-bundle/{sh_token}.sh")).text
    assert 'WITH_UPDATER="true"' in sh
    assert "decnet updater --daemon" in sh


@pytest.mark.anyio
async def test_invalid_agent_name_422(client, auth_token):
    # Uppercase / underscore not allowed by the regex.
    resp = await _post(client, auth_token, agent_name="Bad_Name")
    assert resp.status_code in (400, 422)


@pytest.mark.anyio
async def test_get_bootstrap_contains_expected(client, auth_token):
    post = await _post(client, auth_token, agent_name="alpha", master_host="master.example")
    token = post.json()["token"]

    resp = await client.get(f"/api/v1/swarm/enroll-bundle/{token}.sh")
    assert resp.status_code == 200
    text = resp.text
    assert text.startswith("#!/usr/bin/env bash")
    assert "alpha" in text
    assert "master.example" in text
    assert f"/api/v1/swarm/enroll-bundle/{token}.tgz" in text
    # Script does NOT try to self-read with $0 (that would break under `curl | bash`).
    assert 'tail -n +' not in text and 'awk' not in text


@pytest.mark.anyio
async def test_get_bootstrap_is_idempotent_until_tgz_served(client, auth_token):
    token = (await _post(client, auth_token, agent_name="beta")).json()["token"]
    for _ in range(3):
        assert (await client.get(f"/api/v1/swarm/enroll-bundle/{token}.sh")).status_code == 200


@pytest.mark.anyio
async def test_get_tgz_contents(client, auth_token, tmp_path):
    token = (await _post(
        client, auth_token,
        agent_name="gamma", master_host="10.1.2.3",
        services_ini="[general]\nnet = 10.0.0.0/24\n",
    )).json()["token"]

    resp = await client.get(f"/api/v1/swarm/enroll-bundle/{token}.tgz")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/gzip")

    tf = tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz")
    names = set(tf.getnames())

    # Required files
    assert "etc/decnet/decnet.ini" in names
    assert "home/.decnet/agent/ca.crt" in names
    assert "home/.decnet/agent/worker.crt" in names
    assert "home/.decnet/agent/worker.key" in names
    assert "services.ini" in names
    assert "decnet/cli.py" in names  # source shipped
    assert "pyproject.toml" in names

    # Excluded paths must NOT be shipped
    for bad in names:
        assert not bad.startswith("tests/"), f"leaked test file: {bad}"
        assert not bad.startswith("development/"), f"leaked dev file: {bad}"
        assert not bad.startswith("wiki-checkout/"), f"leaked wiki file: {bad}"
        assert "__pycache__" not in bad
        assert not bad.endswith(".pyc")
        assert "node_modules" not in bad
        # Dev-host env leaks would bake absolute master paths into the agent.
        assert not bad.endswith(".env"), f"leaked env file: {bad}"
        assert ".env.local" not in bad, f"leaked env file: {bad}"
        assert ".env.example" not in bad, f"leaked env file: {bad}"

    # INI content is correct
    ini = tf.extractfile("etc/decnet/decnet.ini").read().decode()
    assert "mode = agent" in ini
    assert "master-host = 10.1.2.3" in ini

    # Key is mode 0600
    key_info = tf.getmember("home/.decnet/agent/worker.key")
    assert (key_info.mode & 0o777) == 0o600

    # Services INI is there
    assert tf.extractfile("services.ini").read().decode().startswith("[general]")


@pytest.mark.anyio
async def test_tgz_is_one_shot(client, auth_token):
    token = (await _post(client, auth_token, agent_name="delta")).json()["token"]
    r1 = await client.get(f"/api/v1/swarm/enroll-bundle/{token}.tgz")
    assert r1.status_code == 200
    r2 = await client.get(f"/api/v1/swarm/enroll-bundle/{token}.tgz")
    assert r2.status_code == 404
    # .sh also invalidated after .tgz served (the host is up; replay is pointless)
    r3 = await client.get(f"/api/v1/swarm/enroll-bundle/{token}.sh")
    assert r3.status_code == 404


@pytest.mark.anyio
async def test_unknown_token_404(client):
    assert (await client.get("/api/v1/swarm/enroll-bundle/not-a-real-token.sh")).status_code == 404
    assert (await client.get("/api/v1/swarm/enroll-bundle/not-a-real-token.tgz")).status_code == 404


@pytest.mark.anyio
async def test_ttl_expiry_returns_404(client, auth_token, monkeypatch):
    token = (await _post(client, auth_token, agent_name="epsilon")).json()["token"]

    # Jump the clock 6 minutes into the future.
    future = datetime.now(timezone.utc) + timedelta(minutes=6)
    monkeypatch.setattr(mod, "_now", lambda: future)

    assert (await client.get(f"/api/v1/swarm/enroll-bundle/{token}.sh")).status_code == 404
    assert (await client.get(f"/api/v1/swarm/enroll-bundle/{token}.tgz")).status_code == 404


@pytest.mark.anyio
async def test_concurrent_tgz_exactly_one_wins(client, auth_token):
    token = (await _post(client, auth_token, agent_name="zeta")).json()["token"]
    url = f"/api/v1/swarm/enroll-bundle/{token}.tgz"
    r1, r2 = await asyncio.gather(client.get(url), client.get(url))
    statuses = sorted([r1.status_code, r2.status_code])
    assert statuses == [200, 404]


@pytest.mark.anyio
async def test_host_row_persisted_after_enroll(client, auth_token):
    from decnet.web.dependencies import repo
    resp = await _post(client, auth_token, agent_name="eta")
    assert resp.status_code == 201
    body = resp.json()
    row = await repo.get_swarm_host_by_uuid(body["host_uuid"])
    assert row is not None
    assert row["name"] == "eta"
    assert row["status"] == "enrolled"
