import pytest

from decnet.web.dependencies import repo


@pytest.fixture(autouse=True)
def enable_developer_mode(monkeypatch):
    monkeypatch.setattr("decnet.web.router.config.api_reinit.DECNET_DEVELOPER", True)
    monkeypatch.setattr("decnet.web.router.config.api_get_config.DECNET_DEVELOPER", True)


@pytest.mark.anyio
async def test_reinit_purges_data(client, auth_token):
    """Admin can purge all logs, bounties, and attackers in developer mode."""
    # Seed some data
    await repo.add_log({
        "decky": "d1", "service": "ssh", "event_type": "connect",
        "attacker_ip": "1.2.3.4", "raw_line": "test", "fields": "{}",
    })
    await repo.add_bounty({
        "decky": "d1", "service": "ssh", "attacker_ip": "1.2.3.4",
        "bounty_type": "credential", "payload": '{"user":"root"}',
    })

    resp = await client.delete(
        "/api/v1/config/reinit",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["deleted"]["logs"] >= 1
    assert data["deleted"]["bounties"] >= 1


@pytest.mark.anyio
async def test_reinit_viewer_forbidden(client, auth_token, viewer_token):
    resp = await client.delete(
        "/api/v1/config/reinit",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_reinit_forbidden_without_developer_mode(client, auth_token, monkeypatch):
    monkeypatch.setattr("decnet.web.router.config.api_reinit.DECNET_DEVELOPER", False)

    resp = await client.delete(
        "/api/v1/config/reinit",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 403
    assert "developer mode" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_config_includes_developer_mode(client, auth_token):
    """Admin config response includes developer_mode when enabled."""
    resp = await client.get(
        "/api/v1/config",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["developer_mode"] is True


@pytest.mark.anyio
async def test_config_excludes_developer_mode_when_disabled(client, auth_token, monkeypatch):
    monkeypatch.setattr("decnet.web.router.config.api_get_config.DECNET_DEVELOPER", False)

    resp = await client.get(
        "/api/v1/config",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    assert "developer_mode" not in resp.json()
