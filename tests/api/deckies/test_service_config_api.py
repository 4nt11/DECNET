# SPDX-License-Identifier: AGPL-3.0-or-later
"""API coverage for /services/{name}/schema + per-decky config PUT/POST.

Engine layer is patched so the tests don't touch docker; auth + routing
+ schema-serialization + 4xx mapping run for real.
"""
from __future__ import annotations

import httpx
import pytest

from decnet.engine import services_live
from decnet.engine.services_live import ServiceConflictError, ServiceMutationError
from decnet.services.base import ConfigValidationError

_FLEET = "/api/v1/deckies"
_TOPO = "/api/v1/topologies"


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------- schema endpoint -----------------------------------------


@pytest.mark.asyncio
async def test_get_ssh_schema_returns_declared_fields(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    res = await client.get(
        f"{_TOPO}/services/ssh/schema", headers=_hdr(auth_token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["name"] == "ssh"
    assert body["ports"] == [22]
    keys = {f["key"] for f in body["fields"]}
    assert keys == {"password", "user", "user_password", "hostname"}
    pw = next(f for f in body["fields"] if f["key"] == "password")
    assert pw["type"] == "password" and pw["secret"] is True


@pytest.mark.asyncio
async def test_get_unknown_service_schema_404(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    res = await client.get(
        f"{_TOPO}/services/no-such-svc/schema", headers=_hdr(auth_token),
    )
    assert res.status_code == 404


# ---------------- fleet PUT / POST apply ----------------------------------


@pytest.mark.asyncio
async def test_fleet_put_config_persists_without_recreate(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    seen: dict = {}

    async def _fake_update(repo, **kw):
        seen.update(kw)
        return {"password": "hunter2"}

    monkeypatch.setattr(
        "decnet.web.router.deckies.api_services.update_service_config",
        _fake_update,
    )
    res = await client.put(
        f"{_FLEET}/web1/services/ssh/config",
        json={"config": {"password": "hunter2"}},
        headers=_hdr(auth_token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["recreated"] is False
    assert body["config"] == {"password": "hunter2"}
    assert seen["apply"] is False and seen["decky_kind"] == "fleet"


@pytest.mark.asyncio
async def test_fleet_apply_config_triggers_recreate(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    seen: dict = {}

    async def _fake_update(repo, **kw):
        seen.update(kw)
        return kw["cfg"]

    monkeypatch.setattr(
        "decnet.web.router.deckies.api_services.update_service_config",
        _fake_update,
    )
    res = await client.post(
        f"{_FLEET}/web1/services/ssh/apply",
        json={"config": {"password": "hunter2"}},
        headers=_hdr(auth_token),
    )
    assert res.status_code == 201
    assert res.json()["recreated"] is True
    assert seen["apply"] is True


@pytest.mark.asyncio
async def test_put_config_400_on_validation_error(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    async def _fake(*a, **kw):
        raise ConfigValidationError("response_code: expected int, got 'oops'")

    monkeypatch.setattr(
        "decnet.web.router.deckies.api_services.update_service_config", _fake,
    )
    res = await client.put(
        f"{_FLEET}/web1/services/http/config",
        json={"config": {"response_code": "oops"}},
        headers=_hdr(auth_token),
    )
    assert res.status_code == 400
    assert "response_code" in res.json()["detail"]


@pytest.mark.asyncio
async def test_put_config_409_when_service_not_on_decky(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    async def _fake(*a, **kw):
        raise ServiceConflictError("service 'ssh' not on decky 'web1'")

    monkeypatch.setattr(
        "decnet.web.router.deckies.api_services.update_service_config", _fake,
    )
    res = await client.put(
        f"{_FLEET}/web1/services/ssh/config",
        json={"config": {}},
        headers=_hdr(auth_token),
    )
    assert res.status_code == 409


# ---------------- topology scope ------------------------------------------


@pytest.mark.asyncio
async def test_topology_put_config_passes_topology_id(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    seen: dict = {}

    async def _fake(repo, **kw):
        seen.update(kw)
        return kw["cfg"]

    monkeypatch.setattr(
        "decnet.web.router.deckies.api_services.update_service_config", _fake,
    )
    res = await client.put(
        f"{_TOPO}/topo-abc/deckies/web1/services/ssh/config",
        json={"config": {"hostname": "mail-01"}},
        headers=_hdr(auth_token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["topology_id"] == "topo-abc"
    assert seen["topology_id"] == "topo-abc"
    assert seen["decky_kind"] == "topology"
