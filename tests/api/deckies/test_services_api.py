"""End-to-end coverage for the live service add/remove endpoints.

Covers both scopes:

* fleet:    POST/DELETE /api/v1/deckies/{decky}/services
* topology: POST/DELETE /api/v1/topologies/{id}/deckies/{decky}/services

The engine layer's ``add_service``/``remove_service`` is patched so the
tests don't shell out to docker; the auth + routing + 4xx-mapping path
runs for real.
"""
from __future__ import annotations

import httpx
import pytest

from decnet.engine.services_live import (
    ServiceConflictError,
    ServiceMutationError,
    ServiceNotFoundError,
)
from decnet.web.router.deckies import api_services


_FLEET_BASE = "/api/v1/deckies"
_TOPO_BASE = "/api/v1/topologies"


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------- fleet ---------------------------------------------------


@pytest.mark.asyncio
async def test_fleet_add_service_returns_post_mutation_list(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    async def _fake_add(repo, *, decky_kind, decky_name, service_name, topology_id=None, config=None):
        assert decky_kind == "fleet" and topology_id is None
        return ["http", service_name]
    monkeypatch.setattr(api_services, "add_service", _fake_add)

    res = await client.post(
        f"{_FLEET_BASE}/web1/services",
        json={"name": "ssh"},
        headers=_hdr(auth_token),
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["decky_name"] == "web1"
    assert body["services"] == ["http", "ssh"]
    assert body.get("topology_id") is None


@pytest.mark.asyncio
async def test_fleet_add_service_422_unknown_service(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    async def _fake_add(*a, **kw):  # noqa: RUF029
        raise ServiceMutationError("unknown service 'bogus'")
    monkeypatch.setattr(api_services, "add_service", _fake_add)
    res = await client.post(
        f"{_FLEET_BASE}/web1/services",
        json={"name": "bogus"},
        headers=_hdr(auth_token),
    )
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_fleet_add_service_409_already_present(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    async def _fake_add(*a, **kw):
        raise ServiceConflictError("service 'ssh' already on decky 'web1'")
    monkeypatch.setattr(api_services, "add_service", _fake_add)
    res = await client.post(
        f"{_FLEET_BASE}/web1/services",
        json={"name": "ssh"},
        headers=_hdr(auth_token),
    )
    assert res.status_code == 409


@pytest.mark.asyncio
async def test_fleet_remove_service_returns_remaining(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    async def _fake_remove(repo, *, decky_kind, decky_name, service_name, topology_id=None):
        return ["http"]
    monkeypatch.setattr(api_services, "remove_service", _fake_remove)
    res = await client.delete(
        f"{_FLEET_BASE}/web1/services/ssh",
        headers=_hdr(auth_token),
    )
    assert res.status_code == 200
    assert res.json()["services"] == ["http"]


@pytest.mark.asyncio
async def test_fleet_remove_service_404_decky_missing(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    async def _fake_remove(*a, **kw):
        raise ServiceNotFoundError("fleet decky 'ghost' not found")
    monkeypatch.setattr(api_services, "remove_service", _fake_remove)
    res = await client.delete(
        f"{_FLEET_BASE}/ghost/services/ssh",
        headers=_hdr(auth_token),
    )
    assert res.status_code == 404


# ---------------- topology ------------------------------------------------


@pytest.mark.asyncio
async def test_topology_add_service_returns_post_mutation_list(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    async def _fake_add(repo, *, decky_kind, topology_id, decky_name, service_name, config=None):
        assert decky_kind == "topology"
        assert topology_id == "abc123"
        return ["http", service_name]
    monkeypatch.setattr(api_services, "add_service", _fake_add)
    res = await client.post(
        f"{_TOPO_BASE}/abc123/deckies/web1/services",
        json={"name": "ssh"},
        headers=_hdr(auth_token),
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["decky_name"] == "web1"
    assert body["topology_id"] == "abc123"
    assert body["services"] == ["http", "ssh"]


@pytest.mark.asyncio
async def test_topology_remove_service_round_trip(
    client: httpx.AsyncClient, auth_token: str, monkeypatch
) -> None:
    async def _fake_remove(repo, *, decky_kind, topology_id, decky_name, service_name):
        return []
    monkeypatch.setattr(api_services, "remove_service", _fake_remove)
    res = await client.delete(
        f"{_TOPO_BASE}/abc123/deckies/router/services/dns",
        headers=_hdr(auth_token),
    )
    assert res.status_code == 200
    assert res.json()["services"] == []


# ---------------- auth ----------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_service_mutation_rejected(
    client: httpx.AsyncClient,
) -> None:
    res = await client.post(
        f"{_FLEET_BASE}/web1/services", json={"name": "ssh"},
    )
    assert res.status_code in (401, 403)
