"""Per-topology persona endpoints — GET/PUT /topologies/{id}/personas."""
from __future__ import annotations

import json

import pytest

from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist
from decnet.web.dependencies import repo as _repo

_V1 = "/api/v1/topologies"


def _cfg(name: str = "personas") -> TopologyConfig:
    return TopologyConfig(
        name=name,
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=1,
        deckies_per_lan_max=1,
        services_explicit=["ssh"],
        randomize_services=False,
        seed=0,
    )


async def _seed(name: str = "personas") -> str:
    return await persist(_repo, generate(_cfg(name)))


def _persona(email: str, name: str = "Jane Doe") -> dict:
    return {
        "name": name,
        "email": email,
        "role": "Admin",
        "tone": "formal",
        "mannerisms": ["uses bullet points"],
    }


@pytest.mark.anyio
async def test_get_default_empty(client, auth_token):
    tid = await _seed("get-empty")
    r = await client.get(
        f"{_V1}/{tid}/personas",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["topology_id"] == tid
    assert body["personas"] == []
    assert body["language_default"] == "en"


@pytest.mark.anyio
async def test_get_404(client, auth_token):
    r = await client.get(
        f"{_V1}/does-not-exist/personas",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_put_then_get(client, auth_token):
    tid = await _seed("put-roundtrip")
    payload = {"personas": [
        _persona("a@example.com", "Alice"),
        _persona("b@example.com", "Bob"),
    ]}
    r = await client.put(
        f"{_V1}/{tid}/personas",
        json=payload,
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200, r.text
    assert len(r.json()["personas"]) == 2

    r2 = await client.get(
        f"{_V1}/{tid}/personas",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r2.status_code == 200
    emails = [p["email"] for p in r2.json()["personas"]]
    assert emails == ["a@example.com", "b@example.com"]

    # Persisted as JSON string in the topology row.
    topo = await _repo.get_topology(tid)
    assert isinstance(topo["email_personas"], str)
    stored = json.loads(topo["email_personas"])
    assert {p["email"] for p in stored} == {"a@example.com", "b@example.com"}


@pytest.mark.anyio
async def test_put_empty_clears(client, auth_token):
    tid = await _seed("put-empty")
    await client.put(
        f"{_V1}/{tid}/personas",
        json={"personas": [_persona("x@example.com")]},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    r = await client.put(
        f"{_V1}/{tid}/personas",
        json={"personas": []},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    assert r.json()["personas"] == []


@pytest.mark.anyio
async def test_put_non_list_400(client, auth_token):
    tid = await _seed("put-non-list")
    r = await client.put(
        f"{_V1}/{tid}/personas",
        json={"personas": "not a list"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_put_all_invalid_400(client, auth_token):
    tid = await _seed("put-all-bad")
    r = await client.put(
        f"{_V1}/{tid}/personas",
        json={"personas": [{"email": "no-at-sign"}, {"name": "no-email"}]},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_put_partial_invalid_keeps_valid(client, auth_token):
    """Mirror the global-pool drop-invalid semantics.

    The endpoint silently drops bad entries; operators discover what
    landed by reading back the GET.
    """
    tid = await _seed("put-partial")
    r = await client.put(
        f"{_V1}/{tid}/personas",
        json={"personas": [
            _persona("good@example.com"),
            {"name": "missing email"},
        ]},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert [p["email"] for p in body["personas"]] == ["good@example.com"]


@pytest.mark.anyio
async def test_put_404_on_missing_topology(client, auth_token):
    r = await client.put(
        f"{_V1}/does-not-exist/personas",
        json={"personas": [_persona("x@example.com")]},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_get_does_not_shadow_existing_topology_id(client, auth_token):
    """Ensure the personas subroute is registered before the bare /{id}.

    If the literal `/personas` segment got shadowed by the parameterized
    `/{id}` route, GET would return the topology body instead of 404 for
    a missing personas resource.  Sanity-check the order.
    """
    tid = await _seed("shadow-check")
    r = await client.get(
        f"{_V1}/{tid}/personas",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    assert "personas" in r.json()
