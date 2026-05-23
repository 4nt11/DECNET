# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit coverage for decnet.decky_io.resolve — container-name helpers."""
from __future__ import annotations

import pytest

from decnet.decky_io import (
    resolve_decky_container,
    resolve_topology_container,
)


def test_resolve_topology_container_prefers_ssh_service() -> None:
    assert resolve_topology_container(
        "abc123def456", "web1", services=["ssh", "http"],
    ) == "web1-ssh"


def test_resolve_topology_container_falls_back_to_base_when_no_ssh() -> None:
    assert resolve_topology_container(
        "abc123def456789", "router", services=["dns"],
    ) == "decnet_t_abc123de_router"


@pytest.mark.asyncio
async def test_resolve_decky_container_fleet_path_returns_ssh_suffix() -> None:
    # Fleet path needs no I/O — repo can be anything.
    container = await resolve_decky_container(None, "web1")
    assert container == "web1-ssh"


@pytest.mark.asyncio
async def test_resolve_decky_container_topology_path_uses_services_list(
    monkeypatch,
) -> None:
    async def _fake_hydrate(_repo, _topo_id):
        return {
            "topology": {"id": _topo_id},
            "lans": [],
            "deckies": [
                {
                    "uuid": "u1", "name": "web1",
                    "decky_config": {"name": "web1"},
                    "services": ["ssh"],
                },
                {
                    "uuid": "u2", "name": "router",
                    "decky_config": {"name": "router"},
                    "services": ["dns"],
                },
            ],
            "edges": [],
        }
    monkeypatch.setattr(
        "decnet.topology.persistence.hydrate", _fake_hydrate,
    )
    assert await resolve_decky_container(
        None, "web1", topology_id="abcdef0123456789",
    ) == "web1-ssh"
    assert await resolve_decky_container(
        None, "router", topology_id="abcdef0123456789",
    ) == "decnet_t_abcdef01_router"


@pytest.mark.asyncio
async def test_resolve_decky_container_raises_when_topology_missing(
    monkeypatch,
) -> None:
    async def _none(_repo, _topo_id):
        return None
    monkeypatch.setattr("decnet.topology.persistence.hydrate", _none)
    with pytest.raises(LookupError, match="topology .* not found"):
        await resolve_decky_container(None, "x", topology_id="ghost")


@pytest.mark.asyncio
async def test_resolve_decky_container_raises_when_decky_not_in_topology(
    monkeypatch,
) -> None:
    async def _fake(_repo, _topo_id):
        return {
            "topology": {"id": _topo_id},
            "lans": [], "edges": [],
            "deckies": [{
                "uuid": "u1", "name": "other",
                "decky_config": {"name": "other"},
                "services": [],
            }],
        }
    monkeypatch.setattr("decnet.topology.persistence.hydrate", _fake)
    with pytest.raises(LookupError, match="not in topology"):
        await resolve_decky_container(
            None, "missing", topology_id="abcdef0123456789",
        )
