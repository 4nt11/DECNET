"""Compose-file generator for a MazeNET topology.

Produces a ``docker-compose.yml`` dict given a hydrated topology
(the output of :func:`decnet.topology.persistence.hydrate`).  The
compose file references each LAN as an ``external: true`` network —
the deployer creates the Docker bridge networks via the SDK before
invoking ``docker compose up``.

Layout:
  * Each decky has a "base" container holding the LAN IPs.  Multi-homed
    (bridge) deckies list every LAN they belong to under ``networks``
    with the per-LAN ``ipv4_address``.
  * Bridge deckies with ``forwards_l3=True`` get ``net.ipv4.ip_forward=1``
    baked in via compose ``sysctls`` plus ``NET_ADMIN`` in ``cap_add``.
  * Service containers share the base namespace via
    ``network_mode: service:<base>``, matching the flat composer.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from decnet.services.registry import get_service

_DEFAULT_BASE_IMAGE = "debian:bookworm-slim"

_DOCKER_LOGGING = {
    "driver": "json-file",
    "options": {"max-size": "10m", "max-file": "5"},
}


def _network_name(topology_id: str, lan_name: str) -> str:
    """Docker network name for a given (topology, LAN) pair."""
    return f"decnet_t_{topology_id[:8]}_{lan_name.lower()}"


def _container_name(topology_id: str, decky_name: str) -> str:
    """Container name for a decky base in a topology."""
    return f"decnet_t_{topology_id[:8]}_{decky_name}"


def generate_topology_compose(hydrated: dict[str, Any]) -> dict:
    """Build the compose dict for a hydrated topology.

    ``hydrated`` is the shape returned by
    :func:`decnet.topology.persistence.hydrate`.
    """
    topology = hydrated["topology"]
    topology_id = topology["id"]
    lans = hydrated["lans"]
    deckies = hydrated["deckies"]

    lan_by_name = {lan["name"]: lan for lan in lans}

    services: dict[str, dict] = {}

    for decky in deckies:
        cfg = decky["decky_config"]
        name = cfg["name"]
        ips_by_lan: dict[str, str] = cfg["ips_by_lan"]
        forwards_l3: bool = cfg.get("forwards_l3", False)
        service_config: dict[str, dict] = cfg.get("service_config", {}) or {}
        svc_names: list[str] = decky["services"]

        base_key = name
        nets: dict[str, dict] = {}
        for lan_name, ip in ips_by_lan.items():
            if lan_name not in lan_by_name:
                raise ValueError(
                    f"decky {name!r} references unknown LAN {lan_name!r}"
                )
            nets[_network_name(topology_id, lan_name)] = {"ipv4_address": ip}

        base: dict = {
            "image": _DEFAULT_BASE_IMAGE,
            "container_name": _container_name(topology_id, name),
            "hostname": name,
            "command": ["sleep", "infinity"],
            "restart": "unless-stopped",
            "networks": nets,
            "cap_add": ["NET_ADMIN"],
            "logging": _DOCKER_LOGGING,
        }
        if forwards_l3:
            base["sysctls"] = {"net.ipv4.ip_forward": 1}

        services[base_key] = base

        for svc_name in svc_names:
            svc = get_service(svc_name)
            if svc is None or svc.fleet_singleton:
                continue
            fragment = svc.compose_fragment(
                name, service_cfg=service_config.get(svc_name, {})
            )
            if "build" in fragment:
                fragment["build"].setdefault("args", {}).setdefault(
                    "BASE_IMAGE", _DEFAULT_BASE_IMAGE
                )
            fragment.setdefault("environment", {})
            fragment["environment"]["HOSTNAME"] = name
            fragment["network_mode"] = f"service:{base_key}"
            fragment["depends_on"] = [base_key]
            fragment.pop("hostname", None)
            fragment.pop("networks", None)
            fragment["logging"] = _DOCKER_LOGGING
            services[f"{name}-{svc_name}"] = fragment

    networks: dict[str, dict] = {
        _network_name(topology_id, lan["name"]): {
            "external": True,
            "name": _network_name(topology_id, lan["name"]),
        }
        for lan in lans
    }

    return {
        "version": "3.8",
        "services": services,
        "networks": networks,
    }


def write_topology_compose(hydrated: dict[str, Any], output_path: Path) -> Path:
    """Write the compose dict for a hydrated topology and return the path."""
    data = generate_topology_compose(hydrated)
    output_path.write_text(
        yaml.dump(data, default_flow_style=False, sort_keys=False)
    )
    return output_path
