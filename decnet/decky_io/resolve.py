# SPDX-License-Identifier: AGPL-3.0-or-later
"""Decky-name → docker container name resolution.

Two scopes:

* **Fleet**: every fleet decky has a ``ssh`` service container named
  ``<decky_name>-ssh`` (see :mod:`decnet.services.ssh`).  We always
  target it because it carries the most realistic filesystem layout.
* **MazeNET (topology)**: same ``<name>-ssh`` convention when the
  decky exposes the ssh service; otherwise the decky's base container
  named ``decnet_t_<topology_id8>_<decky_name>`` (matches
  :func:`decnet.topology.compose._container_name`).

Keeping resolution centralised here means new ``docker exec`` callers
(file drops, future bulk planters, etc.) never need to learn the
naming conventions — they just call :func:`resolve_decky_container`.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

_SSH_CONTAINER_SUFFIX = "-ssh"


def resolve_topology_container(
    topology_id: str, decky_name: str, services: Iterable[str],
) -> str:
    """Container name for a MazeNET decky.

    See module docstring for the convention.  Pure function — no I/O.
    """
    if "ssh" in set(services):
        return f"{decky_name}{_SSH_CONTAINER_SUFFIX}"
    return f"decnet_t_{topology_id[:8]}_{decky_name}"


async def resolve_decky_container(
    repo: Any,
    decky_name: str,
    *,
    topology_id: Optional[str] = None,
) -> str:
    """Resolve the docker container name for *decky_name*.

    Fleet path (``topology_id is None``): returns ``<decky_name>-ssh``
    unconditionally.  No DB lookup — the caller is responsible for
    knowing the decky exists; if it doesn't, the subsequent
    ``docker exec`` returns a clear error.

    Topology path: hydrates the topology, looks up the decky's services
    list, delegates to :func:`resolve_topology_container`.

    Raises:
        LookupError — when ``topology_id`` is set but the topology or
        its named decky doesn't exist.  Callers translate this into
        404/422 at the API layer.
    """
    if topology_id is None:
        return f"{decky_name}{_SSH_CONTAINER_SUFFIX}"

    from decnet.topology.persistence import hydrate
    hydrated = await hydrate(repo, topology_id)
    if hydrated is None:
        raise LookupError(f"topology {topology_id!r} not found")
    for decky in hydrated["deckies"]:
        cfg = decky.get("decky_config") or {}
        name = cfg.get("name") or decky.get("name")
        if name == decky_name:
            services = decky.get("services") or []
            return resolve_topology_container(topology_id, decky_name, services)
    raise LookupError(
        f"decky {decky_name!r} is not in topology {topology_id!r}"
    )
