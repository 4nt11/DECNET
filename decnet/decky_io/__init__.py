# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared primitives for writing/deleting files inside running deckies.

The canary planter and the orchestrator SSH driver both need to drop
bytes into a decky container's filesystem, then sometimes unlink them.
The ARG_MAX-safe ``base64 -d``-via-stdin trick lived in two places
before this module existed.

Public API:

* :func:`write_file_to_container` — write bytes at a path, set mode,
  optionally backdate mtime.
* :func:`delete_file_from_container` — best-effort ``rm -f``.
* :func:`resolve_topology_container` — pick the right docker container
  for a MazeNET decky based on its services list.
* :func:`resolve_decky_container` — async helper that takes
  ``(decky_name, topology_id?)``, hydrates the topology when needed,
  and returns the docker container name.

Container resolution conventions are documented in
:mod:`decnet.topology.compose`; we mirror them here without taking
a runtime dependency on the compose generator.
"""
from __future__ import annotations

from .resolve import (
    resolve_decky_container,
    resolve_topology_container,
)
from .write import (
    delete_file_from_container,
    write_file_to_container,
)

__all__ = [
    "delete_file_from_container",
    "resolve_decky_container",
    "resolve_topology_container",
    "write_file_to_container",
]
