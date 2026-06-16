# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verify BaseRepository structurally satisfies TopologyRepository."""

_PROTOCOL_METHODS = {
    "create_topology",
    "get_topology",
    "update_topology_status",
    "list_topologies",
    "add_lan",
    "list_lans_for_topology",
    "add_topology_decky",
    "list_topology_deckies",
    "add_topology_edge",
    "list_topology_edges",
}


def test_base_repository_satisfies_protocol() -> None:
    from decnet.web.db.repository import BaseRepository

    for name in _PROTOCOL_METHODS:
        assert hasattr(BaseRepository, name), f"BaseRepository missing {name!r}"
