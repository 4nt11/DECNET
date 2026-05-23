# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for :mod:`decnet.topology.hashing`."""
from __future__ import annotations

import copy

from decnet.topology.hashing import canonical_hash


def _sample() -> dict:
    return {
        "topology": {
            "id": "t1",
            "name": "n",
            "mode": "agent",
            "target_host_uuid": "h1",
            "status": "deploying",
            "version": 3,
            "created_at": "2026-04-21T00:00:00+00:00",
        },
        "lans": [
            {"id": "l1", "name": "dmz", "subnet": "10.0.0.0/24", "is_dmz": True,
             "x": 40, "y": 40},
        ],
        "deckies": [
            {
                "uuid": "d1",
                "name": "gw",
                "services": ["ssh"],
                "decky_config": {"archetype": "deaddeck", "forwards_l3": True},
                "state": "pending",
                "x": 10,
                "y": 20,
            }
        ],
        "edges": [
            {"id": "e1", "decky_uuid": "d1", "lan_id": "l1",
             "is_bridge": True, "forwards_l3": True},
        ],
    }


def test_hash_is_stable() -> None:
    assert canonical_hash(_sample()) == canonical_hash(_sample())


def test_key_order_does_not_matter() -> None:
    a = _sample()
    b = {
        "edges": a["edges"],
        "deckies": a["deckies"],
        "lans": a["lans"],
        "topology": a["topology"],
    }
    assert canonical_hash(a) == canonical_hash(b)


def test_volatile_fields_ignored() -> None:
    a = _sample()
    b = copy.deepcopy(a)
    b["topology"]["status"] = "active"
    b["topology"]["version"] = 99
    b["topology"]["status_changed_at"] = "2099-01-01T00:00:00+00:00"
    b["deckies"][0]["last_error"] = "transient"
    b["deckies"][0]["x"] = 9999
    b["lans"][0]["y"] = 12345
    assert canonical_hash(a) == canonical_hash(b)


def test_behavioural_change_flips_hash() -> None:
    a = _sample()
    b = copy.deepcopy(a)
    b["deckies"][0]["services"] = ["ssh", "http"]
    assert canonical_hash(a) != canonical_hash(b)


def test_input_is_not_mutated() -> None:
    a = _sample()
    snapshot = copy.deepcopy(a)
    _ = canonical_hash(a)
    assert a == snapshot
