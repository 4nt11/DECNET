# SPDX-License-Identifier: AGPL-3.0-or-later
"""Backward-compatibility tests for the SWARM state-schema extension.

DeckyConfig gained an optional ``host_uuid`` field in swarm mode.  Existing
state files (unihost) must continue to deserialize without change.
"""
from __future__ import annotations

from decnet.models import DeckyConfig, DecnetConfig


def _minimal_decky(name: str = "decky-01") -> dict:
    return {
        "name": name,
        "ip": "192.168.1.10",
        "services": ["ssh"],
        "distro": "debian",
        "base_image": "debian:bookworm-slim",
        "hostname": "decky01",
    }


def test_decky_config_host_uuid_defaults_to_none() -> None:
    """A decky built from a pre-swarm state blob lands with host_uuid=None."""
    d = DeckyConfig(**_minimal_decky())
    assert d.host_uuid is None


def test_decky_config_accepts_host_uuid() -> None:
    d = DeckyConfig(**_minimal_decky(), host_uuid="host-uuid-abc")
    assert d.host_uuid == "host-uuid-abc"


def test_decnet_config_mode_swarm_with_host_assignments() -> None:
    """Full swarm-mode config: every decky carries a host_uuid."""
    config = DecnetConfig(
        mode="swarm",
        interface="eth0",
        subnet="192.168.1.0/24",
        gateway="192.168.1.1",
        deckies=[
            DeckyConfig(**_minimal_decky("decky-01"), host_uuid="host-A"),
            DeckyConfig(**_minimal_decky("decky-02"), host_uuid="host-B"),
        ],
    )
    assert config.mode == "swarm"
    assert {d.host_uuid for d in config.deckies} == {"host-A", "host-B"}


def test_legacy_unihost_state_still_parses() -> None:
    """A dict matching the pre-swarm schema deserializes unchanged."""
    legacy_blob = {
        "mode": "unihost",
        "interface": "eth0",
        "subnet": "192.168.1.0/24",
        "gateway": "192.168.1.1",
        "deckies": [_minimal_decky()],
    }
    config = DecnetConfig.model_validate(legacy_blob)
    assert config.mode == "unihost"
    assert config.deckies[0].host_uuid is None
