# SPDX-License-Identifier: AGPL-3.0-or-later
"""MazeNET topology config + in-memory generation output."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from pydantic import BaseModel, Field, model_validator


class TopologyConfig(BaseModel):
    """Parameters driving :func:`decnet.topology.generator.generate`."""

    name: str = Field(..., min_length=1, max_length=64)
    mode: str = Field(default="unihost", pattern=r"^(unihost|agent)$")

    # Topology shape
    depth: int = Field(..., ge=1, le=16, description="Max depth from DMZ")
    branching_factor: int = Field(..., ge=1, le=8, description="Max child LANs per LAN")
    deckies_per_lan_min: int = Field(default=1, ge=0, le=32)
    deckies_per_lan_max: int = Field(default=3, ge=1, le=32)

    # Probability a given non-DMZ LAN's connection to its parent uses a
    # bridge decky that forwards L3 (enables attacker pivot).  Bridge
    # existence between parent/child is implicit — every non-DMZ LAN
    # has exactly one parent bridge.  This controls *forwarding*, not
    # the existence of the bridge.
    bridge_forward_probability: float = Field(default=1.0, ge=0.0, le=1.0)

    # Probability of injecting a DAG cross-edge: a decky also bridged
    # from its LAN to a non-parent, non-child LAN.  0.0 yields a tree.
    cross_edge_probability: float = Field(default=0.0, ge=0.0, le=1.0)

    # IP allocation base.  LANs get sequential /24s carved out of this
    # network.  Accepts either a full CIDR (e.g. ``172.16.0.0/12`` for
    # 4096 slots) or the legacy two-octet shorthand ``172.20`` which
    # auto-lifts to ``172.20.0.0/16`` (256 slots).  Default is a /12
    # so mass-scale topologies (depth/branching trees with >256 LANs)
    # don't exhaust the pool on first generation.
    subnet_base_prefix: str = Field(
        default="172.16.0.0/12",
        pattern=r"^\d{1,3}\.\d{1,3}(\.\d{1,3}\.\d{1,3}/\d{1,2})?$",
    )

    # Service selection — reuses decnet.fleet.build_deckies' randomizer.
    randomize_services: bool = Field(default=True)
    services_explicit: Optional[list[str]] = None

    seed: Optional[int] = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _check_min_max(self) -> "TopologyConfig":
        if self.deckies_per_lan_min > self.deckies_per_lan_max:
            raise ValueError(
                "deckies_per_lan_min must be <= deckies_per_lan_max"
            )
        if not self.randomize_services and not self.services_explicit:
            raise ValueError(
                "either randomize_services=True or services_explicit must be set"
            )
        return self


@dataclass
class _PlannedLAN:
    """In-memory LAN record emitted by the generator."""
    name: str
    subnet: str
    is_dmz: bool
    parent: Optional[str]  # name of parent LAN, None for DMZ
    # Canvas coordinates — generator leaves them None; the web editor
    # (or a future auto-layouter) fills them in.
    x: Optional[float] = None
    y: Optional[float] = None


@dataclass
class _PlannedDecky:
    """In-memory decky record emitted by the generator."""
    name: str
    services: list[str]
    # Mapping LAN-name → assigned IP within that LAN's subnet.
    ips_by_lan: dict[str, str] = field(default_factory=dict)
    forwards_l3: bool = False  # only meaningful when present on ≥2 LANs
    # Per-service config overrides: {service_name: {field: value}}.
    # Mirrors ``DeckyConfig.service_config`` from the flat-fleet path;
    # services read these via ``compose_fragment(service_cfg=...)``.
    service_config: dict[str, dict] = field(default_factory=dict)
    # Canvas coordinates — see _PlannedLAN.x/y.
    x: Optional[float] = None
    y: Optional[float] = None


@dataclass
class _PlannedEdge:
    """In-memory (decky, LAN) membership edge."""
    decky_name: str
    lan_name: str
    is_bridge: bool
    forwards_l3: bool


@dataclass
class GeneratedTopology:
    """Full in-memory output of :func:`decnet.topology.generator.generate`.

    Names are unique within the topology.  No UUIDs are assigned here —
    those are minted by :mod:`decnet.topology.persistence` when the
    topology is written to the repo.
    """
    config: TopologyConfig
    lans: list[_PlannedLAN]
    deckies: list[_PlannedDecky]
    edges: list[_PlannedEdge]
