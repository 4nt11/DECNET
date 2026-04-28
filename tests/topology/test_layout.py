"""Layout coordinate roundtrips for LAN and TopologyDecky."""
from __future__ import annotations

import pytest

from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import hydrate, persist
from decnet.web.db.factory import get_repository


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="layout",
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=1,
        deckies_per_lan_max=1,
        cross_edge_probability=0.0,
        randomize_services=False,
        services_explicit=["ssh"],
        seed=4,
    )
    base.update(kw)
    return TopologyConfig(**base)


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "layout.db"))
    await r.initialize()
    return r


@pytest.mark.anyio
async def test_coords_roundtrip_when_set(repo):
    plan = generate(_cfg())
    plan.lans[0].x = 10.5
    plan.lans[0].y = -3.25
    plan.deckies[0].x = 42.0
    plan.deckies[0].y = 7.5
    tid = await persist(repo, plan)
    hydrated = await hydrate(repo, tid)
    lan = next(l for l in hydrated["lans"] if l["name"] == plan.lans[0].name)
    assert lan["x"] == 10.5 and lan["y"] == -3.25
    d = next(d for d in hydrated["deckies"] if d["name"] == plan.deckies[0].name)
    assert d["x"] == 42.0 and d["y"] == 7.5


@pytest.mark.anyio
async def test_coords_default_to_none(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    hydrated = await hydrate(repo, tid)
    for lan in hydrated["lans"]:
        assert lan["x"] is None and lan["y"] is None
    for d in hydrated["deckies"]:
        assert d["x"] is None and d["y"] is None
