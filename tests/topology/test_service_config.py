"""Per-decky, per-service config roundtrips through persist + compose."""
from __future__ import annotations

import pytest
import yaml

from decnet.topology.compose import generate_topology_compose
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import hydrate, persist
from decnet.web.db.factory import get_repository


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="svc",
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=1,
        deckies_per_lan_max=1,
        cross_edge_probability=0.0,
        randomize_services=False,
        services_explicit=["ssh"],
        seed=5,
    )
    base.update(kw)
    return TopologyConfig(**base)


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "svc.db"))
    await r.initialize()
    return r


@pytest.mark.anyio
async def test_service_config_roundtrips(repo):
    plan = generate(_cfg())
    # Operator-style override, as the web editor would write it.
    plan.deckies[0].service_config = {"ssh": {"password": "megapassword"}}
    tid = await persist(repo, plan)

    hydrated = await hydrate(repo, tid)
    decky = next(
        d for d in hydrated["deckies"] if d["name"] == plan.deckies[0].name
    )
    assert decky["decky_config"]["service_config"] == {
        "ssh": {"password": "megapassword"}
    }


@pytest.mark.anyio
async def test_service_config_reaches_compose_fragment(repo):
    plan = generate(_cfg())
    plan.deckies[0].service_config = {"ssh": {"password": "megapassword"}}
    tid = await persist(repo, plan)

    hydrated = await hydrate(repo, tid)
    compose = generate_topology_compose(hydrated)
    # The ssh fragment keys are "<decky>-ssh" (see compose.py:107).
    ssh_key = f"{plan.deckies[0].name}-ssh"
    frag = compose["services"][ssh_key]
    env = frag.get("environment", {})
    assert env.get("SSH_ROOT_PASSWORD") == "megapassword"


@pytest.mark.anyio
async def test_missing_service_config_defaults_work(repo):
    """No service_config override → service falls back to its default."""
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    hydrated = await hydrate(repo, tid)
    compose = generate_topology_compose(hydrated)
    ssh_key = f"{plan.deckies[0].name}-ssh"
    frag = compose["services"][ssh_key]
    assert frag["environment"]["SSH_ROOT_PASSWORD"] == "admin"


@pytest.mark.anyio
async def test_unknown_nested_key_passes_through(repo):
    """Forward-compat: unknown keys under a service reach the fragment
    untouched (current services ignore them; future services may read)."""
    plan = generate(_cfg())
    plan.deckies[0].service_config = {
        "ssh": {"password": "x", "future_flag": "hi"}
    }
    tid = await persist(repo, plan)
    hydrated = await hydrate(repo, tid)
    decky = next(
        d for d in hydrated["deckies"] if d["name"] == plan.deckies[0].name
    )
    assert (
        decky["decky_config"]["service_config"]["ssh"]["future_flag"] == "hi"
    )


@pytest.mark.anyio
async def test_compose_file_yaml_is_loadable(repo):
    """Regression: the compose dict roundtrips through yaml cleanly."""
    plan = generate(_cfg())
    plan.deckies[0].service_config = {"ssh": {"password": "roundtrip"}}
    tid = await persist(repo, plan)
    hydrated = await hydrate(repo, tid)
    compose = generate_topology_compose(hydrated)
    dumped = yaml.dump(compose, sort_keys=False)
    reloaded = yaml.safe_load(dumped)
    ssh_key = f"{plan.deckies[0].name}-ssh"
    assert (
        reloaded["services"][ssh_key]["environment"]["SSH_ROOT_PASSWORD"]
        == "roundtrip"
    )
