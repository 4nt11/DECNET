"""Direct async tests for MazeNET topology persistence.

Exercises the repository layer without going through the HTTP stack or
the in-memory generator.  The synthetic topology here is hand-built so
the test remains meaningful even if generator.py regresses.
"""
import pytest
from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "mazenet.db"))
    await r.initialize()
    return r


@pytest.mark.anyio
async def test_topology_roundtrip(repo):
    t_id = await repo.create_topology(
        {
            "name": "alpha",
            "mode": "unihost",
            "config_snapshot": {"depth": 3, "seed": 42},
        }
    )
    assert t_id
    t = await repo.get_topology(t_id)
    assert t is not None
    assert t.name == "alpha"
    assert t.status == "pending"


@pytest.mark.anyio
async def test_lan_add_update_list(repo):
    t_id = await repo.create_topology(
        {"name": "beta", "mode": "unihost", "config_snapshot": {}}
    )
    lan_id = await repo.add_lan(
        {"topology_id": t_id, "name": "DMZ", "subnet": "172.20.0.0/24", "is_dmz": True}
    )
    await repo.add_lan(
        {"topology_id": t_id, "name": "LAN-A", "subnet": "172.20.1.0/24"}
    )
    await repo.update_lan(lan_id, {"docker_network_id": "abc123"})
    lans = await repo.list_lans_for_topology(t_id)
    assert len(lans) == 2
    by_name = {lan.name: lan for lan in lans}
    assert by_name["DMZ"].docker_network_id == "abc123"
    assert by_name["DMZ"].is_dmz is True
    assert by_name["LAN-A"].is_dmz is False


@pytest.mark.anyio
async def test_topology_decky_json_roundtrip(repo):
    t_id = await repo.create_topology(
        {"name": "gamma", "mode": "unihost", "config_snapshot": {}}
    )
    d_uuid = await repo.add_topology_decky(
        {
            "topology_id": t_id,
            "name": "decky-01",
            "services": ["ssh", "http"],
            "decky_config": {"hostname": "bastion"},
            "ip": "172.20.0.10",
        }
    )
    assert d_uuid
    deckies = await repo.list_topology_deckies(t_id)
    assert len(deckies) == 1
    assert deckies[0].services == ["ssh", "http"]
    assert deckies[0].decky_config == {"hostname": "bastion"}
    assert deckies[0].state == "pending"

    await repo.update_topology_decky(d_uuid, {"state": "running", "ip": "172.20.0.11"})
    deckies = await repo.list_topology_deckies(t_id)
    assert deckies[0].state == "running"
    assert deckies[0].ip == "172.20.0.11"


@pytest.mark.anyio
async def test_topology_decky_name_unique_within_topology(repo):
    """Same decky name is legal across topologies, forbidden within one."""
    t1 = await repo.create_topology(
        {"name": "one", "mode": "unihost", "config_snapshot": {}}
    )
    t2 = await repo.create_topology(
        {"name": "two", "mode": "unihost", "config_snapshot": {}}
    )
    await repo.add_topology_decky(
        {"topology_id": t1, "name": "decky-01", "services": []}
    )
    # Same name, different topology — must succeed.
    await repo.add_topology_decky(
        {"topology_id": t2, "name": "decky-01", "services": []}
    )
    # Same name, same topology — must fail at the DB level.
    with pytest.raises(Exception):
        await repo.add_topology_decky(
            {"topology_id": t1, "name": "decky-01", "services": []}
        )


@pytest.mark.anyio
async def test_status_transition_writes_event(repo):
    t_id = await repo.create_topology(
        {"name": "delta", "mode": "unihost", "config_snapshot": {}}
    )
    await repo.update_topology_status(t_id, "deploying", reason="kickoff")
    await repo.update_topology_status(t_id, "active")
    topo = await repo.get_topology(t_id)
    assert topo.status == "active"

    events = await repo.list_topology_status_events(t_id)
    assert len(events) == 2
    # Ordered desc by at — latest first
    assert events[0]["to_status"] == "active"
    assert events[0]["from_status"] == "deploying"
    assert events[1]["to_status"] == "deploying"
    assert events[1]["from_status"] == "pending"
    assert events[1]["reason"] == "kickoff"


@pytest.mark.anyio
async def test_cascade_delete_clears_all_children(repo):
    t_id = await repo.create_topology(
        {"name": "eps", "mode": "unihost", "config_snapshot": {}}
    )
    lan_id = await repo.add_lan(
        {"topology_id": t_id, "name": "L", "subnet": "10.0.0.0/24"}
    )
    d_uuid = await repo.add_topology_decky(
        {"topology_id": t_id, "name": "d", "services": []}
    )
    await repo.add_topology_edge(
        {"topology_id": t_id, "decky_uuid": d_uuid, "lan_id": lan_id}
    )
    await repo.update_topology_status(t_id, "deploying")
    await repo.enqueue_topology_mutation(t_id, "noop", {"x": 1})

    assert await repo.delete_topology_cascade(t_id) is True
    assert await repo.get_topology(t_id) is None
    assert await repo.list_lans_for_topology(t_id) == []
    assert await repo.list_topology_deckies(t_id) == []
    assert await repo.list_topology_edges(t_id) == []
    assert await repo.list_topology_status_events(t_id) == []
    # Second delete on a missing row returns False, no raise
    assert await repo.delete_topology_cascade(t_id) is False


@pytest.mark.anyio
async def test_list_topologies_filters_by_status(repo):
    a = await repo.create_topology(
        {"name": "a", "mode": "unihost", "config_snapshot": {}}
    )
    b = await repo.create_topology(
        {"name": "b", "mode": "unihost", "config_snapshot": {}}
    )
    await repo.update_topology_status(b, "deploying")
    pend = await repo.list_topologies(status="pending")
    assert {t.id for t in pend} == {a}
    dep = await repo.list_topologies(status="deploying")
    assert {t.id for t in dep} == {b}
    both = await repo.list_topologies()
    assert {t.id for t in both} == {a, b}
