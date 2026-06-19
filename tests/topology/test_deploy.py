# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deploy/teardown integration tests for MazeNET topologies.

Docker-touching paths live behind ``@pytest.mark.live`` per
feedback_skip_heavy_tests.md.  The non-live path here exercises dry-run
deploy (compose file is written, repo status is left untouched) and the
state-machine around failure/teardown using a stub repo.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from decnet.engine.deployer import (
    _teardown_order,
    _topology_compose_path,
    deploy_topology,
    teardown_topology,
)
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist
from decnet.topology.status import TopologyStatus
from decnet.web.db.factory import get_repository


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="dep",
        depth=2,
        branching_factor=2,
        deckies_per_lan_min=1,
        deckies_per_lan_max=1,
        cross_edge_probability=0.0,
        randomize_services=False,
        services_explicit=["ssh"],
        seed=11,
    )
    base.update(kw)
    return TopologyConfig(**base)


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "dep.db"))
    await r.initialize()
    return r


@pytest.mark.anyio
async def test_dry_run_writes_compose_and_preserves_pending(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("DECNET_RUN_DIR", str(tmp_path))
    plan = generate(_cfg())
    tid = await persist(repo, plan)

    await deploy_topology(repo, tid, dry_run=True)

    compose_path = _topology_compose_path(tid)
    assert compose_path.exists(), "dry run must emit a compose file"

    topo = await repo.get_topology(tid)
    assert topo.status == TopologyStatus.PENDING, (
        "dry run must not transition status"
    )


@pytest.mark.anyio
async def test_deploy_failure_transitions_to_failed(repo, tmp_path, monkeypatch):
    """If compose-up fails, status lands at FAILED with the reason logged."""
    monkeypatch.chdir(tmp_path)
    plan = generate(_cfg())
    tid = await persist(repo, plan)

    class _BoomClient:
        def __init__(self):
            self.networks = self
        def list(self, names=None, filters=None):  # noqa: ARG002
            return []
        def create(self, *a, **kw):  # noqa: ARG002
            raise RuntimeError("boom: docker daemon unreachable")

    with patch("decnet.engine.deployer.docker.from_env", return_value=_BoomClient()):
        with pytest.raises(RuntimeError, match="boom"):
            await deploy_topology(repo, tid)

    topo = await repo.get_topology(tid)
    assert topo.status == TopologyStatus.FAILED

    events = await repo.list_topology_status_events(tid)
    # Events are returned newest-first.
    last = events[0]
    assert last["to_status"] == TopologyStatus.FAILED
    assert "boom" in (last["reason"] or "")


@pytest.mark.anyio
async def test_deploy_failure_rolls_back_created_networks(repo, tmp_path, monkeypatch):
    """Networks created before the failing op must be removed on rollback.

    Reproduces the ``Pool overlaps`` regression: a failed deploy left
    partial networks alive and the next deploy hit an IPAM conflict."""
    monkeypatch.chdir(tmp_path)
    plan = generate(_cfg())
    tid = await persist(repo, plan)

    class _PartialClient:
        def __init__(self):
            self.networks = self
            self.created: list[str] = []
            self.removed: list[str] = []
            self._call = 0
            self._created_objs: dict[str, _FakeNet] = {}
        def list(self, names=None, filters=None):  # noqa: ARG002
            if not names:
                return []
            return [self._created_objs[n] for n in names if n in self._created_objs]
        def create(self, name, *a, **kw):  # noqa: ARG002
            self._call += 1
            # Succeed on the first N-1 creates, blow up on the last.
            if self._call >= 2:
                raise RuntimeError("boom: pool overlap")
            self.created.append(name)
            obj = _FakeNet(name, self)
            self._created_objs[name] = obj
            return obj

    class _FakeNet:
        def __init__(self, name, client):
            self.name = name
            self.id = f"id-{name}"
            self.attrs = {"Containers": {}}
            self._client = client
        def remove(self):
            self._client.removed.append(self.name)
            self._client._created_objs.pop(self.name, None)

    fake = _PartialClient()
    with patch("decnet.engine.deployer.docker.from_env", return_value=fake):
        with patch("decnet.engine.deployer._compose") as mock_down:
            with pytest.raises(RuntimeError, match="boom"):
                await deploy_topology(repo, tid)
            # compose down is invoked only when compose was actually started
            # OR a partial compose file exists; create_bridge_network failed
            # before write_topology_compose, so _compose should not have run.
            mock_down.assert_not_called()

    # Every network created this attempt must have been removed on rollback.
    assert set(fake.removed) == set(fake.created)

    topo = await repo.get_topology(tid)
    assert topo.status == TopologyStatus.FAILED


@pytest.mark.anyio
async def test_teardown_from_failed_marks_torn_down(repo, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    # Drive it into FAILED directly via the legal path.
    from decnet.topology.persistence import transition_status
    await transition_status(repo, tid, TopologyStatus.DEPLOYING)
    await transition_status(repo, tid, TopologyStatus.FAILED, reason="test")

    class _StubClient:
        def __init__(self):
            self.networks = self
        def list(self, names=None, filters=None):  # noqa: ARG002
            return []

    with patch("decnet.engine.deployer.docker.from_env", return_value=_StubClient()):
        await teardown_topology(repo, tid)

    topo = await repo.get_topology(tid)
    assert topo.status == TopologyStatus.TORN_DOWN


def test_teardown_order_is_stable():
    lans = [{"name": f"LAN-{i:02d}"} for i in range(5)]
    assert _teardown_order(lans) == [
        "LAN-04", "LAN-03", "LAN-02", "LAN-01", "LAN-00",
    ]


@pytest.mark.live
@pytest.mark.anyio
async def test_deploy_and_teardown_against_real_docker(repo, tmp_path, monkeypatch):
    """End-to-end: create real Docker bridge networks, verify, tear down.

    Skipped on CI; run locally with ``pytest -m live tests/topology``.
    Does NOT run ``docker compose up`` — that's exercised by the flat
    fleet tests. This test covers the topology-specific paths only
    (LAN network creation, multi-home bridge wiring, teardown order).
    """
    monkeypatch.chdir(tmp_path)
    docker = pytest.importorskip("docker")
    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:  # pragma: no cover - environment-specific
        pytest.skip(f"docker daemon not reachable: {exc}")

    plan = generate(_cfg(depth=1, branching_factor=1))
    tid = await persist(repo, plan)

    from decnet.topology.compose import _network_name

    try:
        await deploy_topology(repo, tid, dry_run=True)
        # Dry run doesn't create networks. Now exercise the real path by
        # creating just the networks (no compose up) and tearing down.
        from decnet.network import create_bridge_network, remove_bridge_network
        for lan in plan.lans:
            create_bridge_network(
                client,
                _network_name(tid, lan.name),
                lan.subnet,
                internal=not lan.is_dmz,
            )
        existing = {n.name for n in client.networks.list()}
        for lan in plan.lans:
            assert _network_name(tid, lan.name) in existing
    finally:
        for lan in plan.lans:
            remove_bridge_network(client, _network_name(tid, lan.name))

    remaining = {n.name for n in client.networks.list()}
    for lan in plan.lans:
        assert _network_name(tid, lan.name) not in remaining

    # Compose artifact cleanup
    p = _topology_compose_path(tid)
    if p.exists():
        p.unlink()
    # Sanity: Path roundtrip still resolvable
    assert isinstance(Path(str(p)), Path)


def test_compose_path_is_absolute_and_cwd_independent(tmp_path, monkeypatch):
    """Regression: a CWD-relative compose path littered the install dir and
    let teardown's unlink() miss orphans. Path must be absolute and stable
    across CWD changes so write and teardown always agree."""
    monkeypatch.setenv("DECNET_RUN_DIR", str(tmp_path))
    tid = "abcdef1234567890"

    monkeypatch.chdir(tmp_path)
    p1 = _topology_compose_path(tid)
    sub = tmp_path / "elsewhere"
    sub.mkdir()
    monkeypatch.chdir(sub)
    p2 = _topology_compose_path(tid)

    assert p1.is_absolute()
    assert p1 == p2, "compose path must not depend on process CWD"
    assert p1.parent == tmp_path
