# SPDX-License-Identifier: AGPL-3.0-or-later
"""Each topology runs under its own docker compose project.

The shared ``-p decnet`` project meant that ``--remove-orphans`` on
either a fleet redeploy or a topology teardown swept every container in
the project — wiping sibling topologies and the flat fleet along with
the intended target. Each topology now gets ``decnet-topo-<id8>`` so
the orphan sweep is scoped to that one topology.
"""
from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from decnet.engine.deployer import (
    _compose,
    _compose_with_retry,
    _topology_compose_project,
    FLEET_COMPOSE_PROJECT,
)


def test_topology_project_name_is_per_topology():
    p1 = _topology_compose_project("abcdef12-3456-7890-aaaa-bbbbbbbbbbbb")
    p2 = _topology_compose_project("cafef00d-1111-2222-3333-444444444444")
    assert p1 == "decnet-topo-abcdef12"
    assert p2 == "decnet-topo-cafef00d"
    assert p1 != FLEET_COMPOSE_PROJECT
    assert p2 != FLEET_COMPOSE_PROJECT
    assert p1 != p2


def _run_compose_capturing_cmd(**kwargs):
    """Invoke _compose with subprocess.run mocked and return the argv."""
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with patch("decnet.engine.deployer.subprocess.run", return_value=fake) as mr:
        _compose("down", **kwargs)
    assert mr.called
    return list(mr.call_args[0][0])


def test_compose_defaults_to_fleet_project():
    cmd = _run_compose_capturing_cmd()
    assert "-p" in cmd
    assert cmd[cmd.index("-p") + 1] == FLEET_COMPOSE_PROJECT


def test_compose_accepts_topology_project():
    project = _topology_compose_project("deadbeef-0000-0000-0000-000000000000")
    cmd = _run_compose_capturing_cmd(project=project)
    assert "-p" in cmd
    assert cmd[cmd.index("-p") + 1] == project
    assert cmd[cmd.index("-p") + 1] != FLEET_COMPOSE_PROJECT


def test_compose_with_retry_uses_passed_project():
    project = _topology_compose_project("feedface-0000-0000-0000-000000000000")
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with patch("decnet.engine.deployer.subprocess.run", return_value=fake) as mr:
        _compose_with_retry("up", "-d", project=project)
    cmd = list(mr.call_args[0][0])
    assert "-p" in cmd
    assert cmd[cmd.index("-p") + 1] == project


@pytest.fixture
async def repo(tmp_path):
    from decnet.web.db.factory import get_repository
    r = get_repository(db_path=str(tmp_path / "iso.db"))
    await r.initialize()
    return r


@pytest.mark.anyio
async def test_teardown_topology_uses_per_topo_project(repo, tmp_path, monkeypatch):
    """The real teardown path must pass the per-topology project so the
    fleet (-p decnet) is untouched by the orphan sweep."""
    from decnet.engine.deployer import teardown_topology
    from decnet.topology.generator import generate
    from decnet.topology.persistence import persist, transition_status
    from decnet.topology.status import TopologyStatus
    from decnet.topology.config import TopologyConfig

    monkeypatch.chdir(tmp_path)
    plan = generate(TopologyConfig(
        name="iso", depth=2, branching_factor=2,
        deckies_per_lan_min=1, deckies_per_lan_max=1,
        cross_edge_probability=0.0, randomize_services=False,
        services_explicit=["ssh"], seed=7,
    ))
    tid = await persist(repo, plan)
    await transition_status(repo, tid, TopologyStatus.DEPLOYING)
    await transition_status(repo, tid, TopologyStatus.ACTIVE)

    # Drop a compose file so teardown's `if compose_path.exists()` branch
    # fires and we capture the project argument.
    from decnet.engine.deployer import _topology_compose_path
    compose_path = _topology_compose_path(tid)
    compose_path.write_text("services: {}\n")

    expected_project = _topology_compose_project(tid)

    class _StubClient:
        def __init__(self):
            self.networks = self
        def list(self, names=None, filters=None):  # noqa: ARG002
            return []

    captured_projects: list[str] = []

    def _fake_compose(*args, compose_file=None, env=None, project=FLEET_COMPOSE_PROJECT):  # noqa: ARG001
        captured_projects.append(project)

    with patch("decnet.engine.deployer.docker.from_env", return_value=_StubClient()):
        with patch("decnet.engine.deployer._compose", side_effect=_fake_compose):
            await teardown_topology(repo, tid)

    assert captured_projects, "teardown should have invoked compose"
    assert all(p == expected_project for p in captured_projects), (
        f"teardown leaked into another project: {captured_projects}"
    )
