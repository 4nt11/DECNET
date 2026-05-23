# SPDX-License-Identifier: AGPL-3.0-or-later
"""decnet.lifecycle: runner + strategy tests.

All docker calls and AgentClient I/O are mocked; we exercise the
state-machine transitions (pending -> running -> succeeded|failed) and
the routing (swarm vs unihost; per-decky host_uuid).
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from decnet.config import DeckyConfig, DecnetConfig
from decnet.lifecycle.runner import run_deploy, run_mutate
from decnet.lifecycle.strategies import (
    LocalDeployStrategy,
    LocalMutateStrategy,
    SwarmDeployStrategy,
    SwarmMutateStrategy,
    select_deploy_strategy,
    select_mutate_strategy,
)


def _decky(name="decky-01", host_uuid=None) -> DeckyConfig:
    return DeckyConfig(
        name=name, ip="10.66.0.10",
        services=["ssh"], distro="debian",
        base_image="debian:bookworm-slim", hostname=name,
        host_uuid=host_uuid,
    )


def _config(mode="unihost", deckies=None) -> DecnetConfig:
    return DecnetConfig(
        mode=mode, interface="eth0",
        subnet="10.66.0.0/24", gateway="10.66.0.1",
        deckies=deckies or [_decky()],
    )


class _RepoStub:
    def __init__(self):
        self.updates: list[tuple[str, dict]] = []

    async def update_lifecycle(self, lid, fields):
        self.updates.append((lid, fields))


# --- strategy selection --------------------------------------------------

def test_select_deploy_unihost_returns_local() -> None:
    assert isinstance(select_deploy_strategy(_config()), LocalDeployStrategy)


def test_select_deploy_swarm_returns_swarm() -> None:
    cfg = _config(mode="swarm", deckies=[_decky(host_uuid="h1")])
    assert isinstance(select_deploy_strategy(cfg), SwarmDeployStrategy)


def test_select_mutate_master_resident_returns_local() -> None:
    cfg = _config(mode="swarm", deckies=[_decky(host_uuid=None)])
    assert isinstance(
        select_mutate_strategy(cfg, cfg.deckies[0]), LocalMutateStrategy,
    )


def test_select_mutate_swarm_resident_returns_swarm() -> None:
    cfg = _config(mode="swarm", deckies=[_decky(host_uuid="h1")])
    assert isinstance(
        select_mutate_strategy(cfg, cfg.deckies[0]), SwarmMutateStrategy,
    )


# --- LocalDeployStrategy -------------------------------------------------

@pytest.mark.asyncio
async def test_local_deploy_success_flips_all_rows() -> None:
    cfg = _config(deckies=[_decky("d1"), _decky("d2")])
    repo = _RepoStub()
    with patch("anyio.to_thread.run_sync", new_callable=AsyncMock):
        await LocalDeployStrategy().execute(
            repo, None,
            lifecycle_ids={"d1": "lid-1", "d2": "lid-2"},
            config=cfg,
        )
    statuses = [(lid, f["status"]) for lid, f in repo.updates]
    # Each decky: running then succeeded
    assert ("lid-1", "running") in statuses
    assert ("lid-2", "running") in statuses
    assert ("lid-1", "succeeded") in statuses
    assert ("lid-2", "succeeded") in statuses


@pytest.mark.asyncio
async def test_local_deploy_failure_flips_all_rows_failed() -> None:
    cfg = _config(deckies=[_decky("d1"), _decky("d2")])
    repo = _RepoStub()
    with patch(
        "anyio.to_thread.run_sync",
        new_callable=AsyncMock,
        side_effect=RuntimeError("compose boom"),
    ):
        await LocalDeployStrategy().execute(
            repo, None,
            lifecycle_ids={"d1": "lid-1", "d2": "lid-2"},
            config=cfg,
        )
    failed = [(lid, f) for lid, f in repo.updates if f["status"] == "failed"]
    assert len(failed) == 2
    assert all("compose boom" in f["error"] for _, f in failed)


# --- SwarmDeployStrategy -------------------------------------------------

@pytest.mark.asyncio
async def test_swarm_deploy_dispatches_per_host_shard() -> None:
    cfg = _config(
        mode="swarm",
        deckies=[
            _decky("d1", host_uuid="h1"),
            _decky("d2", host_uuid="h1"),
            _decky("d3", host_uuid="h2"),
        ],
    )
    repo = _RepoStub()
    deploy_mock = AsyncMock(return_value={"status": "accepted"})
    agent_ctx = MagicMock()
    agent_ctx.__aenter__ = AsyncMock(
        return_value=MagicMock(deploy=deploy_mock),
    )
    agent_ctx.__aexit__ = AsyncMock(return_value=None)
    with patch(
        "decnet.engine.deployer._resolve_swarm_host",
        new_callable=AsyncMock,
        return_value={"uuid": "x", "address": "10.0.0.1"},
    ), patch(
        "decnet.swarm.client.AgentClient", return_value=agent_ctx,
    ):
        await SwarmDeployStrategy().execute(
            repo, None,
            lifecycle_ids={"d1": "lid-1", "d2": "lid-2", "d3": "lid-3"},
            config=cfg,
        )
    # One AgentClient.deploy call per host.
    assert deploy_mock.await_count == 2
    # All rows transition to running; none reach terminal (worker drives).
    statuses = {(lid, f["status"]) for lid, f in repo.updates}
    assert ("lid-1", "running") in statuses
    assert ("lid-2", "running") in statuses
    assert ("lid-3", "running") in statuses
    assert not any(s in ("succeeded", "failed") for _, s in statuses)


@pytest.mark.asyncio
async def test_swarm_deploy_dispatch_failure_marks_shard_failed() -> None:
    cfg = _config(
        mode="swarm",
        deckies=[_decky("d1", host_uuid="h1"), _decky("d2", host_uuid="h1")],
    )
    repo = _RepoStub()
    with patch(
        "decnet.engine.deployer._resolve_swarm_host",
        new_callable=AsyncMock,
        side_effect=ValueError("unknown host"),
    ):
        await SwarmDeployStrategy().execute(
            repo, None,
            lifecycle_ids={"d1": "lid-1", "d2": "lid-2"},
            config=cfg,
        )
    failed = [(lid, f) for lid, f in repo.updates if f["status"] == "failed"]
    assert len(failed) == 2
    assert all("unknown host" in f["error"] for _, f in failed)


# --- LocalMutateStrategy / runner --------------------------------------

@pytest.mark.asyncio
async def test_local_mutate_success(tmp_path: Path) -> None:
    cfg = _config(deckies=[_decky("d1")])
    decky = cfg.deckies[0]
    repo = _RepoStub()
    with patch("decnet.composer.write_compose"), \
         patch("anyio.to_thread.run_sync", new_callable=AsyncMock):
        await LocalMutateStrategy().execute(
            repo, None,
            lifecycle_id="lid-1",
            decky=decky,
            services=["http"],
            full_config=cfg,
            compose_path=tmp_path / "c.yml",
        )
    statuses = [f["status"] for _, f in repo.updates]
    assert "running" in statuses
    assert "succeeded" in statuses
    # Side effect: decky.services was mutated in place.
    assert decky.services == ["http"]


@pytest.mark.asyncio
async def test_local_mutate_failure(tmp_path: Path) -> None:
    cfg = _config(deckies=[_decky("d1")])
    repo = _RepoStub()
    with patch("decnet.composer.write_compose"), \
         patch(
             "anyio.to_thread.run_sync",
             new_callable=AsyncMock,
             side_effect=RuntimeError("docker fail"),
         ):
        await LocalMutateStrategy().execute(
            repo, None,
            lifecycle_id="lid-1",
            decky=cfg.deckies[0],
            services=["http"],
            full_config=cfg,
            compose_path=tmp_path / "c.yml",
        )
    statuses = [f["status"] for _, f in repo.updates]
    assert "running" in statuses
    assert "failed" in statuses


# --- SwarmMutateStrategy -------------------------------------------------

@pytest.mark.asyncio
async def test_swarm_mutate_dispatches_via_agent(tmp_path: Path) -> None:
    cfg = _config(mode="swarm", deckies=[_decky("d1", host_uuid="h1")])
    repo = _RepoStub()
    mutate_mock = AsyncMock(return_value={"status": "accepted"})
    agent_ctx = MagicMock()
    agent_ctx.__aenter__ = AsyncMock(
        return_value=MagicMock(mutate=mutate_mock),
    )
    agent_ctx.__aexit__ = AsyncMock(return_value=None)
    with patch(
        "decnet.engine.deployer._resolve_swarm_host",
        new_callable=AsyncMock,
        return_value={"uuid": "h1", "address": "10.0.0.1"},
    ), patch(
        "decnet.swarm.client.AgentClient", return_value=agent_ctx,
    ):
        await SwarmMutateStrategy().execute(
            repo, None,
            lifecycle_id="lid-1",
            decky=cfg.deckies[0],
            services=["http"],
            full_config=cfg,
            compose_path=tmp_path / "c.yml",
        )
    mutate_mock.assert_awaited_once()
    # Row was flipped to running; worker drives terminal.
    statuses = [f["status"] for _, f in repo.updates]
    assert "running" in statuses
    assert "succeeded" not in statuses
    assert "failed" not in statuses


# --- runner orchestration ------------------------------------------------

@pytest.mark.asyncio
async def test_run_deploy_unihost_uses_local_strategy() -> None:
    cfg = _config(deckies=[_decky("d1")])
    repo = _RepoStub()
    with patch("anyio.to_thread.run_sync", new_callable=AsyncMock):
        await run_deploy(repo, None, lifecycle_ids={"d1": "lid-1"}, config=cfg)
    statuses = [f["status"] for _, f in repo.updates]
    assert statuses == ["running", "succeeded"]


@pytest.mark.asyncio
async def test_run_deploy_swarm_splits_routes() -> None:
    """In swarm mode, mixed master-resident + worker-resident deckies
    take both strategies."""
    cfg = _config(
        mode="swarm",
        deckies=[
            _decky("local-one", host_uuid=None),
            _decky("remote-one", host_uuid="h1"),
        ],
    )
    repo = _RepoStub()
    deploy_mock = AsyncMock(return_value={"status": "accepted"})
    agent_ctx = MagicMock()
    agent_ctx.__aenter__ = AsyncMock(
        return_value=MagicMock(deploy=deploy_mock),
    )
    agent_ctx.__aexit__ = AsyncMock(return_value=None)
    with patch(
        "decnet.engine.deployer._resolve_swarm_host",
        new_callable=AsyncMock,
        return_value={"uuid": "h1", "address": "10.0.0.1"},
    ), patch(
        "decnet.swarm.client.AgentClient", return_value=agent_ctx,
    ), patch(
        "anyio.to_thread.run_sync", new_callable=AsyncMock,
    ):
        await run_deploy(
            repo, None,
            lifecycle_ids={"local-one": "lid-L", "remote-one": "lid-R"},
            config=cfg,
        )
    # local-one ran end-to-end; remote-one ran -> running only.
    by_lid: dict[str, list[str]] = {}
    for lid, f in repo.updates:
        by_lid.setdefault(lid, []).append(f["status"])
    assert by_lid["lid-L"] == ["running", "succeeded"]
    assert by_lid["lid-R"] == ["running"]
    deploy_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_mutate_local(tmp_path: Path) -> None:
    cfg = _config(deckies=[_decky("d1")])
    repo = _RepoStub()
    with patch("decnet.composer.write_compose"), \
         patch("anyio.to_thread.run_sync", new_callable=AsyncMock):
        await run_mutate(
            repo, None,
            lifecycle_id="lid-1",
            decky=cfg.deckies[0],
            services=["http"],
            full_config=cfg,
            compose_path=tmp_path / "c.yml",
        )
    statuses = [f["status"] for _, f in repo.updates]
    assert statuses == ["running", "succeeded"]


@pytest.mark.asyncio
async def test_run_deploy_never_raises_when_strategy_crashes() -> None:
    """Defense in depth: a strategy bug must not crash the task and
    leave rows wedged in pending."""
    cfg = _config(deckies=[_decky("d1")])
    repo = _RepoStub()
    with patch(
        "decnet.lifecycle.strategies.LocalDeployStrategy.execute",
        new_callable=AsyncMock,
        side_effect=RuntimeError("bug"),
    ):
        # Should not raise.
        await run_deploy(repo, None, lifecycle_ids={"d1": "lid-1"}, config=cfg)
