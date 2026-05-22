"""Lifecycle execution strategies.

Each strategy owns the work for one (operation, transport) combo:

* ``LocalDeployStrategy`` — master-resident deckies: writes a compose
  file and runs ``docker compose up -d`` on the master via
  ``engine.deployer.deploy`` off the request thread.
* ``SwarmDeployStrategy`` — worker-resident deckies: fans the sharded
  config to each worker via ``AgentClient.deploy``.  The worker returns
  202 immediately; the worker's next heartbeat drives the terminal
  transition (see ``master heartbeat handler accepts lifecycle deltas``).
* ``LocalMutateStrategy`` / ``SwarmMutateStrategy`` — same split, for a
  per-decky mutate of services list.

The runner picks the right concrete class.  Strategies update the DB
row + emit bus signals; they never raise back at the runner — they
turn exceptions into ``failed`` rows and return.
"""
from __future__ import annotations

import abc
from datetime import datetime, timezone

import anyio

from decnet.bus.base import BaseBus
from decnet.config import DecnetConfig, DeckyConfig
from decnet.lifecycle.events import emit_lifecycle
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository

log = get_logger("lifecycle.strategy")


# --- base ----------------------------------------------------------------

class _StrategyBase(abc.ABC):
    """Shared helpers — DB row transitions + bus emit."""

    async def _mark_running(
        self,
        repo: BaseRepository,
        bus: BaseBus | None,
        *,
        lifecycle_id: str,
        decky_name: str,
        operation: str,
    ) -> None:
        await repo.update_lifecycle(lifecycle_id, {"status": "running"})
        await emit_lifecycle(
            bus,
            lifecycle_id=lifecycle_id,
            decky_name=decky_name,
            operation=operation,
            status="running",
        )

    async def _mark_succeeded(
        self,
        repo: BaseRepository,
        bus: BaseBus | None,
        *,
        lifecycle_id: str,
        decky_name: str,
        operation: str,
    ) -> None:
        await repo.update_lifecycle(
            lifecycle_id,
            {
                "status": "succeeded",
                "completed_at": datetime.now(timezone.utc),
            },
        )
        await emit_lifecycle(
            bus,
            lifecycle_id=lifecycle_id,
            decky_name=decky_name,
            operation=operation,
            status="succeeded",
        )

    async def _mark_failed(
        self,
        repo: BaseRepository,
        bus: BaseBus | None,
        *,
        lifecycle_id: str,
        decky_name: str,
        operation: str,
        error: str,
    ) -> None:
        await repo.update_lifecycle(
            lifecycle_id,
            {
                "status": "failed",
                "error": error[:2000],
                "completed_at": datetime.now(timezone.utc),
            },
        )
        await emit_lifecycle(
            bus,
            lifecycle_id=lifecycle_id,
            decky_name=decky_name,
            operation=operation,
            status="failed",
            error=error[:2000],
        )


# --- deploy --------------------------------------------------------------

class DeployStrategy(_StrategyBase):
    """ABC for deploy strategies. Concrete implementations override
    :meth:`execute`."""

    @abc.abstractmethod
    async def execute(
        self,
        repo: BaseRepository,
        bus: BaseBus | None,
        *,
        lifecycle_ids: dict[str, str],  # decky_name -> lifecycle_id
        config: DecnetConfig,
    ) -> None: ...


class LocalDeployStrategy(DeployStrategy):
    """Master-resident deploy via ``engine.deployer.deploy``.

    Coalesces N decky lifecycle rows into one compose-up call (compose
    is naturally batched), then flips all rows together.
    """

    async def execute(
        self,
        repo: BaseRepository,
        bus: BaseBus | None,
        *,
        lifecycle_ids: dict[str, str],
        config: DecnetConfig,
    ) -> None:
        from decnet.engine import deployer as _deployer

        for decky_name, lid in lifecycle_ids.items():
            await self._mark_running(
                repo, bus, lifecycle_id=lid,
                decky_name=decky_name, operation="deploy",
            )
        try:
            await anyio.to_thread.run_sync(
                _deployer.deploy, config, False, False, False,
            )
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
            log.exception("local deploy failed")
            for decky_name, lid in lifecycle_ids.items():
                await self._mark_failed(
                    repo, bus, lifecycle_id=lid,
                    decky_name=decky_name, operation="deploy",
                    error=err,
                )
            return
        for decky_name, lid in lifecycle_ids.items():
            await self._mark_succeeded(
                repo, bus, lifecycle_id=lid,
                decky_name=decky_name, operation="deploy",
            )


class SwarmDeployStrategy(DeployStrategy):
    """Worker-resident deploy via ``AgentClient.deploy``.

    Marks rows ``running`` on dispatch.  The worker's /deploy is async
    (202); its next heartbeat carries lifecycle deltas that drive the
    terminal transition via the master's heartbeat handler.  If the
    dispatch itself raises (network / mTLS / 5xx), the row is marked
    ``failed`` here.
    """

    async def execute(
        self,
        repo: BaseRepository,
        bus: BaseBus | None,
        *,
        lifecycle_ids: dict[str, str],
        config: DecnetConfig,
    ) -> None:
        from decnet.engine.deployer import _resolve_swarm_host
        from decnet.swarm.client import AgentClient

        # Shard deckies by host so we can fire one AgentClient.deploy
        # per host carrying that host's slice of the config.
        shards: dict[str, list[DeckyConfig]] = {}
        for decky in config.deckies:
            if decky.host_uuid is None:
                # Master-resident decky in swarm mode: skip here; runner
                # routes those through LocalDeployStrategy at the
                # caller's discretion.  Defensive guard only.
                continue
            shards.setdefault(decky.host_uuid, []).append(decky)

        for host_uuid, deckies in shards.items():
            shard_lifecycle = {
                d.name: lifecycle_ids[d.name]
                for d in deckies if d.name in lifecycle_ids
            }
            for decky in deckies:
                lid = shard_lifecycle.get(decky.name)
                if lid is None:
                    continue
                await self._mark_running(
                    repo, bus, lifecycle_id=lid,
                    decky_name=decky.name, operation="deploy",
                )
            try:
                host = await _resolve_swarm_host(repo, host_uuid)
                shard_cfg = config.model_copy(update={"deckies": deckies})
                async with AgentClient(host=host) as agent:
                    await agent.deploy(shard_cfg)
            except Exception as exc:  # noqa: BLE001
                err = f"{type(exc).__name__}: {exc}"
                log.exception(
                    "swarm deploy dispatch failed host_uuid=%s", host_uuid,
                )
                for decky_name, lid in shard_lifecycle.items():
                    await self._mark_failed(
                        repo, bus, lifecycle_id=lid,
                        decky_name=decky_name, operation="deploy",
                        error=err,
                    )
                continue
            # Successful dispatch -> rows stay running; worker drives
            # the terminal via heartbeat.


# --- mutate --------------------------------------------------------------

class MutateStrategy(_StrategyBase):
    """ABC for mutate strategies."""

    @abc.abstractmethod
    async def execute(
        self,
        repo: BaseRepository,
        bus: BaseBus | None,
        *,
        lifecycle_id: str,
        decky: DeckyConfig,
        services: list[str],
        full_config: DecnetConfig,
        compose_path,
    ) -> None: ...


class LocalMutateStrategy(MutateStrategy):
    """Master-local mutate: rewrites compose + ``compose up -d``."""

    async def execute(
        self,
        repo: BaseRepository,
        bus: BaseBus | None,
        *,
        lifecycle_id: str,
        decky: DeckyConfig,
        services: list[str],
        full_config: DecnetConfig,
        compose_path,
    ) -> None:
        from decnet.composer import write_compose
        from decnet.engine import _compose_with_retry

        await self._mark_running(
            repo, bus, lifecycle_id=lifecycle_id,
            decky_name=decky.name, operation="mutate",
        )
        try:
            decky.services = list(services)
            write_compose(full_config, compose_path)
            await anyio.to_thread.run_sync(
                lambda: _compose_with_retry(
                    "up", "-d", "--remove-orphans",
                    compose_file=compose_path,
                ),
            )
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
            log.exception("local mutate failed decky=%s", decky.name)
            await self._mark_failed(
                repo, bus, lifecycle_id=lifecycle_id,
                decky_name=decky.name, operation="mutate",
                error=err,
            )
            return
        await self._mark_succeeded(
            repo, bus, lifecycle_id=lifecycle_id,
            decky_name=decky.name, operation="mutate",
        )


class SwarmMutateStrategy(MutateStrategy):
    """Worker-resident mutate via ``AgentClient.mutate``.

    Same shape as SwarmDeployStrategy: row -> running on dispatch,
    worker drives terminal via heartbeat.
    """

    async def execute(
        self,
        repo: BaseRepository,
        bus: BaseBus | None,
        *,
        lifecycle_id: str,
        decky: DeckyConfig,
        services: list[str],
        full_config: DecnetConfig,
        compose_path,
    ) -> None:
        from decnet.engine.deployer import _resolve_swarm_host
        from decnet.swarm.client import AgentClient

        await self._mark_running(
            repo, bus, lifecycle_id=lifecycle_id,
            decky_name=decky.name, operation="mutate",
        )
        if decky.host_uuid is None:
            await self._mark_failed(
                repo, bus, lifecycle_id=lifecycle_id,
                decky_name=decky.name, operation="mutate",
                error="swarm mutate strategy invoked for decky with no host_uuid",
            )
            return
        try:
            host = await _resolve_swarm_host(repo, decky.host_uuid)
            async with AgentClient(host=host) as agent:
                await agent.mutate(decky.name, list(services))
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
            log.exception("swarm mutate dispatch failed decky=%s", decky.name)
            await self._mark_failed(
                repo, bus, lifecycle_id=lifecycle_id,
                decky_name=decky.name, operation="mutate",
                error=err,
            )
            return
        # Worker drives terminal via heartbeat.


def select_deploy_strategy(config: DecnetConfig) -> DeployStrategy:
    """Pick strategy by deployment mode.  In swarm mode deckies with
    ``host_uuid`` go remote; the caller must route master-resident
    swarm deckies (host_uuid=None) through the local strategy
    separately."""
    if config.mode == "swarm":
        return SwarmDeployStrategy()
    return LocalDeployStrategy()


def select_mutate_strategy(
    config: DecnetConfig, decky: DeckyConfig,
) -> MutateStrategy:
    """Pick strategy by decky placement."""
    if config.mode == "swarm" and decky.host_uuid is not None:
        return SwarmMutateStrategy()
    return LocalMutateStrategy()


__all__ = [
    "DeployStrategy",
    "LocalDeployStrategy",
    "SwarmDeployStrategy",
    "MutateStrategy",
    "LocalMutateStrategy",
    "SwarmMutateStrategy",
    "select_deploy_strategy",
    "select_mutate_strategy",
]
