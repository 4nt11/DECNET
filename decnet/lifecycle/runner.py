# SPDX-License-Identifier: AGPL-3.0-or-later
"""Async deploy/mutate orchestration entry points.

Called by the master API handlers right after they create the lifecycle
rows.  Picks the right strategy (local vs swarm) and runs it off the
HTTP request thread via ``asyncio.create_task`` at the caller.
"""
from __future__ import annotations

from pathlib import Path

from decnet.bus.base import BaseBus
from decnet.config import DecnetConfig, DeckyConfig
from decnet.lifecycle.strategies import (
    LocalDeployStrategy,
    SwarmDeployStrategy,
    select_deploy_strategy,
    select_mutate_strategy,
)
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository

log = get_logger("lifecycle.runner")


async def run_deploy(
    repo: BaseRepository,
    bus: BaseBus | None,
    *,
    lifecycle_ids: dict[str, str],
    config: DecnetConfig,
) -> None:
    """Execute the deploy referenced by *lifecycle_ids* (decky_name ->
    lifecycle_id).  Never raises — strategy turns errors into failed
    rows.  Intended to be wrapped in ``asyncio.create_task``.

    In swarm mode the config may contain BOTH worker-resident deckies
    (host_uuid set) and master-resident ones (host_uuid is None); we
    route each subset through its own strategy.
    """
    try:
        if config.mode == "swarm":
            remote_deckies = [d for d in config.deckies if d.host_uuid is not None]
            local_deckies = [d for d in config.deckies if d.host_uuid is None]
            if remote_deckies:
                remote_ids = {
                    d.name: lifecycle_ids[d.name]
                    for d in remote_deckies if d.name in lifecycle_ids
                }
                remote_cfg = config.model_copy(update={"deckies": remote_deckies})
                await SwarmDeployStrategy().execute(
                    repo, bus,
                    lifecycle_ids=remote_ids, config=remote_cfg,
                )
            if local_deckies:
                local_ids = {
                    d.name: lifecycle_ids[d.name]
                    for d in local_deckies if d.name in lifecycle_ids
                }
                local_cfg = config.model_copy(update={"deckies": local_deckies})
                await LocalDeployStrategy().execute(
                    repo, bus,
                    lifecycle_ids=local_ids, config=local_cfg,
                )
        else:
            strategy = select_deploy_strategy(config)
            await strategy.execute(
                repo, bus, lifecycle_ids=lifecycle_ids, config=config,
            )
    except Exception:  # noqa: BLE001 — defense in depth: never crash task
        log.exception("lifecycle.run_deploy crashed unexpectedly")


async def run_mutate(
    repo: BaseRepository,
    bus: BaseBus | None,
    *,
    lifecycle_id: str,
    decky: DeckyConfig,
    services: list[str],
    full_config: DecnetConfig,
    compose_path: Path,
) -> None:
    """Execute a single-decky mutate.  Never raises."""
    try:
        strategy = select_mutate_strategy(full_config, decky)
        await strategy.execute(
            repo, bus,
            lifecycle_id=lifecycle_id, decky=decky,
            services=services, full_config=full_config,
            compose_path=compose_path,
        )
    except Exception:  # noqa: BLE001
        log.exception("lifecycle.run_mutate crashed unexpectedly")


__all__ = ["run_deploy", "run_mutate"]
