"""Thin adapter between the agent's HTTP endpoints and the existing
``decnet.engine.deployer`` code path.

Kept deliberately small: the agent does not re-implement deployment logic,
it only translates a master RPC into the same function calls the unihost
CLI already uses.  Everything runs in a worker thread (the deployer is
blocking) so the FastAPI event loop stays responsive.
"""
from __future__ import annotations

import asyncio
from typing import Any

from decnet.engine import deployer as _deployer
from decnet.config import DecnetConfig, load_state, clear_state
from decnet.logging import get_logger

log = get_logger("agent.executor")


async def deploy(config: DecnetConfig, dry_run: bool = False, no_cache: bool = False) -> None:
    """Run the blocking deployer off-loop. The deployer itself calls
    save_state() internally once the compose file is materialised."""
    log.info("agent.deploy name=%s deckies=%d", config.name, len(config.deckies))
    await asyncio.to_thread(_deployer.deploy, config, dry_run, no_cache, False)


async def teardown(decky_id: str | None = None) -> None:
    log.info("agent.teardown decky_id=%s", decky_id)
    await asyncio.to_thread(_deployer.teardown, decky_id)
    if decky_id is None:
        await asyncio.to_thread(clear_state)


async def status() -> dict[str, Any]:
    state = await asyncio.to_thread(load_state)
    if state is None:
        return {"deployed": False, "deckies": []}
    config, _compose_path = state
    return {
        "deployed": True,
        "name": getattr(config, "name", None),
        "compose_path": str(_compose_path),
        "deckies": [d.model_dump() for d in config.deckies],
    }
