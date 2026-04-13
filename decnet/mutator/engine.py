"""
Mutation Engine for DECNET.
Handles dynamic rotation of exposed honeypot services over time.
"""

import random
import time
from typing import Optional

from rich.console import Console

from decnet.archetypes import get_archetype
from decnet.fleet import all_service_names
from decnet.composer import write_compose
from decnet.config import DeckyConfig, DecnetConfig
from decnet.engine import _compose_with_retry
from decnet.logging import get_logger

from pathlib import Path
import anyio
import asyncio
from decnet.web.db.repository import BaseRepository

log = get_logger("mutator")
console = Console()


async def mutate_decky(decky_name: str, repo: BaseRepository) -> bool:
    """
    Perform an Intra-Archetype Shuffle for a specific decky.
    Returns True if mutation succeeded, False otherwise.
    """
    log.debug("mutate_decky: start decky=%s", decky_name)
    state_dict = await repo.get_state("deployment")
    if state_dict is None:
        log.error("mutate_decky: no active deployment found in database")
        console.print("[red]No active deployment found in database.[/]")
        return False

    config = DecnetConfig(**state_dict["config"])
    compose_path = Path(state_dict["compose_path"])
    decky: Optional[DeckyConfig] = next((d for d in config.deckies if d.name == decky_name), None)

    if not decky:
        console.print(f"[red]Decky '{decky_name}' not found in state.[/]")
        return False

    if decky.archetype:
        try:
            arch = get_archetype(decky.archetype)
            svc_pool = list(arch.services)
        except ValueError:
            svc_pool = all_service_names()
    else:
        svc_pool = all_service_names()

    if not svc_pool:
        console.print(f"[yellow]No services available for mutating '{decky_name}'.[/]")
        return False

    current_services = set(decky.services)

    attempts = 0
    while True:
        count = random.randint(1, min(3, len(svc_pool)))  # nosec B311
        chosen = set(random.sample(svc_pool, count))  # nosec B311
        attempts += 1
        if chosen != current_services or attempts > 20:
            break

    decky.services = list(chosen)
    decky.last_mutated = time.time()

    # Save to DB
    await repo.set_state("deployment", {"config": config.model_dump(), "compose_path": str(compose_path)})

    # Still writes files for Docker to use
    write_compose(config, compose_path)

    log.info("mutation applied decky=%s services=%s", decky_name, ",".join(decky.services))
    console.print(f"[cyan]Mutating '{decky_name}' to services: {', '.join(decky.services)}[/]")

    try:
        # Wrap blocking call in thread
        await anyio.to_thread.run_sync(_compose_with_retry, "up", "-d", "--remove-orphans", compose_path)
    except Exception as e:
        log.error("mutation failed decky=%s error=%s", decky_name, e)
        console.print(f"[red]Failed to mutate '{decky_name}': {e}[/]")
        return False

    return True


async def mutate_all(repo: BaseRepository, force: bool = False) -> None:
    """
    Check all deckies and mutate those that are due.
    If force=True, mutates all deckies regardless of schedule.
    """
    log.debug("mutate_all: start force=%s", force)
    state_dict = await repo.get_state("deployment")
    if state_dict is None:
        log.error("mutate_all: no active deployment found")
        console.print("[red]No active deployment found.[/]")
        return

    config = DecnetConfig(**state_dict["config"])
    now = time.time()

    mutated_count = 0
    for decky in config.deckies:
        interval_mins = decky.mutate_interval or config.mutate_interval
        if interval_mins is None and not force:
            continue

        if force:
            due = True
        else:
            elapsed_secs = now - decky.last_mutated
            due = elapsed_secs >= (interval_mins * 60)

        if due:
            success = await mutate_decky(decky.name, repo=repo)
            if success:
                mutated_count += 1

    if mutated_count == 0 and not force:
        log.debug("mutate_all: no deckies due for mutation")
        console.print("[dim]No deckies are due for mutation.[/]")
    else:
        log.info("mutate_all: complete mutated_count=%d", mutated_count)


async def run_watch_loop(repo: BaseRepository, poll_interval_secs: int = 10) -> None:
    """Run an infinite loop checking for deckies that need mutation."""
    log.info("mutator watch loop started poll_interval_secs=%d", poll_interval_secs)
    console.print(f"[green]DECNET Mutator Watcher started (polling every {poll_interval_secs}s).[/]")
    try:
        while True:
            await mutate_all(force=False, repo=repo)
            await asyncio.sleep(poll_interval_secs)
    except KeyboardInterrupt:
        log.info("mutator watch loop stopped")
        console.print("\n[dim]Mutator watcher stopped.[/]")
