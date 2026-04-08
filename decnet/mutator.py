"""
Mutation Engine for DECNET.
Handles dynamic rotation of exposed honeypot services over time.
"""

import random
import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.console import Console

from decnet.archetypes import get_archetype
from decnet.cli import _all_service_names
from decnet.composer import write_compose
from decnet.config import DeckyConfig, load_state, save_state
from decnet.deployer import COMPOSE_FILE

console = Console()

def _compose_with_retry(
    *args: str,
    compose_file: Path = COMPOSE_FILE,
    retries: int = 3,
    delay: float = 5.0,
) -> None:
    """Run a docker compose command, retrying on transient failures."""
    last_exc: subprocess.CalledProcessError | None = None
    cmd = ["docker", "compose", "-f", str(compose_file), *args]
    for attempt in range(1, retries + 1):
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            if result.stdout:
                print(result.stdout, end="")
            return
        last_exc = subprocess.CalledProcessError(
            result.returncode, cmd, result.stdout, result.stderr
        )
        if attempt < retries:
            time.sleep(delay)
            delay *= 2
    raise last_exc

def mutate_decky(decky_name: str) -> bool:
    """
    Perform an Intra-Archetype Shuffle for a specific decky.
    Returns True if mutation succeeded, False otherwise.
    """
    state = load_state()
    if state is None:
        console.print("[red]No active deployment found (no decnet-state.json).[/]")
        return False

    config, compose_path = state
    decky: Optional[DeckyConfig] = next((d for d in config.deckies if d.name == decky_name), None)

    if not decky:
        console.print(f"[red]Decky '{decky_name}' not found in state.[/]")
        return False

    # Determine allowed services pool
    if decky.archetype:
        try:
            arch = get_archetype(decky.archetype)
            svc_pool = list(arch.services)
        except ValueError:
            svc_pool = _all_service_names()
    else:
        svc_pool = _all_service_names()

    if not svc_pool:
        console.print(f"[yellow]No services available for mutating '{decky_name}'.[/]")
        return False

    # Prevent mutating to the exact same set if possible
    current_services = set(decky.services)
    
    attempts = 0
    while True:
        count = random.randint(1, min(3, len(svc_pool)))
        chosen = set(random.sample(svc_pool, count))
        attempts += 1
        if chosen != current_services or attempts > 20:
            break

    decky.services = list(chosen)
    decky.last_mutated = time.time()

    # Save new state
    save_state(config, compose_path)

    # Regenerate compose file
    write_compose(config, compose_path)

    console.print(f"[cyan]Mutating '{decky_name}' to services: {', '.join(decky.services)}[/]")

    # Bring up the new services and remove old orphans
    try:
        _compose_with_retry("up", "-d", "--remove-orphans", compose_file=compose_path)
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to mutate '{decky_name}': {e.stderr}[/]")
        return False

    return True

def mutate_all(force: bool = False) -> None:
    """
    Check all deckies and mutate those that are due.
    If force=True, mutates all deckies regardless of schedule.
    """
    state = load_state()
    if state is None:
        console.print("[red]No active deployment found.[/]")
        return

    config, _ = state
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
            success = mutate_decky(decky.name)
            if success:
                mutated_count += 1
            # Re-load state for next decky just in case, but mutate_decky saves it.
            # However, mutate_decky operates on its own loaded state.
            # Since mutate_decky loads and saves the state, our loop over `config.deckies`
            # has an outdated `last_mutated` if we don't reload. It's fine because we process one by one.
    
    if mutated_count == 0 and not force:
        console.print("[dim]No deckies are due for mutation.[/]")

def run_watch_loop(poll_interval_secs: int = 10) -> None:
    """Run an infinite loop checking for deckies that need mutation."""
    console.print(f"[green]DECNET Mutator Watcher started (polling every {poll_interval_secs}s).[/]")
    try:
        while True:
            mutate_all(force=False)
            time.sleep(poll_interval_secs)
    except KeyboardInterrupt:
        console.print("\n[dim]Mutator watcher stopped.[/]")
