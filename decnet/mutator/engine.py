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
from decnet.config import DeckyConfig, load_state, save_state
from decnet.engine import _compose_with_retry

import subprocess  # nosec B404

console = Console()


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

    save_state(config, compose_path)
    write_compose(config, compose_path)

    console.print(f"[cyan]Mutating '{decky_name}' to services: {', '.join(decky.services)}[/]")

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
