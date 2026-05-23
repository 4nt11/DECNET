# SPDX-License-Identifier: AGPL-3.0-or-later
"""Role-based CLI gating.

MAINTAINERS: when you add a new Typer command (or add_typer group) that is
master-only, register its name in MASTER_ONLY_COMMANDS / MASTER_ONLY_GROUPS
below. The gate is the only thing that:
  (a) hides the command from `decnet --help` on worker hosts, and
  (b) prevents a misconfigured worker from invoking master-side logic.
Forgetting to register a new command is a role-boundary bug. Grep for
MASTER_ONLY when touching command registration.

Worker-legitimate commands (NOT in these sets): agent, updater, forwarder,
status, collect, probe, sniffer. Agents run deckies locally and should be
able to inspect them + run the per-host microservices (collector streams
container logs, prober characterizes attackers hitting this host, sniffer
captures traffic). Mutator and Profiler stay master-only: the mutator
orchestrates respawns across the swarm; the profiler rebuilds attacker
profiles against the master DB (no per-host DB exists).
"""

from __future__ import annotations

import os

import typer

from .utils import console

MASTER_ONLY_COMMANDS: frozenset[str] = frozenset({
    "api", "swarmctl", "deploy", "redeploy", "teardown",
    "mutate", "listener", "profiler",
    "services", "distros", "correlate", "archetypes", "web",
    "db-reset", "init", "webhook", "clusterer", "campaign-clusterer",
    # `ttp` runs on agents — local SMTP decoys persist .eml files into the
    # agent's artifacts tree and the EmailLifter disk-reaches them in-process
    # (DEBT-047). `ttp-backfill` stays master-only: it walks the master DB.
    "ttp-backfill",
})
MASTER_ONLY_GROUPS: frozenset[str] = frozenset(
    {"swarm", "topology", "geoip", "realism"}
)


def _agent_mode_active() -> bool:
    """True when the host is configured as an agent AND master commands are
    disallowed (the default for agents). Workers overriding this explicitly
    set DECNET_DISALLOW_MASTER=false to opt into hybrid use."""
    mode = os.environ.get("DECNET_MODE", "master").lower()
    disallow = os.environ.get("DECNET_DISALLOW_MASTER", "true").lower() == "true"
    return mode == "agent" and disallow


def _require_master_mode(command_name: str) -> None:
    """Defence-in-depth: called at the top of every master-only command body.

    The registration-time gate in _gate_commands_by_mode() already hides
    these commands from Typer's dispatch table, but this check protects
    against direct function imports (e.g. from tests or third-party tools)
    that would bypass Typer entirely."""
    if _agent_mode_active():
        console.print(
            f"[red]`decnet {command_name}` is a master-only command; this host "
            f"is configured as an agent (DECNET_MODE=agent).[/]"
        )
        raise typer.Exit(1)


def _gate_commands_by_mode(_app: typer.Typer) -> None:
    if not _agent_mode_active():
        return
    _app.registered_commands = [
        c for c in _app.registered_commands
        if (c.name or (c.callback.__name__ if c.callback else "")) not in MASTER_ONLY_COMMANDS
    ]
    _app.registered_groups = [
        g for g in _app.registered_groups
        if g.name not in MASTER_ONLY_GROUPS
    ]
