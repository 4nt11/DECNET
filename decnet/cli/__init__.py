"""
DECNET CLI — entry point for all commands.

Usage:
  decnet deploy --mode unihost --deckies 5 --randomize-services
  decnet status
  decnet teardown [--all | --id decky-01]
  decnet services

Layout: each command module exports ``register(app)`` which attaches its
commands to the passed Typer app. ``__init__.py`` builds the root app,
calls every module's ``register`` in order, then runs the master-only
gate. The gate must fire LAST so it sees the fully-populated dispatch
table before filtering.
"""

from __future__ import annotations

import typer

from . import (
    agent,
    api,
    bus,
    db,
    deploy,
    forwarder,
    geoip,
    init,
    inventory,
    lifecycle,
    listener,
    orchestrator,
    profiler,
    sniffer,
    swarm,
    swarmctl,
    topology,
    updater,
    web,
    webhook,
    workers,
)
from .gating import _gate_commands_by_mode
from .utils import console as console, log as log

app = typer.Typer(
    name="decnet",
    help="Deploy a deception network of honeypot deckies on your LAN.",
    no_args_is_help=True,
)

# Order matches the old flat layout so `decnet --help` reads the same.
for _mod in (
    api, swarmctl, agent, updater, listener, forwarder,
    swarm,
    deploy, lifecycle, workers, inventory,
    web, profiler, orchestrator, sniffer, db,
    topology, bus, geoip, init, webhook,
):
    _mod.register(app)

_gate_commands_by_mode(app)

# Backwards-compat re-exports. Tests and third-party tooling import these
# directly from ``decnet.cli``; the refactor must keep them resolvable.
from .db import _db_reset_mysql_async  # noqa: E402,F401
from .gating import (  # noqa: E402,F401
    MASTER_ONLY_COMMANDS,
    MASTER_ONLY_GROUPS,
    _agent_mode_active,
    _require_master_mode,
)
from .utils import (  # noqa: E402,F401
    _daemonize,
    _http_request,
    _is_running,
    _kill_all_services,
    _pid_dir,
    _service_registry,
    _spawn_detached,
    _swarmctl_base_url,
)


if __name__ == "__main__":  # pragma: no cover
    app()
