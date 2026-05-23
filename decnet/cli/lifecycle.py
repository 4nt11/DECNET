# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import subprocess  # nosec B404
from typing import Optional

import typer
from rich.table import Table

from decnet.env import DECNET_INGEST_LOG_FILE

from . import utils as _utils
from .gating import _agent_mode_active, _require_master_mode
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command()
    def redeploy(
        log_file: str = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", "-f", help="Path to the DECNET log file"),
    ) -> None:
        """Check running DECNET services and relaunch any that are down."""
        log.info("redeploy: checking services")
        registry = _utils._service_registry(str(log_file))

        table = Table(title="DECNET Services", show_lines=True)
        table.add_column("Service", style="bold cyan")
        table.add_column("Status")
        table.add_column("PID", style="dim")
        table.add_column("Action")

        relaunched = 0
        for name, match_fn, launch_args in registry:
            pid = _utils._is_running(match_fn)
            if pid is not None:
                table.add_row(name, "[green]UP[/]", str(pid), "—")
            else:
                try:
                    subprocess.Popen(  # nosec B603
                        launch_args,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                    )
                    table.add_row(name, "[red]DOWN[/]", "—", "[green]relaunched[/]")
                    relaunched += 1
                except (FileNotFoundError, subprocess.SubprocessError) as exc:
                    table.add_row(name, "[red]DOWN[/]", "—", f"[red]failed: {exc}[/]")

        console.print(table)
        if relaunched:
            console.print(f"[green]{relaunched} service(s) relaunched.[/]")
        else:
            console.print("[green]All services running.[/]")

    @app.command()
    def status() -> None:
        """Show running deckies and the state of every ``decnet-*`` unit.

        Prefers systemd (``systemctl list-units 'decnet-*.service'``) so
        agents, masters and mixed hosts all get one consistent view of
        what's installed, loaded, and active. Falls back to the psutil
        cmdline registry on boxes without systemd (dev laptops, CI
        containers, non-systemd init) so `decnet status` is still useful
        there.
        """
        log.info("status command invoked")
        from decnet.engine import status as _status
        _status()

        units = _utils._systemd_units()
        if units is not None:
            _render_systemd_units(units)
        else:
            _render_psutil_fallback()

    def _render_systemd_units(units: list[dict]) -> None:
        svc_table = Table(title="DECNET Services (systemd)", show_lines=True)
        svc_table.add_column("Unit", style="bold cyan")
        svc_table.add_column("Load")
        svc_table.add_column("Active")
        svc_table.add_column("Sub")
        svc_table.add_column("Description", style="dim")

        if not units:
            console.print(
                "[yellow]No decnet-* systemd units loaded. "
                "Run `sudo decnet init` to install them.[/]"
            )
            return

        def _active_style(active: str) -> str:
            if active == "active":
                return "[green]active[/]"
            if active == "failed":
                return "[red]failed[/]"
            return f"[yellow]{active}[/]"

        for u in sorted(units, key=lambda x: x.get("unit", "")):
            svc_table.add_row(
                u.get("unit", ""),
                u.get("load", ""),
                _active_style(u.get("active", "")),
                u.get("sub", ""),
                u.get("description", ""),
            )
        console.print(svc_table)

    def _render_psutil_fallback() -> None:
        registry = _utils._service_registry(str(DECNET_INGEST_LOG_FILE))
        if _agent_mode_active():
            registry = [r for r in registry if r[0] not in {"Mutator", "Profiler", "API"}]
        svc_table = Table(
            title="DECNET Services (psutil fallback — systemd unavailable)",
            show_lines=True,
        )
        svc_table.add_column("Service", style="bold cyan")
        svc_table.add_column("Status")
        svc_table.add_column("PID", style="dim")

        for name, match_fn, _launch_args in registry:
            pid = _utils._is_running(match_fn)
            if pid is not None:
                svc_table.add_row(name, "[green]UP[/]", str(pid))
            else:
                svc_table.add_row(name, "[red]DOWN[/]", "—")

        console.print(svc_table)

    @app.command()
    def teardown(
        all_: bool = typer.Option(False, "--all", help="Tear down all deckies and remove network"),
        id_: Optional[str] = typer.Option(None, "--id", help="Tear down a specific decky by name"),
    ) -> None:
        """Stop and remove deckies."""
        _require_master_mode("teardown")
        if not all_ and not id_:
            console.print("[red]Specify --all or --id <name>.[/]")
            raise typer.Exit(1)

        log.info("teardown command invoked all=%s id=%s", all_, id_)
        from decnet.engine import teardown as _teardown
        _teardown(decky_id=id_)
        log.info("teardown complete all=%s id=%s", all_, id_)

        if all_:
            _utils._kill_all_services()
