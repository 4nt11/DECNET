from __future__ import annotations

from typing import Optional

import typer
from rich.table import Table

from decnet.archetypes import Archetype, get_archetype
from decnet.config import DecnetConfig
from decnet.distros import get_distro
from decnet.env import DECNET_API_HOST, DECNET_INGEST_LOG_FILE
from decnet.fleet import all_service_names, build_deckies, build_deckies_from_ini
from decnet.ini_loader import load_ini
from decnet.network import detect_interface, detect_subnet, allocate_ips, get_host_ip

from . import utils as _utils
from .gating import _require_master_mode
from .utils import console, log


def _deploy_swarm(config: "DecnetConfig", *, dry_run: bool, no_cache: bool) -> None:
    """Shard deckies round-robin across enrolled workers and POST to swarmctl."""
    base = _utils._swarmctl_base_url(None)
    resp = _utils._http_request("GET", base + "/swarm/hosts?host_status=enrolled")
    enrolled = resp.json()
    resp2 = _utils._http_request("GET", base + "/swarm/hosts?host_status=active")
    active = resp2.json()
    workers = [*enrolled, *active]
    if not workers:
        console.print("[red]No enrolled workers — run `decnet swarm enroll ...` first.[/]")
        raise typer.Exit(1)

    assigned: list = []
    for idx, d in enumerate(config.deckies):
        target = workers[idx % len(workers)]
        assigned.append(d.model_copy(update={"host_uuid": target["uuid"]}))
    config = config.model_copy(update={"deckies": assigned})

    body = {"config": config.model_dump(mode="json"), "dry_run": dry_run, "no_cache": no_cache}
    console.print(f"[cyan]Dispatching {len(config.deckies)} deckies across {len(workers)} worker(s)...[/]")
    resp3 = _utils._http_request("POST", base + "/swarm/deploy", json_body=body, timeout=900.0)
    results = resp3.json().get("results", [])

    table = Table(title="SWARM deploy results")
    for col in ("worker", "host_uuid", "ok", "detail"):
        table.add_column(col)
    any_failed = False
    for r in results:
        ok = bool(r.get("ok"))
        if not ok:
            any_failed = True
        detail = r.get("detail")
        if isinstance(detail, dict):
            detail = detail.get("status") or "ok"
        table.add_row(
            str(r.get("host_name") or ""),
            str(r.get("host_uuid") or ""),
            "[green]yes[/]" if ok else "[red]no[/]",
            str(detail)[:80],
        )
    console.print(table)
    if any_failed:
        raise typer.Exit(1)


def register(app: typer.Typer) -> None:
    @app.command()
    def deploy(
        mode: str = typer.Option("unihost", "--mode", "-m", help="Deployment mode: unihost | swarm"),
        deckies: Optional[int] = typer.Option(None, "--deckies", "-n", help="Number of deckies to deploy (required without --config)", min=1),
        interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Host NIC (auto-detected if omitted)"),
        subnet: Optional[str] = typer.Option(None, "--subnet", help="LAN subnet CIDR (auto-detected if omitted)"),
        ip_start: Optional[str] = typer.Option(None, "--ip-start", help="First decky IP (auto if omitted)"),
        services: Optional[str] = typer.Option(None, "--services", help="Comma-separated services, e.g. ssh,smb,rdp"),
        randomize_services: bool = typer.Option(False, "--randomize-services", help="Assign random services to each decky"),
        distro: Optional[str] = typer.Option(None, "--distro", help="Comma-separated distro slugs, e.g. debian,ubuntu22,rocky9"),
        randomize_distros: bool = typer.Option(False, "--randomize-distros", help="Assign a random distro to each decky"),
        log_file: Optional[str] = typer.Option(DECNET_INGEST_LOG_FILE, "--log-file", help="Host path for the collector to write RFC 5424 logs (e.g. /var/log/decnet/decnet.log)"),
        archetype_name: Optional[str] = typer.Option(None, "--archetype", "-a", help="Machine archetype slug (e.g. linux-server, windows-workstation)"),
        mutate_interval: Optional[int] = typer.Option(30, "--mutate-interval", help="Automatically rotate services every N minutes"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Generate compose file without starting containers"),
        no_cache: bool = typer.Option(False, "--no-cache", help="Force rebuild all images, ignoring Docker layer cache"),
        parallel: bool = typer.Option(False, "--parallel", help="Build all images concurrently (enables BuildKit, separates build from up)"),
        ipvlan: bool = typer.Option(False, "--ipvlan", help="Use IPvlan L2 instead of MACVLAN (required on WiFi interfaces)"),
        config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Path to INI config file"),
        api: bool = typer.Option(False, "--api", help="Start the FastAPI backend to ingest and serve logs"),
        api_port: int = typer.Option(8000, "--api-port", help="Port for the backend API"),
        daemon: bool = typer.Option(False, "--daemon", help="Detach to background as a daemon process"),
    ) -> None:
        """Deploy deckies to the LAN."""
        import os
        import subprocess  # nosec B404
        import sys
        from pathlib import Path as _Path

        _require_master_mode("deploy")
        if daemon:
            log.info("deploy daemonizing mode=%s deckies=%s", mode, deckies)
            _utils._daemonize()

        log.info("deploy command invoked mode=%s deckies=%s dry_run=%s", mode, deckies, dry_run)
        if mode not in ("unihost", "swarm"):
            console.print("[red]--mode must be 'unihost' or 'swarm'[/]")
            raise typer.Exit(1)

        if config_file:
            try:
                ini = load_ini(config_file)
            except FileNotFoundError as e:
                console.print(f"[red]{e}[/]")
                raise typer.Exit(1)

            iface = interface or ini.interface or detect_interface()
            subnet_cidr = subnet or ini.subnet
            effective_gateway = ini.gateway
            if subnet_cidr is None:
                subnet_cidr, effective_gateway = detect_subnet(iface)
            elif effective_gateway is None:
                _, effective_gateway = detect_subnet(iface)

            host_ip = get_host_ip(iface)
            console.print(f"[dim]Config:[/] {config_file}  [dim]Interface:[/] {iface}  "
                          f"[dim]Subnet:[/] {subnet_cidr}  [dim]Gateway:[/] {effective_gateway}  "
                          f"[dim]Host IP:[/] {host_ip}")

            if ini.custom_services:
                from decnet.custom_service import CustomService
                from decnet.services.registry import register_custom_service
                for cs in ini.custom_services:
                    register_custom_service(
                        CustomService(
                            name=cs.name,
                            image=cs.image,
                            exec_cmd=cs.exec_cmd,
                            ports=cs.ports,
                        )
                    )

            effective_log_file = log_file
            try:
                decky_configs = build_deckies_from_ini(
                    ini, subnet_cidr, effective_gateway, host_ip, randomize_services, cli_mutate_interval=mutate_interval
                )
            except ValueError as e:
                console.print(f"[red]{e}[/]")
                raise typer.Exit(1)
        else:
            if deckies is None:
                console.print("[red]--deckies is required when --config is not used.[/]")
                raise typer.Exit(1)

            services_list = [s.strip() for s in services.split(",")] if services else None
            if services_list:
                known = set(all_service_names())
                unknown = [s for s in services_list if s not in known]
                if unknown:
                    console.print(f"[red]Unknown service(s): {unknown}. Available: {all_service_names()}[/]")
                    raise typer.Exit(1)

            arch: Archetype | None = None
            if archetype_name:
                try:
                    arch = get_archetype(archetype_name)
                except ValueError as e:
                    console.print(f"[red]{e}[/]")
                    raise typer.Exit(1)

            if not services_list and not randomize_services and not arch:
                console.print("[red]Specify --services, --archetype, or --randomize-services.[/]")
                raise typer.Exit(1)

            iface = interface or detect_interface()
            if subnet is None:
                subnet_cidr, effective_gateway = detect_subnet(iface)
            else:
                subnet_cidr = subnet
                _, effective_gateway = detect_subnet(iface)

            host_ip = get_host_ip(iface)
            console.print(f"[dim]Interface:[/] {iface}  [dim]Subnet:[/] {subnet_cidr}  "
                          f"[dim]Gateway:[/] {effective_gateway}  [dim]Host IP:[/] {host_ip}")

            distros_list = [d.strip() for d in distro.split(",")] if distro else None
            if distros_list:
                try:
                    for slug in distros_list:
                        get_distro(slug)
                except ValueError as e:
                    console.print(f"[red]{e}[/]")
                    raise typer.Exit(1)

            ips = allocate_ips(subnet_cidr, effective_gateway, host_ip, deckies, ip_start)
            decky_configs = build_deckies(
                deckies, ips, services_list, randomize_services,
                distros_explicit=distros_list, randomize_distros=randomize_distros,
                archetype=arch, mutate_interval=mutate_interval,
            )
            effective_log_file = log_file

        if api and not effective_log_file:
            effective_log_file = os.path.join(os.getcwd(), "decnet.log")
            console.print(f"[cyan]API mode enabled: defaulting log-file to {effective_log_file}[/]")

        config = DecnetConfig(
            mode=mode,
            interface=iface,
            subnet=subnet_cidr,
            gateway=effective_gateway,
            deckies=decky_configs,
            log_file=effective_log_file,
            ipvlan=ipvlan,
            mutate_interval=mutate_interval,
        )

        log.debug("deploy: config built deckies=%d interface=%s subnet=%s", len(config.deckies), config.interface, config.subnet)

        if mode == "swarm":
            _deploy_swarm(config, dry_run=dry_run, no_cache=no_cache)
            if dry_run:
                log.info("deploy: swarm dry-run complete, no workers dispatched")
            else:
                log.info("deploy: swarm deployment complete deckies=%d", len(config.deckies))
            return

        from decnet.engine import deploy as _deploy
        _deploy(config, dry_run=dry_run, no_cache=no_cache, parallel=parallel)
        if dry_run:
            log.info("deploy: dry-run complete, no containers started")
        else:
            log.info("deploy: deployment complete deckies=%d", len(config.deckies))

        if mutate_interval is not None and not dry_run:
            console.print(f"[green]Starting DECNET Mutator watcher in the background (interval: {mutate_interval}m)...[/]")
            try:
                subprocess.Popen(  # nosec B603
                    [sys.executable, "-m", "decnet.cli", "mutate", "--watch"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except (FileNotFoundError, subprocess.SubprocessError):
                console.print("[red]Failed to start mutator watcher.[/]")

        if effective_log_file and not dry_run and not api:
            _collector_err = _Path(effective_log_file).with_suffix(".collector.log")
            console.print(f"[bold cyan]Starting log collector[/] → {effective_log_file}")
            subprocess.Popen(  # nosec B603
                [sys.executable, "-m", "decnet.cli", "collect", "--log-file", str(effective_log_file)],
                stdin=subprocess.DEVNULL,
                stdout=open(_collector_err, "a"),
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        if api and not dry_run:
            console.print(f"[green]Starting DECNET API on port {api_port}...[/]")
            _env: dict[str, str] = os.environ.copy()
            _env["DECNET_INGEST_LOG_FILE"] = str(effective_log_file or "")
            try:
                subprocess.Popen(  # nosec B603
                    [sys.executable, "-m", "uvicorn", "decnet.web.api:app", "--host", DECNET_API_HOST, "--port", str(api_port)],
                    env=_env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT
                )
                console.print(f"[dim]API running at http://{DECNET_API_HOST}:{api_port}[/]")
            except (FileNotFoundError, subprocess.SubprocessError):
                console.print("[red]Failed to start API. Ensure 'uvicorn' is installed in the current environment.[/]")

        if effective_log_file and not dry_run:
            console.print("[bold cyan]Starting DECNET-PROBER[/] (auto-discovers attackers from log stream)")
            try:
                subprocess.Popen(  # nosec B603
                    [sys.executable, "-m", "decnet.cli", "probe", "--daemon", "--log-file", str(effective_log_file)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except (FileNotFoundError, subprocess.SubprocessError):
                console.print("[red]Failed to start DECNET-PROBER.[/]")

        if effective_log_file and not dry_run:
            console.print("[bold cyan]Starting DECNET-PROFILER[/] (builds attacker profiles from log stream)")
            try:
                subprocess.Popen(  # nosec B603
                    [sys.executable, "-m", "decnet.cli", "profiler", "--daemon"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except (FileNotFoundError, subprocess.SubprocessError):
                console.print("[red]Failed to start DECNET-PROFILER.[/]")

        if effective_log_file and not dry_run:
            console.print("[bold cyan]Starting DECNET-SNIFFER[/] (passive network capture)")
            try:
                subprocess.Popen(  # nosec B603
                    [sys.executable, "-m", "decnet.cli", "sniffer", "--daemon", "--log-file", str(effective_log_file)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except (FileNotFoundError, subprocess.SubprocessError):
                console.print("[red]Failed to start DECNET-SNIFFER.[/]")
