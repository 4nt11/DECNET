# SPDX-License-Identifier: AGPL-3.0-or-later
"""MazeNET topology CLI: generate / deploy / teardown / list / show."""
from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import hydrate, persist
from decnet.topology.status import TopologyStatus

from .gating import _require_master_mode

_console = Console()

_group = typer.Typer(
    name="topology",
    help="MazeNET nested-topology commands (DECNET master only).",
    no_args_is_help=True,
)


async def _repo():
    from decnet.web.db.factory import get_repository
    r = get_repository()
    await r.initialize()
    return r


@_group.command("generate")
def _generate(
    name: str = typer.Option(..., "--name", help="Topology name"),
    depth: int = typer.Option(3, "--depth", min=1, max=16),
    branching: int = typer.Option(2, "--branching", min=1, max=8),
    deckies_per_lan: str = typer.Option(
        "1-3",
        "--deckies-per-lan",
        help="Min-max deckies per LAN, e.g. 1-3",
    ),
    bridge_forward_probability: float = typer.Option(1.0, "--bridge-forward-p", min=0.0, max=1.0),
    cross_edge_probability: float = typer.Option(0.0, "--cross-edge-p", min=0.0, max=1.0),
    services: Optional[str] = typer.Option(None, "--services", help="Comma-separated explicit services"),
    randomize_services: bool = typer.Option(True, "--randomize-services/--no-randomize-services"),
    seed: Optional[int] = typer.Option(None, "--seed", min=0),
) -> None:
    """Generate a topology plan and persist it as pending."""
    _require_master_mode("topology generate")

    try:
        lo, hi = (int(x) for x in deckies_per_lan.split("-", 1))
    except ValueError:
        _console.print("[red]--deckies-per-lan must be formatted as MIN-MAX, e.g. 1-3.[/]")
        raise typer.Exit(1)

    services_explicit = (
        [s.strip() for s in services.split(",") if s.strip()] if services else None
    )

    try:
        cfg = TopologyConfig(
            name=name,
            depth=depth,
            branching_factor=branching,
            deckies_per_lan_min=lo,
            deckies_per_lan_max=hi,
            bridge_forward_probability=bridge_forward_probability,
            cross_edge_probability=cross_edge_probability,
            services_explicit=services_explicit,
            randomize_services=randomize_services if not services_explicit else False,
            seed=seed,
        )
    except ValueError as e:
        _console.print(f"[red]{e}[/]")
        raise typer.Exit(1)

    plan = generate(cfg)

    async def _go() -> str:
        repo = await _repo()
        return await persist(repo, plan)

    tid = asyncio.run(_go())
    _console.print(f"[green]Topology persisted as pending[/] — id=[bold]{tid}[/]")
    _console.print(
        f"  LANs: {len(plan.lans)}  deckies: {len(plan.deckies)}  edges: {len(plan.edges)}"
    )


@_group.command("list")
def _list() -> None:
    """List all topologies."""
    _require_master_mode("topology list")

    async def _go() -> list[dict]:
        repo = await _repo()
        return await repo.list_topologies()

    rows = asyncio.run(_go())
    if not rows:
        _console.print("[yellow]No topologies.[/]")
        return
    table = Table(title="DECNET / MazeNET Topologies")
    for col in ("id", "name", "mode", "status", "created_at"):
        table.add_column(col)
    for r in rows:
        table.add_row(
            str(r["id"]),
            str(r["name"]),
            str(r["mode"]),
            str(r["status"]),
            str(r.get("created_at", "")),
        )
    _console.print(table)


@_group.command("show")
def _show(topology_id: str = typer.Argument(..., help="Topology id")) -> None:
    """Print a structured summary of a topology."""
    _require_master_mode("topology show")

    async def _go():
        repo = await _repo()
        return await hydrate(repo, topology_id)

    hydrated = asyncio.run(_go())
    if hydrated is None:
        _console.print(f"[red]No such topology: {topology_id}[/]")
        raise typer.Exit(1)

    topo = hydrated["topology"]
    _console.print(
        f"[bold]{topo['name']}[/]  id={topo['id']}  status={topo['status']}"
        f"  mode={topo['mode']}"
    )

    def _decky_name(d: dict) -> str:
        cfg = d.get("decky_config") or {}
        return cfg.get("name") or d.get("name") or d["uuid"]

    deckies_by_name = {_decky_name(d): d for d in hydrated["deckies"]}
    edges_by_lan: dict[str, list[dict]] = {}
    for e in hydrated["edges"]:
        edges_by_lan.setdefault(e["lan_id"], []).append(e)

    for lan in hydrated["lans"]:
        dmz_tag = " [dim](DMZ)[/]" if lan["is_dmz"] else ""
        _console.print(f"\n[cyan]LAN[/] {lan['name']}  {lan['subnet']}{dmz_tag}")
        lan_edges = edges_by_lan.get(lan["id"], [])
        for e in lan_edges:
            # Find the decky name via uuid.
            decky = next(
                (d for d in hydrated["deckies"] if d["uuid"] == e["decky_uuid"]),
                None,
            )
            if decky is None:
                continue
            cfg = decky.get("decky_config") or {}
            name = _decky_name(decky)
            ip = (cfg.get("ips_by_lan") or {}).get(lan["name"]) or decky.get("ip") or "?"
            tags = []
            if e["is_bridge"]:
                tags.append("bridge")
            if e["forwards_l3"]:
                tags.append("L3-forward")
            tag_s = f" [yellow]({', '.join(tags)})[/]" if tags else ""
            svcs = ",".join(cfg.get("services") or decky.get("services") or []) or "-"
            _console.print(f"  • {name}  {ip}  svcs={svcs}{tag_s}")

    _ = deckies_by_name  # for future cross-reference extensions


@_group.command("deploy")
def _deploy(
    topology_id: str = typer.Argument(..., help="Topology id (must be pending)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Write compose + create nets, skip containers"),
) -> None:
    """Deploy a pending topology."""
    _require_master_mode("topology deploy")
    from decnet.engine.deployer import deploy_topology

    async def _go() -> None:
        repo = await _repo()
        await deploy_topology(repo, topology_id, dry_run=dry_run)

    asyncio.run(_go())
    _console.print(f"[green]Topology {topology_id} deployed.[/]")


@_group.command("teardown")
def _teardown(
    topology_id: str = typer.Argument(..., help="Topology id"),
) -> None:
    """Tear down a topology. Legal from active|degraded|failed|deploying."""
    _require_master_mode("topology teardown")
    from decnet.engine.deployer import teardown_topology

    async def _go() -> None:
        repo = await _repo()
        await teardown_topology(repo, topology_id)

    asyncio.run(_go())
    _console.print(f"[green]Topology {topology_id} torn down.[/]")


@_group.command("delete")
def _delete(
    topology_id: str = typer.Argument(..., help="Topology id"),
    force: bool = typer.Option(
        False,
        "--force",
        help="Skip the confirmation prompt (required for non-interactive use).",
    ),
) -> None:
    """Delete a topology and all its children (LANs, deckies, edges, mutations).

    Refuses while containers are running — teardown first.
    """
    _require_master_mode("topology delete")

    _RUNNING = {
        TopologyStatus.DEPLOYING,
        TopologyStatus.ACTIVE,
        TopologyStatus.DEGRADED,
        TopologyStatus.TEARING_DOWN,
    }

    async def _go() -> tuple[bool, Optional[str]]:
        repo = await _repo()
        topo = await repo.get_topology(topology_id)
        if topo is None:
            return False, "not-found"
        if topo.status in _RUNNING:
            return False, str(topo.status)
        ok = await repo.delete_topology_cascade(topology_id)
        return ok, None

    if not force and not typer.confirm(
        f"Delete topology {topology_id} and all its children? This cannot be undone.",
        default=False,
    ):
        _console.print("[yellow]Cancelled.[/]")
        raise typer.Exit(0)

    ok, reason = asyncio.run(_go())
    if reason == "not-found":
        _console.print(f"[red]No such topology: {topology_id}[/]")
        raise typer.Exit(1)
    if reason is not None:
        _console.print(
            f"[red]Cannot delete while status={reason!r}. Run "
            f"[bold]decnet topology teardown {topology_id}[/] first.[/]"
        )
        raise typer.Exit(1)
    if not ok:
        _console.print(f"[red]Delete failed: {topology_id}[/]")
        raise typer.Exit(1)
    _console.print(f"[green]Topology {topology_id} deleted.[/]")


@_group.command("mutate")
def _mutate(
    topology_id: str = typer.Argument(..., help="Topology id (active or degraded)"),
    op: str = typer.Argument(
        ...,
        help=(
            "One of: add_lan, remove_lan, add_decky, attach_decky, "
            "detach_decky, remove_decky, update_decky, update_lan"
        ),
    ),
    payload_json: str = typer.Option(
        "{}",
        "--payload-json",
        help="JSON payload for the op (see mutator.ops for keys)",
    ),
    expected_version: Optional[int] = typer.Option(
        None,
        "--expected-version",
        help="Optimistic-concurrency guard; enqueue fails with a "
        "VersionConflict if the topology has since been mutated.",
    ),
) -> None:
    """Enqueue a live mutation.  The mutator's watch loop applies it."""
    _require_master_mode("topology mutate")
    import json

    try:
        payload = json.loads(payload_json)
    except ValueError as e:
        _console.print(f"[red]Invalid JSON: {e}[/]")
        raise typer.Exit(1)

    async def _go() -> str:
        repo = await _repo()
        return await repo.enqueue_topology_mutation(
            topology_id, op, payload, expected_version=expected_version,
        )

    mid = asyncio.run(_go())
    _console.print(
        f"[green]Mutation enqueued[/] — id=[bold]{mid}[/] op={op} "
        f"(watch for state=applied on [cyan]topology mutations {topology_id}[/])"
    )


@_group.command("mutations")
def _mutations(
    topology_id: str = typer.Argument(..., help="Topology id"),
    state: Optional[str] = typer.Option(
        None,
        "--state",
        help="Filter to one of pending|applying|applied|failed",
    ),
) -> None:
    """List queued/applied mutations for a topology."""
    _require_master_mode("topology mutations")

    async def _go() -> list[dict]:
        repo = await _repo()
        return await repo.list_topology_mutations(topology_id, state=state)

    rows = asyncio.run(_go())
    if not rows:
        _console.print("[yellow]No mutations.[/]")
        return
    table = Table(title=f"Mutations — topology {topology_id}")
    for col in ("id", "op", "state", "requested_at", "applied_at", "reason"):
        table.add_column(col)
    for r in rows:
        table.add_row(
            str(r["id"]),
            str(r["op"]),
            str(r["state"]),
            str(r.get("requested_at", "")),
            str(r.get("applied_at") or ""),
            str(r.get("reason") or ""),
        )
    _console.print(table)


def register(app: typer.Typer) -> None:
    app.add_typer(_group, name="topology")


__all__ = ["register", "TopologyStatus"]
