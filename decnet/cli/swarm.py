# SPDX-License-Identifier: AGPL-3.0-or-later
"""`decnet swarm ...` — master-side operator commands (HTTP to local swarmctl)."""

from __future__ import annotations

from typing import Optional

import typer
from rich.table import Table

from . import utils as _utils
from .utils import console


def register(app: typer.Typer) -> None:
    swarm_app = typer.Typer(
        name="swarm",
        help="Manage swarm workers (enroll, list, decommission). Requires `decnet swarmctl` running.",
        no_args_is_help=True,
    )
    app.add_typer(swarm_app, name="swarm")

    @swarm_app.command("enroll")
    def swarm_enroll(
        name: str = typer.Option(..., "--name", help="Short hostname for the worker (also the cert CN)"),
        address: str = typer.Option(..., "--address", help="IP or DNS the master uses to reach the worker"),
        agent_port: int = typer.Option(8765, "--agent-port", help="Worker agent TCP port"),
        sans: Optional[str] = typer.Option(None, "--sans", help="Comma-separated extra SANs for the worker cert"),
        notes: Optional[str] = typer.Option(None, "--notes", help="Free-form operator notes"),
        out_dir: Optional[str] = typer.Option(None, "--out-dir", help="Write the bundle (ca.crt/worker.crt/worker.key) to this dir for scp"),
        updater: bool = typer.Option(False, "--updater", help="Also issue an updater-identity cert (CN=updater@<name>) for the remote self-updater"),
        url: Optional[str] = typer.Option(None, "--url", help="Override swarm controller URL (default: 127.0.0.1:8770)"),
    ) -> None:
        """Issue a mTLS bundle for a new worker and register it in the swarm."""
        import pathlib as _pathlib

        body: dict = {"name": name, "address": address, "agent_port": agent_port}
        if sans:
            body["sans"] = [s.strip() for s in sans.split(",") if s.strip()]
        if notes:
            body["notes"] = notes
        if updater:
            body["issue_updater_bundle"] = True

        resp = _utils._http_request("POST", _utils._swarmctl_base_url(url) + "/swarm/enroll", json_body=body)
        data = resp.json()

        console.print(f"[green]Enrolled worker:[/] {data['name']}  "
                      f"[dim]uuid=[/]{data['host_uuid']}  "
                      f"[dim]fingerprint=[/]{data['fingerprint']}")
        if data.get("updater"):
            console.print(f"[green]  + updater identity[/] "
                          f"[dim]fingerprint=[/]{data['updater']['fingerprint']}")

        if out_dir:
            target = _pathlib.Path(out_dir).expanduser()
            target.mkdir(parents=True, exist_ok=True)
            (target / "ca.crt").write_text(data["ca_cert_pem"])
            (target / "worker.crt").write_text(data["worker_cert_pem"])
            (target / "worker.key").write_text(data["worker_key_pem"])
            for leaf in ("worker.key",):
                try:
                    (target / leaf).chmod(0o600)
                except OSError:
                    pass
            console.print(f"[cyan]Agent bundle written to[/] {target}")

            if data.get("updater"):
                upd_target = target.parent / f"{target.name}-updater"
                upd_target.mkdir(parents=True, exist_ok=True)
                (upd_target / "ca.crt").write_text(data["ca_cert_pem"])
                (upd_target / "updater.crt").write_text(data["updater"]["updater_cert_pem"])
                (upd_target / "updater.key").write_text(data["updater"]["updater_key_pem"])
                try:
                    (upd_target / "updater.key").chmod(0o600)
                except OSError:
                    pass
                console.print(f"[cyan]Updater bundle written to[/] {upd_target}")
                console.print("[dim]Ship the agent dir to ~/.decnet/agent/ and the updater dir to ~/.decnet/updater/ on the worker.[/]")
            else:
                console.print("[dim]Ship this directory to the worker at ~/.decnet/agent/ (or wherever `decnet agent --agent-dir` points).[/]")
        else:
            console.print("[yellow]No --out-dir given — bundle PEMs are in the JSON response; persist them before leaving this shell.[/]")

    @swarm_app.command("list")
    def swarm_list(
        host_status: Optional[str] = typer.Option(None, "--status", help="Filter by status (enrolled|active|unreachable|decommissioned)"),
        url: Optional[str] = typer.Option(None, "--url", help="Override swarm controller URL"),
    ) -> None:
        """List enrolled workers."""
        q = f"?host_status={host_status}" if host_status else ""
        resp = _utils._http_request("GET", _utils._swarmctl_base_url(url) + "/swarm/hosts" + q)
        rows = resp.json()
        if not rows:
            console.print("[dim]No workers enrolled.[/]")
            return
        table = Table(title="DECNET swarm workers")
        for col in ("name", "address", "port", "status", "last heartbeat", "enrolled"):
            table.add_column(col)
        for r in rows:
            table.add_row(
                r.get("name") or "",
                r.get("address") or "",
                str(r.get("agent_port") or ""),
                r.get("status") or "",
                str(r.get("last_heartbeat") or "—"),
                str(r.get("enrolled_at") or "—"),
            )
        console.print(table)

    @swarm_app.command("check")
    def swarm_check(
        url: Optional[str] = typer.Option(None, "--url", help="Override swarm controller URL"),
        json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
    ) -> None:
        """Actively probe every enrolled worker and refresh status + last_heartbeat."""
        resp = _utils._http_request("POST", _utils._swarmctl_base_url(url) + "/swarm/check", timeout=60.0)
        payload = resp.json()
        results = payload.get("results", [])

        if json_out:
            console.print_json(data=payload)
            return

        if not results:
            console.print("[dim]No workers enrolled.[/]")
            return

        table = Table(title="DECNET swarm check")
        for col in ("name", "address", "reachable", "detail"):
            table.add_column(col)
        for r in results:
            reachable = r.get("reachable")
            mark = "[green]yes[/]" if reachable else "[red]no[/]"
            detail = r.get("detail")
            detail_str = "—"
            if isinstance(detail, dict):
                detail_str = detail.get("status") or ", ".join(f"{k}={v}" for k, v in detail.items())
            elif detail is not None:
                detail_str = str(detail)
            table.add_row(
                r.get("name") or "",
                r.get("address") or "",
                mark,
                detail_str,
            )
        console.print(table)

    @swarm_app.command("update")
    def swarm_update(
        host: Optional[str] = typer.Option(None, "--host", help="Target worker (name or UUID). Omit with --all."),
        all_hosts: bool = typer.Option(False, "--all", help="Push to every enrolled worker."),
        include_self: bool = typer.Option(False, "--include-self", help="Also push to each updater's /update-self after a successful agent update."),
        root: Optional[str] = typer.Option(None, "--root", help="Source tree to tar (default: CWD)."),
        exclude: list[str] = typer.Option([], "--exclude", help="Additional exclude glob. Repeatable."),
        updater_port: int = typer.Option(8766, "--updater-port", help="Port the workers' updater listens on."),
        dry_run: bool = typer.Option(False, "--dry-run", help="Build the tarball and print stats; no network."),
        url: Optional[str] = typer.Option(None, "--url", help="Override swarm controller URL."),
    ) -> None:
        """Push the current working tree to workers' self-updaters (with auto-rollback on failure)."""
        import asyncio
        import pathlib as _pathlib

        from decnet.swarm.tar_tree import tar_working_tree, detect_git_sha
        from decnet.swarm.updater_client import UpdaterClient

        if not (host or all_hosts):
            console.print("[red]Supply --host <name> or --all.[/]")
            raise typer.Exit(2)
        if host and all_hosts:
            console.print("[red]--host and --all are mutually exclusive.[/]")
            raise typer.Exit(2)

        base = _utils._swarmctl_base_url(url)
        resp = _utils._http_request("GET", base + "/swarm/hosts")
        rows = resp.json()
        if host:
            targets = [r for r in rows if r.get("name") == host or r.get("uuid") == host]
            if not targets:
                console.print(f"[red]No enrolled worker matching '{host}'.[/]")
                raise typer.Exit(1)
        else:
            targets = [r for r in rows if r.get("status") != "decommissioned"]
        if not targets:
            console.print("[dim]No targets.[/]")
            return

        tree_root = _pathlib.Path(root) if root else _pathlib.Path.cwd()
        sha = detect_git_sha(tree_root)
        console.print(f"[dim]Tarring[/] {tree_root} [dim]sha={sha or '(not a git repo)'}[/]")
        tarball = tar_working_tree(tree_root, extra_excludes=exclude)
        console.print(f"[dim]Tarball size:[/] {len(tarball):,} bytes")

        if dry_run:
            console.print("[yellow]--dry-run: not pushing.[/]")
            for t in targets:
                console.print(f"  would push to [cyan]{t.get('name')}[/] at {t.get('address')}:{updater_port}")
            return

        async def _push_one(h: dict) -> dict:
            name = h.get("name") or h.get("uuid")
            out: dict = {"name": name, "address": h.get("address"), "agent": None, "self": None}
            try:
                async with UpdaterClient(h, updater_port=updater_port) as u:
                    r = await u.update(tarball, sha=sha)
                    out["agent"] = {"status": r.status_code, "body": r.json() if r.content else {}}
                    if r.status_code == 200 and include_self:
                        rs = await u.update_self(tarball, sha=sha)
                        out["self"] = {"status": rs.status_code, "body": rs.json() if rs.content else {}}
            except Exception as exc:  # noqa: BLE001
                out["error"] = f"{type(exc).__name__}: {exc}"
            return out

        async def _push_all() -> list[dict]:
            return await asyncio.gather(*(_push_one(t) for t in targets))

        results = asyncio.run(_push_all())

        table = Table(title="DECNET swarm update")
        for col in ("host", "address", "agent", "self", "detail"):
            table.add_column(col)
        any_failure = False
        for r in results:
            agent = r.get("agent") or {}
            selff = r.get("self") or {}
            err = r.get("error")
            if err:
                any_failure = True
                table.add_row(r["name"], r.get("address") or "", "[red]error[/]", "—", err)
                continue
            a_status = agent.get("status")
            if a_status == 200:
                agent_cell = "[green]updated[/]"
            elif a_status == 409:
                agent_cell = "[yellow]rolled-back[/]"
                any_failure = True
            else:
                agent_cell = f"[red]{a_status}[/]"
                any_failure = True
            if not include_self:
                self_cell = "—"
            elif selff.get("status") == 200 or selff.get("status") is None:
                self_cell = "[green]ok[/]" if selff else "[dim]skipped[/]"
            else:
                self_cell = f"[red]{selff.get('status')}[/]"
            detail = ""
            body = agent.get("body") or {}
            if isinstance(body, dict):
                detail = body.get("release", {}).get("sha") or body.get("detail", {}).get("error") or ""
            table.add_row(r["name"], r.get("address") or "", agent_cell, self_cell, str(detail)[:80])
        console.print(table)

        if any_failure:
            raise typer.Exit(1)

    @swarm_app.command("deckies")
    def swarm_deckies(
        host: Optional[str] = typer.Option(None, "--host", help="Filter by worker name or UUID"),
        state: Optional[str] = typer.Option(None, "--state", help="Filter by shard state (pending|running|failed|torn_down)"),
        url: Optional[str] = typer.Option(None, "--url", help="Override swarm controller URL"),
        json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
    ) -> None:
        """List deployed deckies across the swarm with their owning worker host."""
        base = _utils._swarmctl_base_url(url)

        host_uuid: Optional[str] = None
        if host:
            resp = _utils._http_request("GET", base + "/swarm/hosts")
            rows = resp.json()
            match = next((r for r in rows if r.get("uuid") == host or r.get("name") == host), None)
            if match is None:
                console.print(f"[red]No enrolled worker matching '{host}'.[/]")
                raise typer.Exit(1)
            host_uuid = match["uuid"]

        query = []
        if host_uuid:
            query.append(f"host_uuid={host_uuid}")
        if state:
            query.append(f"state={state}")
        path = "/swarm/deckies" + ("?" + "&".join(query) if query else "")

        resp = _utils._http_request("GET", base + path)
        rows = resp.json()

        if json_out:
            console.print_json(data=rows)
            return

        if not rows:
            console.print("[dim]No deckies deployed.[/]")
            return

        table = Table(title="DECNET swarm deckies")
        for col in ("decky", "host", "address", "state", "services"):
            table.add_column(col)
        for r in rows:
            services = ",".join(r.get("services") or []) or "—"
            state_val = r.get("state") or "pending"
            colored = {
                "running": f"[green]{state_val}[/]",
                "failed": f"[red]{state_val}[/]",
                "pending": f"[yellow]{state_val}[/]",
                "torn_down": f"[dim]{state_val}[/]",
            }.get(state_val, state_val)
            table.add_row(
                r.get("decky_name") or "",
                r.get("host_name") or "<unknown>",
                r.get("host_address") or "",
                colored,
                services,
            )
        console.print(table)

    @swarm_app.command("decommission")
    def swarm_decommission(
        name: Optional[str] = typer.Option(None, "--name", help="Worker hostname"),
        uuid: Optional[str] = typer.Option(None, "--uuid", help="Worker UUID (skip lookup)"),
        url: Optional[str] = typer.Option(None, "--url", help="Override swarm controller URL"),
        yes: bool = typer.Option(False, "--yes", "-y", help="Skip interactive confirmation"),
    ) -> None:
        """Remove a worker from the swarm (cascades decky shard rows)."""
        if not (name or uuid):
            console.print("[red]Supply --name or --uuid.[/]")
            raise typer.Exit(2)

        base = _utils._swarmctl_base_url(url)
        target_uuid = uuid
        target_name = name
        if target_uuid is None:
            resp = _utils._http_request("GET", base + "/swarm/hosts")
            rows = resp.json()
            match = next((r for r in rows if r.get("name") == name), None)
            if match is None:
                console.print(f"[red]No enrolled worker named '{name}'.[/]")
                raise typer.Exit(1)
            target_uuid = match["uuid"]
            target_name = match.get("name") or target_name

        if not yes:
            confirm = typer.confirm(f"Decommission worker {target_name!r} ({target_uuid})?", default=False)
            if not confirm:
                console.print("[dim]Aborted.[/]")
                raise typer.Exit(0)

        _utils._http_request("DELETE", f"{base}/swarm/hosts/{target_uuid}")
        console.print(f"[green]Decommissioned {target_name or target_uuid}.[/]")
