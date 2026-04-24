"""GeoIP CLI — refresh and lookup subcommands (master-only).

Usage::

    decnet geoip refresh          # re-download RIR files and rebuild the index
    decnet geoip lookup 8.8.8.8   # one-shot IP -> country dump
"""
from __future__ import annotations

import typer

from .gating import _require_master_mode
from .utils import console, log

_group = typer.Typer(
    name="geoip",
    help="GeoIP provider management (master only).",
    no_args_is_help=True,
)


@_group.command("refresh")
def _refresh() -> None:
    """Force re-download of the GeoIP provider data and rebuild the index."""
    _require_master_mode("geoip refresh")
    from decnet.geoip import get_lookup
    from decnet.geoip.factory import get_provider

    provider = get_provider()
    log.info("geoip: forcing refresh via %s provider", provider.name)
    console.print(f"[bold cyan]Refreshing {provider.name} GeoIP data…[/]")
    try:
        lookup = get_lookup(force_refresh=True)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]refresh failed: {exc}[/]")
        raise typer.Exit(1) from exc
    console.print(
        f"[green]OK[/] {provider.name} index rebuilt "
        f"({len(lookup)} ranges)."
    )


@_group.command("lookup")
def _lookup(
    ip: str = typer.Argument(..., help="IP address to resolve."),
) -> None:
    """Print the country code for an IP (or 'unknown')."""
    _require_master_mode("geoip lookup")
    from decnet.geoip import enrich_ip

    cc, source = enrich_ip(ip)
    if cc is None:
        console.print(f"{ip} [yellow]unknown[/]")
        raise typer.Exit(0)
    console.print(f"{ip} [green]cc={cc}[/] source={source}")


def register(app: typer.Typer) -> None:
    app.add_typer(_group, name="geoip")
