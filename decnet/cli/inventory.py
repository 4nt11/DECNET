# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import typer
from rich.table import Table

from decnet.archetypes import all_archetypes
from decnet.distros import all_distros
from decnet.services.registry import all_services

from .utils import console


def register(app: typer.Typer) -> None:
    @app.command(name="services")
    def list_services() -> None:
        """List all registered honeypot service plugins."""
        svcs = all_services()
        table = Table(title="Available Services", show_lines=True)
        table.add_column("Name", style="bold cyan")
        table.add_column("Ports")
        table.add_column("Image")
        for name, svc in sorted(svcs.items()):
            table.add_row(name, ", ".join(str(p) for p in svc.ports), svc.default_image)
        console.print(table)

    @app.command(name="distros")
    def list_distros() -> None:
        """List all available OS distro profiles for deckies."""
        table = Table(title="Available Distro Profiles", show_lines=True)
        table.add_column("Slug", style="bold cyan")
        table.add_column("Display Name")
        table.add_column("Docker Image", style="dim")
        for slug, profile in sorted(all_distros().items()):
            table.add_row(slug, profile.display_name, profile.image)
        console.print(table)

    @app.command(name="archetypes")
    def list_archetypes() -> None:
        """List all machine archetype profiles."""
        table = Table(title="Machine Archetypes", show_lines=True)
        table.add_column("Slug", style="bold cyan")
        table.add_column("Display Name")
        table.add_column("Default Services", style="green")
        table.add_column("Description", style="dim")
        for slug, arch in sorted(all_archetypes().items()):
            table.add_row(
                slug,
                arch.display_name,
                ", ".join(arch.services),
                arch.description,
            )
        console.print(table)
