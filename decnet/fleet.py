"""
Fleet builder — shared logic for constructing DeckyConfig lists.

Used by both the CLI and the web API router to build deckies from
flags or INI config. Lives here (not in cli.py) so that the web layer
and the mutation engine can import it without depending on the CLI.
"""

import random
from typing import Optional

from decnet.archetypes import Archetype, get_archetype
from decnet.config import DeckyConfig, random_hostname
from decnet.distros import all_distros, get_distro, random_distro
from decnet.models import IniConfig
from decnet.services.registry import all_services


def all_service_names() -> list[str]:
    """Return all registered service names from the live plugin registry."""
    return sorted(all_services().keys())


def resolve_distros(
    distros_explicit: list[str] | None,
    randomize_distros: bool,
    n: int,
    archetype: Archetype | None = None,
) -> list[str]:
    """Return a list of n distro slugs based on flags or archetype preference."""
    if distros_explicit:
        return [distros_explicit[i % len(distros_explicit)] for i in range(n)]
    if randomize_distros:
        return [random_distro().slug for _ in range(n)]
    if archetype:
        pool = archetype.preferred_distros
        return [pool[i % len(pool)] for i in range(n)]
    slugs = list(all_distros().keys())
    return [slugs[i % len(slugs)] for i in range(n)]


def build_deckies(
    n: int,
    ips: list[str],
    services_explicit: list[str] | None,
    randomize_services: bool,
    distros_explicit: list[str] | None = None,
    randomize_distros: bool = False,
    archetype: Archetype | None = None,
    mutate_interval: Optional[int] = None,
) -> list[DeckyConfig]:
    """Build a list of DeckyConfigs from CLI-style flags."""
    deckies = []
    used_combos: set[frozenset] = set()
    distro_slugs = resolve_distros(distros_explicit, randomize_distros, n, archetype)

    for i, ip in enumerate(ips):
        name = f"decky-{i + 1:02d}"
        distro = get_distro(distro_slugs[i])
        hostname = random_hostname(distro.slug)

        if services_explicit:
            svc_list = services_explicit
        elif archetype:
            svc_list = list(archetype.services)
        elif randomize_services:
            svc_pool = all_service_names()
            attempts = 0
            while True:
                count = random.randint(1, min(3, len(svc_pool)))  # nosec B311
                chosen = frozenset(random.sample(svc_pool, count))  # nosec B311
                attempts += 1
                if chosen not in used_combos or attempts > 20:
                    break
            svc_list = list(chosen)
            used_combos.add(chosen)
        else:
            raise ValueError("Provide services_explicit, archetype, or randomize_services=True.")

        deckies.append(
            DeckyConfig(
                name=name,
                ip=ip,
                services=svc_list,
                distro=distro.slug,
                base_image=distro.image,
                build_base=distro.build_base,
                hostname=hostname,
                archetype=archetype.slug if archetype else None,
                nmap_os=archetype.nmap_os if archetype else "linux",
                mutate_interval=mutate_interval,
            )
        )
    return deckies


def build_deckies_from_ini(
    ini: IniConfig,
    subnet_cidr: str,
    gateway: str,
    host_ip: str,
    randomize: bool,
    cli_mutate_interval: int | None = None,
) -> list[DeckyConfig]:
    """Build DeckyConfig list from an IniConfig, auto-allocating missing IPs."""
    from ipaddress import IPv4Address, IPv4Network
    import time
    now = time.time()

    explicit_ips: set[IPv4Address] = {
        IPv4Address(s.ip) for s in ini.deckies if s.ip
    }

    net = IPv4Network(subnet_cidr, strict=False)
    reserved = {
        net.network_address,
        net.broadcast_address,
        IPv4Address(gateway),
        IPv4Address(host_ip),
    } | explicit_ips

    auto_pool = (str(addr) for addr in net.hosts() if addr not in reserved)

    deckies: list[DeckyConfig] = []
    for spec in ini.deckies:
        arch: Archetype | None = None
        if spec.archetype:
            arch = get_archetype(spec.archetype)

        distro_pool = arch.preferred_distros if arch else list(all_distros().keys())
        distro = get_distro(distro_pool[len(deckies) % len(distro_pool)])
        hostname = random_hostname(distro.slug)

        ip = spec.ip or next(auto_pool, None)
        if ip is None:
            raise ValueError(f"Not enough free IPs in {subnet_cidr} while assigning IP for '{spec.name}'.")

        if spec.services:
            known = set(all_service_names())
            unknown = [s for s in spec.services if s not in known]
            if unknown:
                raise ValueError(
                    f"Unknown service(s) in [{spec.name}]: {unknown}. "
                    f"Available: {all_service_names()}"
                )
            svc_list = spec.services
        elif arch:
            svc_list = list(arch.services)
        elif randomize or (not spec.services and not arch):
            svc_pool = all_service_names()
            count = random.randint(1, min(3, len(svc_pool)))  # nosec B311
            svc_list = random.sample(svc_pool, count)  # nosec B311

        resolved_nmap_os = spec.nmap_os or (arch.nmap_os if arch else "linux")

        decky_mutate_interval = cli_mutate_interval
        if decky_mutate_interval is None:
            decky_mutate_interval = spec.mutate_interval if spec.mutate_interval is not None else ini.mutate_interval

        deckies.append(DeckyConfig(
            name=spec.name,
            ip=ip,
            services=svc_list,
            distro=distro.slug,
            base_image=distro.image,
            build_base=distro.build_base,
            hostname=hostname,
            archetype=arch.slug if arch else None,
            service_config=spec.service_config,
            nmap_os=resolved_nmap_os,
            mutate_interval=decky_mutate_interval,
            last_mutated=now,
        ))
    return deckies
