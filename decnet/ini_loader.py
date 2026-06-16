# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Parse DECNET INI deployment config files.

Format:
    [general]
    net=192.168.1.0/24
    gw=192.168.1.1
    interface=wlp6s0

    [hostname-1]
    ip=192.168.1.82               # optional
    services=ssh,smb              # optional; falls back to --randomize-services
    archetype=linux-server        # optional; sets services+distros automatically
    amount=3                      # optional; spawn N deckies from this config (default: 1)

    [hostname-1.ssh]              # optional per-service persona config
    kernel_version=5.15.0-76-generic
    users=root:toor,admin:admin123

    [hostname-1.http]
    server_header=nginx/1.18.0
    fake_app=wordpress

    [hostname-2]
    services=ssh

    [hostname-3]
    ip=192.168.1.32

    # Archetype shorthand — spin up 5 windows workstations:
    [corp-workstations]
    archetype=windows-workstation
    amount=5

    # Custom (bring-your-own) service definitions:
    [custom-myservice]
    binary=my-docker-image:latest
    exec=/usr/bin/myservice -p 8080
    ports=8080

"""

import configparser
from pathlib import Path
from decnet.models import IniConfig, DeckySpec, CustomServiceSpec, validate_ini_string  # noqa: F401


def load_ini(path: str | Path) -> IniConfig:
    """Parse a DECNET INI file and return an IniConfig."""
    cp = configparser.ConfigParser()
    read = cp.read(str(path))
    if not read:
        raise FileNotFoundError(f"Config file not found: {path}")
    return _parse_configparser(cp)


def load_ini_from_string(content: str) -> IniConfig:
    """Parse a DECNET INI string and return an IniConfig."""
    # Normalize line endings (CRLF → LF, bare CR → LF) so the validator
    # and configparser both see the same line boundaries.
    content = content.replace('\r\n', '\n').replace('\r', '\n')
    validate_ini_string(content)
    cp = configparser.ConfigParser(strict=False)
    cp.read_string(content)
    return _parse_configparser(cp)


def _parse_configparser(cp: configparser.ConfigParser) -> IniConfig:
    cfg = IniConfig()

    if cp.has_section("general"):
        g = cp["general"]
        cfg.subnet = g.get("net")
        cfg.gateway = g.get("gw")
        cfg.interface = g.get("interface")

    from decnet.services.registry import all_services
    known_services = set(all_services().keys())

    # First pass: collect decky sections and custom service definitions
    for section in cp.sections():
        if section == "general":
            continue

        # A service sub-section is identified if the section name has at least one dot
        # AND the last segment is a known service name.
        # e.g. "decky-01.ssh" -> sub-section
        # e.g. "decky.webmail" -> decky section (if "webmail" is not a service)
        if "." in section:
            _, _, last_segment = section.rpartition(".")
            if last_segment in known_services:
                continue  # sub-section handled in second pass

        if section.startswith("custom-"):
            # Bring-your-own service definition
            s = cp[section]
            svc_name = section[len("custom-"):]
            image = s.get("binary", "")
            exec_cmd = s.get("exec", "")
            ports_raw = s.get("ports", "")
            ports = [int(p.strip()) for p in ports_raw.split(",") if p.strip().isdigit()]
            cfg.custom_services.append(
                CustomServiceSpec(name=svc_name, image=image, exec_cmd=exec_cmd, ports=ports)
            )
            continue
        s = cp[section]
        ip = s.get("ip")
        svc_raw = s.get("services")
        services = [sv.strip() for sv in svc_raw.split(",")] if svc_raw else None
        archetype = s.get("archetype")
        nmap_os = s.get("nmap_os") or s.get("nmap-os") or None

        mi_raw = s.get("mutate_interval") or s.get("mutate-interval")
        mutate_interval = None
        if mi_raw:
            try:
                mutate_interval = int(mi_raw)
            except ValueError:
                raise ValueError(f"[{section}] mutate_interval= must be an integer, got '{mi_raw}'")

        amount_raw = s.get("amount", "1")
        try:
            amount = int(amount_raw)
            if amount < 1:
                raise ValueError
            if amount > 100:
                raise ValueError(f"[{section}] amount={amount} exceeds maximum allowed (100).")
        except ValueError as e:
            if "exceeds maximum" in str(e):
                raise e
            raise ValueError(f"[{section}] amount= must be a positive integer, got '{amount_raw}'")

        if amount == 1:
            cfg.deckies.append(DeckySpec(
                name=section, ip=ip, services=services, archetype=archetype, nmap_os=nmap_os, mutate_interval=mutate_interval,
            ))
        else:
            # Expand into N deckies; explicit ip is ignored (can't share one IP)
            if ip:
                raise ValueError(
                    f"[{section}] Cannot combine ip= with amount={amount}. "
                    "Remove ip= or use amount=1."
                )
            for idx in range(1, amount + 1):
                cfg.deckies.append(DeckySpec(
                    name=f"{section}-{idx:02d}",
                    ip=None,
                    services=services,
                    archetype=archetype,
                    nmap_os=nmap_os,
                    mutate_interval=mutate_interval,
                ))

    # Second pass: collect per-service subsections [decky-name.service]
    # Also propagates to expanded deckies: [group.ssh] applies to group-01, group-02, ...
    decky_map = {d.name: d for d in cfg.deckies}
    for section in cp.sections():
        if "." not in section:
            continue

        decky_name, dot, svc_name = section.rpartition(".")
        if svc_name not in known_services:
            continue # not a service sub-section

        svc_cfg = {k: v for k, v in cp[section].items()}
        if decky_name in decky_map:
            # Direct match — single decky
            decky_map[decky_name].service_config[svc_name] = svc_cfg
        else:
            # Try to find expanded deckies with prefix "{decky_name}-NN"
            matched = [
                d for d in cfg.deckies
                if d.name.startswith(f"{decky_name}-")
            ]
            if not matched:
                continue  # orphaned subsection — ignore
            for d in matched:
                d.service_config[svc_name] = svc_cfg

    return cfg
