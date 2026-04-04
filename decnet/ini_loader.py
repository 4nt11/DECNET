"""
Parse DECNET INI deployment config files.

Format:
    [general]
    net=192.168.1.0/24
    gw=192.168.1.1
    interface=wlp6s0
    log_target=192.168.1.5:5140   # optional

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
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DeckySpec:
    name: str
    ip: str | None = None
    services: list[str] | None = None
    archetype: str | None = None
    service_config: dict[str, dict] = field(default_factory=dict)
    nmap_os: str | None = None     # explicit OS family override (linux/windows/bsd/embedded/cisco)


@dataclass
class CustomServiceSpec:
    """Spec for a user-defined (bring-your-own) service."""
    name: str          # service slug, e.g. "myservice" (section is "custom-myservice")
    image: str         # Docker image to use
    exec_cmd: str      # command to run inside the container
    ports: list[int] = field(default_factory=list)


@dataclass
class IniConfig:
    subnet: str | None = None
    gateway: str | None = None
    interface: str | None = None
    log_target: str | None = None
    deckies: list[DeckySpec] = field(default_factory=list)
    custom_services: list[CustomServiceSpec] = field(default_factory=list)


def load_ini(path: str | Path) -> IniConfig:
    """Parse a DECNET INI file and return an IniConfig."""
    cp = configparser.ConfigParser()
    read = cp.read(str(path))
    if not read:
        raise FileNotFoundError(f"Config file not found: {path}")

    cfg = IniConfig()

    if cp.has_section("general"):
        g = cp["general"]
        cfg.subnet = g.get("net")
        cfg.gateway = g.get("gw")
        cfg.interface = g.get("interface")
        cfg.log_target = g.get("log_target") or g.get("log-target")

    # First pass: collect decky sections and custom service definitions
    for section in cp.sections():
        if section == "general":
            continue
        if "." in section:
            continue  # subsections handled in second pass
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
        amount_raw = s.get("amount", "1")
        try:
            amount = int(amount_raw)
            if amount < 1:
                raise ValueError
        except ValueError:
            raise ValueError(f"[{section}] amount= must be a positive integer, got '{amount_raw}'")

        if amount == 1:
            cfg.deckies.append(DeckySpec(
                name=section, ip=ip, services=services, archetype=archetype, nmap_os=nmap_os,
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
                ))

    # Second pass: collect per-service subsections [decky-name.service]
    # Also propagates to expanded deckies: [group.ssh] applies to group-01, group-02, ...
    decky_map = {d.name: d for d in cfg.deckies}
    for section in cp.sections():
        if "." not in section:
            continue
        decky_name, _, svc_name = section.partition(".")
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
