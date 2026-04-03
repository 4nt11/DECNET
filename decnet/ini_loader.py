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

    [hostname-2]
    services=ssh

    [hostname-3]
    ip=192.168.1.32
"""

import configparser
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DeckySpec:
    name: str
    ip: str | None = None
    services: list[str] | None = None


@dataclass
class IniConfig:
    subnet: str | None = None
    gateway: str | None = None
    interface: str | None = None
    log_target: str | None = None
    deckies: list[DeckySpec] = field(default_factory=list)


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

    for section in cp.sections():
        if section == "general":
            continue
        s = cp[section]
        ip = s.get("ip")
        svc_raw = s.get("services")
        services = [sv.strip() for sv in svc_raw.split(",")] if svc_raw else None
        cfg.deckies.append(DeckySpec(name=section, ip=ip, services=services))

    return cfg
