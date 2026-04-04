"""
Pydantic models for DECNET configuration and runtime state.
State is persisted to decnet-state.json in the working directory.
"""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, field_validator

from decnet.distros import random_hostname as _random_hostname

STATE_FILE = Path("decnet-state.json")


def random_hostname(distro_slug: str = "debian") -> str:
    return _random_hostname(distro_slug)


class DeckyConfig(BaseModel):
    name: str
    ip: str
    services: list[str]
    distro: str          # slug from distros.DISTROS, e.g. "debian", "ubuntu22"
    base_image: str      # Docker image for the base/IP-holder container
    build_base: str = "debian:bookworm-slim"  # apt-compatible image for service Dockerfiles
    hostname: str
    archetype: str | None = None  # archetype slug if spawned from an archetype profile
    service_config: dict[str, dict] = {}  # optional per-service persona config
    nmap_os: str = "linux"        # OS family for TCP/IP stack spoofing (see os_fingerprint.py)

    @field_validator("services")
    @classmethod
    def services_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("A decky must have at least one service.")
        return v


class DecnetConfig(BaseModel):
    mode: Literal["unihost", "swarm"]
    interface: str
    subnet: str
    gateway: str
    deckies: list[DeckyConfig]
    log_target: str | None = None  # "ip:port" or None
    log_file: str | None = None    # path for RFC 5424 syslog file output
    ipvlan: bool = False           # use IPvlan L2 instead of MACVLAN (WiFi-friendly)

    @field_validator("log_target")
    @classmethod
    def validate_log_target(cls, v: str | None) -> str | None:
        if v is None:
            return v
        parts = v.rsplit(":", 1)
        if len(parts) != 2 or not parts[1].isdigit():
            raise ValueError("log_target must be in ip:port format, e.g. 192.168.1.5:5140")
        return v


def save_state(config: DecnetConfig, compose_path: Path) -> None:
    payload = {
        "config": config.model_dump(),
        "compose_path": str(compose_path),
    }
    STATE_FILE.write_text(json.dumps(payload, indent=2))


def load_state() -> tuple[DecnetConfig, Path] | None:
    if not STATE_FILE.exists():
        return None
    data = json.loads(STATE_FILE.read_text())
    return DecnetConfig(**data["config"]), Path(data["compose_path"])


def clear_state() -> None:
    if STATE_FILE.exists():
        STATE_FILE.unlink()
