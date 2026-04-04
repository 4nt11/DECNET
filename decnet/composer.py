"""
Generates a docker-compose.yml from a DecnetConfig.

Network model:
  Each decky gets ONE "base" container that holds the MACVLAN IP.
  All service containers for that decky share the base's network namespace
  via `network_mode: "service:<base>"`.  From the outside, every service on
  a given decky appears to come from the same IP — exactly like a real host.
"""

from pathlib import Path

import yaml

from decnet.config import DecnetConfig
from decnet.network import MACVLAN_NETWORK_NAME
from decnet.os_fingerprint import get_os_sysctls
from decnet.services.registry import get_service

_CONTAINER_LOG_DIR = "/var/log/decnet"

_LOG_NETWORK = "decnet_logs"


def _resolve_log_file(log_file: str) -> tuple[str, str]:
    """
    Return (host_dir, container_log_path) for a user-supplied log file path.

    The host path is resolved to absolute so Docker can bind-mount it.
    All containers share the same host directory, mounted at _CONTAINER_LOG_DIR.
    """
    host_path = Path(log_file).resolve()
    host_dir = str(host_path.parent)
    container_path = f"{_CONTAINER_LOG_DIR}/{host_path.name}"
    return host_dir, container_path


def generate_compose(config: DecnetConfig) -> dict:
    """Build and return the full docker-compose data structure."""
    services: dict = {}

    log_host_dir: str | None = None
    log_container_path: str | None = None
    if config.log_file:
        log_host_dir, log_container_path = _resolve_log_file(config.log_file)
        # Ensure the host log directory exists so Docker doesn't create it as root-owned
        Path(log_host_dir).mkdir(parents=True, exist_ok=True)

    for decky in config.deckies:
        base_key = decky.name  # e.g. "decky-01"

        # --- Base container: owns the MACVLAN IP, runs nothing but sleep ---
        base: dict = {
            "image": decky.base_image,
            "container_name": base_key,
            "hostname": decky.hostname,
            "command": ["sleep", "infinity"],
            "restart": "unless-stopped",
            "networks": {
                MACVLAN_NETWORK_NAME: {
                    "ipv4_address": decky.ip,
                }
            },
        }
        if config.log_target:
            base["networks"][_LOG_NETWORK] = {}

        # Inject TCP/IP stack sysctls to spoof the claimed OS fingerprint.
        # Only the base container needs this — service containers inherit the
        # same network namespace via network_mode: "service:<base>".
        base["sysctls"] = get_os_sysctls(decky.nmap_os)
        base["cap_add"] = ["NET_ADMIN"]

        services[base_key] = base

        # --- Service containers: share base network namespace ---
        for svc_name in decky.services:
            svc = get_service(svc_name)
            svc_cfg = decky.service_config.get(svc_name, {})
            fragment = svc.compose_fragment(
                decky.name, log_target=config.log_target, service_cfg=svc_cfg
            )

            # Inject the per-decky base image into build services so containers
            # vary by distro and don't all fingerprint as debian:bookworm-slim.
            if "build" in fragment:
                fragment["build"].setdefault("args", {})["BASE_IMAGE"] = decky.build_base

            fragment.setdefault("environment", {})
            fragment["environment"]["HOSTNAME"] = decky.hostname
            if log_host_dir and log_container_path:
                fragment["environment"]["DECNET_LOG_FILE"] = log_container_path
                fragment.setdefault("volumes", [])
                mount = f"{log_host_dir}:{_CONTAINER_LOG_DIR}"
                if mount not in fragment["volumes"]:
                    fragment["volumes"].append(mount)

            # Share the base container's network — no own IP needed
            fragment["network_mode"] = f"service:{base_key}"
            fragment["depends_on"] = [base_key]

            # hostname must not be set when using network_mode
            fragment.pop("hostname", None)
            fragment.pop("networks", None)

            services[f"{decky.name}-{svc_name}"] = fragment

    # Network definitions
    networks: dict = {
        MACVLAN_NETWORK_NAME: {
            "external": True,  # created by network.py before compose up
        }
    }
    if config.log_target:
        networks[_LOG_NETWORK] = {"driver": "bridge", "internal": True}

    return {
        "version": "3.8",
        "services": services,
        "networks": networks,
    }


def write_compose(config: DecnetConfig, output_path: Path) -> Path:
    """Write the docker-compose.yml to output_path and return it."""
    data = generate_compose(config)
    output_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
    return output_path
