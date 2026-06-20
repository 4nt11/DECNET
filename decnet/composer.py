# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Generates a docker-compose.yml from a DecnetConfig.

Network model:
  Each decky gets ONE "base" container that holds the MACVLAN IP.
  All service containers for that decky share the base's network namespace
  via `network_mode: "service:<base>"`.  From the outside, every service on
  a given decky appears to come from the same IP — exactly like a real host.

Logging model:
  Service containers write RFC 5424 lines to stdout.  Docker captures them
  via the json-file driver.  The host-side collector (decnet.web.collector)
  streams those logs and writes them to the host log file for the ingester
  and rsyslog to consume.  No bind mounts or shared volumes are needed.
"""

from pathlib import Path

import yaml

from decnet.config import DecnetConfig
from decnet.network import MACVLAN_NETWORK_NAME
from decnet.os_fingerprint import get_os_mangle, get_os_sysctls
from decnet.services.registry import get_service

_DOCKER_LOGGING = {
    "driver": "json-file",
    "options": {
        "max-size": "10m",
        "max-file": "5",
    },
}

# Build context for the cloak base image (decnet subtree synced in by
# deployer._sync_cloak_sources before build).
_CLOAK_CONTEXT = Path(__file__).parent / "templates" / "_shared" / "cloak"

# Netns-safe: run the cloak best-effort in the background, but keep `sleep
# infinity` as PID 1 in the foreground so a cloak crash never tears down the
# base container (and with it the netns every service container shares).
_CLOAK_COMMAND = ["sh", "-c", "python3 -m decnet.cloak & exec sleep infinity"]


def _decky_open_tcp_ports(services: list[str]) -> list[int]:
    """Sorted, de-duped TCP ports a decky's services listen on (for the cloak
    responder's T2/T3 classification — DECNET_OPEN_PORTS)."""
    ports: set[int] = set()
    for svc_name in services:
        svc = get_service(svc_name)
        if svc is not None:
            ports.update(svc.ports)
    return sorted(ports)


def generate_compose(config: DecnetConfig) -> dict:
    """Build and return the full docker-compose data structure."""
    services: dict = {}

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

        # Inject TCP/IP stack sysctls to spoof the claimed OS fingerprint.
        # Only the base container needs this — service containers inherit the
        # same network namespace via network_mode: "service:<base>".
        base["sysctls"] = get_os_sysctls(decky.nmap_os)
        base["cap_add"] = ["NET_ADMIN"]

        # sysctls reach only global packet fields. nmap_os families with an
        # egress mangle profile (windows*) additionally run the cloak in the
        # base container to rewrite SYN-ACK shape + synthesize T2/T3 replies, so
        # they read as the claimed OS under active fingerprinting (nmap -O).
        if get_os_mangle(decky.nmap_os) is not None:
            base.pop("image", None)
            base["build"] = {
                "context": str(_CLOAK_CONTEXT),
                "args": {"BASE_IMAGE": decky.build_base},
            }
            base["command"] = _CLOAK_COMMAND
            base["cap_add"] = ["NET_ADMIN", "NET_RAW"]  # NET_RAW: responder send/sniff
            ports = _decky_open_tcp_ports(decky.services)
            base["environment"] = {
                "DECNET_NMAP_OS": decky.nmap_os,
                "DECNET_OPEN_PORTS": ",".join(str(p) for p in ports),
                "DECKY_IP": decky.ip,
            }

        services[base_key] = base

        # --- Service containers: share base network namespace ---
        for svc_name in decky.services:
            svc = get_service(svc_name)
            if svc.fleet_singleton:
                continue
            svc_cfg = decky.service_config.get(svc_name, {})
            fragment = svc.compose_fragment(decky.name, service_cfg=svc_cfg)

            # Inject the per-decky base image into build services so containers
            # vary by distro and don't all fingerprint as debian:bookworm-slim.
            # Services that need a fixed upstream image (e.g. conpot) can pre-set
            # build.args.BASE_IMAGE in their compose_fragment() to opt out.
            if "build" in fragment:
                args = fragment["build"].setdefault("args", {})
                args.setdefault("BASE_IMAGE", decky.build_base)

            fragment.setdefault("environment", {})
            fragment["environment"]["HOSTNAME"] = decky.hostname

            # Share the base container's network — no own IP needed
            fragment["network_mode"] = f"service:{base_key}"
            fragment["depends_on"] = [base_key]

            # hostname must not be set when using network_mode
            fragment.pop("hostname", None)
            fragment.pop("networks", None)

            # Rotate Docker logs so disk usage is bounded
            fragment["logging"] = _DOCKER_LOGGING

            # Stamp DECNET ownership labels so the collector's docker-events
            # watcher can identify newly-started containers without consulting
            # decnet-state.json (which is written and read out-of-band with
            # `docker compose up`, leaving a race window where freshly started
            # containers were silently ignored).
            labels = dict(fragment.get("labels") or {})
            labels.update({
                "decnet.fleet.service": "true",
                "decnet.fleet.decky": decky.name,
                "decnet.fleet.service_name": svc_name,
            })
            fragment["labels"] = labels

            services[f"{decky.name}-{svc_name}"] = fragment

    # Network definitions
    networks: dict = {
        MACVLAN_NETWORK_NAME: {
            "external": True,  # created by network.py before compose up
        }
    }

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
