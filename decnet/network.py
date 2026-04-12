"""
Network management for DECNET.

Handles:
  - Auto-detection of the host's active interface + subnet + gateway
  - MACVLAN Docker network creation
  - Host-side macvlan interface (hairpin fix so the deployer can reach deckies)
  - IP allocation (sequential, skipping reserved addresses)
"""

import os
import subprocess  # nosec B404
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

import docker

MACVLAN_NETWORK_NAME = "decnet_lan"
HOST_MACVLAN_IFACE = "decnet_macvlan0"
HOST_IPVLAN_IFACE = "decnet_ipvlan0"


# ---------------------------------------------------------------------------
# Interface / subnet auto-detection
# ---------------------------------------------------------------------------

def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)  # nosec B603 B404


def detect_interface() -> str:
    """Return the name of the default outbound interface."""
    result = _run(["ip", "route", "show", "default"])
    for line in result.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    raise RuntimeError("Could not auto-detect network interface. Use --interface.")


def detect_subnet(interface: str) -> tuple[str, str]:
    """
    Return (subnet_cidr, gateway) for the given interface.
    e.g. ("192.168.1.0/24", "192.168.1.1")
    """
    result = _run(["ip", "addr", "show", interface])
    subnet_cidr = None
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet ") and not line.startswith("inet6"):
            # e.g. "inet 192.168.1.5/24 brd 192.168.1.255 scope global eth0"
            addr_cidr = line.split()[1]
            iface = IPv4Interface(addr_cidr)
            subnet_cidr = str(iface.network)
            break
    if subnet_cidr is None:
        raise RuntimeError(f"Could not detect subnet for interface {interface}.")

    gw_result = _run(["ip", "route", "show", "default"])
    gateway = None
    for line in gw_result.stdout.splitlines():
        parts = line.split()
        if "via" in parts:
            gateway = parts[parts.index("via") + 1]
            break
    if gateway is None:
        raise RuntimeError("Could not detect gateway.")

    return subnet_cidr, gateway


def get_host_ip(interface: str) -> str:
    """Return the host's IP on the given interface."""
    result = _run(["ip", "addr", "show", interface])
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet ") and not line.startswith("inet6"):
            return line.split()[1].split("/")[0]
    raise RuntimeError(f"Could not determine host IP for interface {interface}.")


# ---------------------------------------------------------------------------
# IP allocation
# ---------------------------------------------------------------------------

def allocate_ips(
    subnet: str,
    gateway: str,
    host_ip: str,
    count: int,
    ip_start: str | None = None,
) -> list[str]:
    """
    Return a list of `count` available IPs from the subnet,
    skipping network addr, broadcast, gateway, and host IP.
    Starts from ip_start if given, else from the first usable host.
    """
    net = IPv4Network(subnet, strict=False)
    reserved = {
        net.network_address,
        net.broadcast_address,
        IPv4Address(gateway),
        IPv4Address(host_ip),
    }

    start_addr = IPv4Address(ip_start) if ip_start else net.network_address + 1

    allocated: list[str] = []
    for addr in net.hosts():
        if addr < start_addr:
            continue
        if addr in reserved:
            continue
        allocated.append(str(addr))
        if len(allocated) == count:
            break

    if len(allocated) < count:
        raise RuntimeError(
            f"Not enough free IPs in {subnet} for {count} deckies "
            f"(found {len(allocated)})."
        )
    return allocated


# ---------------------------------------------------------------------------
# Docker MACVLAN network
# ---------------------------------------------------------------------------

def create_macvlan_network(
    client: docker.DockerClient,
    interface: str,
    subnet: str,
    gateway: str,
    ip_range: str,
) -> None:
    """Create the MACVLAN Docker network. No-op if it already exists."""
    existing = [n.name for n in client.networks.list()]
    if MACVLAN_NETWORK_NAME in existing:
        return

    client.networks.create(
        name=MACVLAN_NETWORK_NAME,
        driver="macvlan",
        options={"parent": interface},
        ipam=docker.types.IPAMConfig(
            driver="default",
            pool_configs=[
                docker.types.IPAMPool(
                    subnet=subnet,
                    gateway=gateway,
                    iprange=ip_range,
                )
            ],
        ),
    )


def create_ipvlan_network(
    client: docker.DockerClient,
    interface: str,
    subnet: str,
    gateway: str,
    ip_range: str,
) -> None:
    """Create an IPvlan L2 Docker network. No-op if it already exists."""
    existing = [n.name for n in client.networks.list()]
    if MACVLAN_NETWORK_NAME in existing:
        return

    client.networks.create(
        name=MACVLAN_NETWORK_NAME,
        driver="ipvlan",
        options={"parent": interface, "ipvlan_mode": "l2"},
        ipam=docker.types.IPAMConfig(
            driver="default",
            pool_configs=[
                docker.types.IPAMPool(
                    subnet=subnet,
                    gateway=gateway,
                    iprange=ip_range,
                )
            ],
        ),
    )


def remove_macvlan_network(client: docker.DockerClient) -> None:
    nets = [n for n in client.networks.list() if n.name == MACVLAN_NETWORK_NAME]
    for n in nets:
        n.remove()


# ---------------------------------------------------------------------------
# Host-side macvlan interface (hairpin fix)
# ---------------------------------------------------------------------------

def _require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError(
            "MACVLAN host-side interface setup requires root. Run with sudo."
        )


def setup_host_macvlan(interface: str, host_macvlan_ip: str, decky_ip_range: str) -> None:
    """
    Create a macvlan interface on the host so the deployer can reach deckies.
    Idempotent — skips steps that are already done.
    """
    _require_root()

    # Check if interface already exists
    result = _run(["ip", "link", "show", HOST_MACVLAN_IFACE], check=False)
    if result.returncode != 0:
        _run(["ip", "link", "add", HOST_MACVLAN_IFACE, "link", interface, "type", "macvlan", "mode", "bridge"])

    _run(["ip", "addr", "add", f"{host_macvlan_ip}/32", "dev", HOST_MACVLAN_IFACE], check=False)
    _run(["ip", "link", "set", HOST_MACVLAN_IFACE, "up"])
    _run(["ip", "route", "add", decky_ip_range, "dev", HOST_MACVLAN_IFACE], check=False)


def teardown_host_macvlan(decky_ip_range: str) -> None:
    _require_root()
    _run(["ip", "route", "del", decky_ip_range, "dev", HOST_MACVLAN_IFACE], check=False)
    _run(["ip", "link", "del", HOST_MACVLAN_IFACE], check=False)


def setup_host_ipvlan(interface: str, host_ipvlan_ip: str, decky_ip_range: str) -> None:
    """
    Create an IPvlan interface on the host so the deployer can reach deckies.
    Idempotent — skips steps that are already done.
    """
    _require_root()

    result = _run(["ip", "link", "show", HOST_IPVLAN_IFACE], check=False)
    if result.returncode != 0:
        _run(["ip", "link", "add", HOST_IPVLAN_IFACE, "link", interface, "type", "ipvlan", "mode", "l2"])

    _run(["ip", "addr", "add", f"{host_ipvlan_ip}/32", "dev", HOST_IPVLAN_IFACE], check=False)
    _run(["ip", "link", "set", HOST_IPVLAN_IFACE, "up"])
    _run(["ip", "route", "add", decky_ip_range, "dev", HOST_IPVLAN_IFACE], check=False)


def teardown_host_ipvlan(decky_ip_range: str) -> None:
    _require_root()
    _run(["ip", "route", "del", decky_ip_range, "dev", HOST_IPVLAN_IFACE], check=False)
    _run(["ip", "link", "del", HOST_IPVLAN_IFACE], check=False)


# ---------------------------------------------------------------------------
# Compute an ip_range CIDR that covers a list of IPs
# ---------------------------------------------------------------------------

def ips_to_range(ips: list[str]) -> str:
    """
    Given a list of IPs, return the tightest /N CIDR that covers them all.
    Used as the --ip-range for MACVLAN so Docker assigns exactly those IPs.
    """
    addrs = [IPv4Address(ip) for ip in ips]
    network = IPv4Network(
        (int(min(addrs)), 32 - (int(max(addrs)) ^ int(min(addrs))).bit_length()),
        strict=False,
    )
    return str(network)
