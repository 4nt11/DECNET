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

def _ensure_network(
    client: docker.DockerClient,
    *,
    driver: str,
    interface: str,
    subnet: str,
    gateway: str,
    ip_range: str,
    extra_options: dict | None = None,
) -> None:
    """Create the decnet docker network with ``driver``, replacing any
    existing network of the same name that was built with a different driver.

    Why the replace-on-driver-mismatch: macvlan and ipvlan slaves can't
    coexist on the same parent interface. If an earlier run left behind a
    macvlan-driver network and we're now asked for ipvlan (or vice versa),
    short-circuiting on name alone leaves Docker attaching new containers
    to the old driver and the host NIC ends up EBUSY on the next port
    create. So: when driver disagrees, disconnect everything and DROP it.
    """
    options = {"parent": interface}
    if extra_options:
        options.update(extra_options)

    for net in client.networks.list(names=[MACVLAN_NETWORK_NAME]):
        # networks.list() doesn't populate Containers — reload to get the
        # full inspect payload (including connected container IDs).
        try:
            net.reload()
        except docker.errors.APIError:
            pass

        if net.attrs.get("Driver") == driver:
            # Same driver — but if the IPAM pool drifted (different subnet,
            # gateway, or ip-range than this deploy asks for), reusing it
            # hands out addresses from the old pool and we race the real LAN.
            # Compare and rebuild on mismatch — but only when no containers
            # are attached. With active endpoints Docker refuses the remove
            # with 403; just attach to the existing network instead.
            pools = (net.attrs.get("IPAM") or {}).get("Config") or []
            cur = pools[0] if pools else {}
            if (
                cur.get("Subnet") == subnet
                and cur.get("Gateway") == gateway
                and cur.get("IPRange") == ip_range
            ):
                return  # right driver AND matching pool, leave it alone
            if net.attrs.get("Containers"):
                # Active endpoints — can't safely rebuild. Attach to the
                # existing network; IPAM drift on ip_range only affects
                # Docker's auto-assign pool, which DECNET doesn't use
                # (IPs are always set explicitly in the compose file).
                return
        # Driver mismatch OR empty-endpoint IPAM drift — tear it down.
        # Disconnect any live containers first so `remove()` doesn't
        # refuse with ErrNetworkInUse.
        for cid in (net.attrs.get("Containers") or {}):
            try:
                net.disconnect(cid, force=True)
            except docker.errors.APIError:
                pass
        net.remove()

    client.networks.create(
        name=MACVLAN_NETWORK_NAME,
        driver=driver,
        options=options,
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


def create_macvlan_network(
    client: docker.DockerClient,
    interface: str,
    subnet: str,
    gateway: str,
    ip_range: str,
) -> None:
    """Create the MACVLAN Docker network, replacing an ipvlan-driver one of
    the same name if necessary (parent-NIC can't host both drivers)."""
    _ensure_network(
        client, driver="macvlan", interface=interface,
        subnet=subnet, gateway=gateway, ip_range=ip_range,
    )


def create_ipvlan_network(
    client: docker.DockerClient,
    interface: str,
    subnet: str,
    gateway: str,
    ip_range: str,
) -> None:
    """Create an IPvlan L2 Docker network, replacing a macvlan-driver one of
    the same name if necessary (parent-NIC can't host both drivers)."""
    _ensure_network(
        client, driver="ipvlan", interface=interface,
        subnet=subnet, gateway=gateway, ip_range=ip_range,
        extra_options={"ipvlan_mode": "l2"},
    )


def remove_macvlan_network(client: docker.DockerClient) -> None:
    nets = [n for n in client.networks.list() if n.name == MACVLAN_NETWORK_NAME]
    for n in nets:
        n.remove()


# ---------------------------------------------------------------------------
# Plain Docker bridge networks (MazeNET topologies — one per LAN)
# ---------------------------------------------------------------------------

def create_bridge_network(
    client: docker.DockerClient,
    name: str,
    subnet: str,
    *,
    internal: bool = False,
) -> str:
    """Create (or reuse) a plain Docker bridge network and return its id.

    ``internal=True`` blocks outbound routing via the host — used for
    non-DMZ MazeNET LANs so deckies can only reach what the bridge
    deckies let them reach.
    """
    for net in client.networks.list(names=[name]):
        pools = (net.attrs.get("IPAM") or {}).get("Config") or []
        cur = pools[0] if pools else {}
        if net.attrs.get("Driver") == "bridge" and cur.get("Subnet") == subnet:
            return net.id
        for cid in (net.attrs.get("Containers") or {}):
            try:
                net.disconnect(cid, force=True)
            except docker.errors.APIError:
                pass
        net.remove()

    # Orphaned networks from a prior half-torn-down topology can still
    # claim the subnet under a different name — Docker then rejects our
    # create with "Pool overlaps".  Sweep any unused bridge that sits on
    # the same subnet and owns no running containers.
    for net in client.networks.list(filters={"driver": "bridge"}):
        if net.name == name:
            continue
        pools = (net.attrs.get("IPAM") or {}).get("Config") or []
        cur = pools[0] if pools else {}
        if cur.get("Subnet") != subnet:
            continue
        if net.attrs.get("Containers"):
            continue
        try:
            net.remove()
        except docker.errors.APIError:
            pass

    net = client.networks.create(
        name=name,
        driver="bridge",
        internal=internal,
        ipam=docker.types.IPAMConfig(
            driver="default",
            pool_configs=[docker.types.IPAMPool(subnet=subnet)],
        ),
    )
    return net.id


def remove_bridge_network(client: docker.DockerClient, name: str) -> None:
    for net in client.networks.list(names=[name]):
        for cid in (net.attrs.get("Containers") or {}):
            try:
                net.disconnect(cid, force=True)
            except docker.errors.APIError:
                pass
        try:
            net.remove()
        except docker.errors.APIError:
            pass


# ---------------------------------------------------------------------------
# Host-side macvlan interface (hairpin fix)
# ---------------------------------------------------------------------------

# Linux capability bit positions — see capabilities(7).
_CAP_NET_ADMIN = 12


def _has_cap_net_admin() -> bool:
    """True if the current process holds CAP_NET_ADMIN in its effective set.

    Reads ``/proc/self/status`` rather than calling ``capget(2)`` so we
    don't need a libcap dependency.  ``CapEff`` is a 64-bit hex bitmask;
    bit 12 is CAP_NET_ADMIN.
    """
    try:
        with open("/proc/self/status", "r") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    bits = int(line.split()[1], 16)
                    return bool(bits & (1 << _CAP_NET_ADMIN))
    except OSError:
        pass
    return False


def _require_net_admin() -> None:
    """Reject early if the process can't run ``ip link add ... macvlan``.

    CAP_NET_ADMIN is what the kernel actually checks for netlink RTM_NEWLINK
    of a macvlan/ipvlan slave; euid==0 is sufficient (it grants every cap)
    but not necessary.  Prefer the cap check so the systemd unit's
    ``AmbientCapabilities=CAP_NET_ADMIN`` is honoured without forcing the
    whole API to run as root.
    """
    if os.geteuid() == 0 or _has_cap_net_admin():
        return
    raise PermissionError(
        "MACVLAN host-side interface setup needs CAP_NET_ADMIN. "
        "Either run as root or grant the cap (systemd: "
        "AmbientCapabilities=CAP_NET_ADMIN)."
    )


def setup_host_macvlan(interface: str, host_macvlan_ip: str, decky_ip_range: str) -> None:
    """
    Create a macvlan interface on the host so the deployer can reach deckies.
    Idempotent — skips steps that are already done. Drops a stale ipvlan
    host-helper first: the two drivers can share a parent NIC on paper but
    leaving the opposite helper in place is just cruft after a driver swap.
    """
    _require_net_admin()

    _run(["ip", "link", "del", HOST_IPVLAN_IFACE], check=False)

    _run(["ip", "link", "del", HOST_IPVLAN_IFACE], check=False)

    # Check if interface already exists
    result = _run(["ip", "link", "show", HOST_MACVLAN_IFACE], check=False)
    if result.returncode != 0:
        _run(["ip", "link", "add", HOST_MACVLAN_IFACE, "link", interface, "type", "macvlan", "mode", "bridge"])

    _run(["ip", "addr", "add", f"{host_macvlan_ip}/32", "dev", HOST_MACVLAN_IFACE], check=False)
    _run(["ip", "link", "set", HOST_MACVLAN_IFACE, "up"])
    _run(["ip", "route", "add", decky_ip_range, "dev", HOST_MACVLAN_IFACE], check=False)


def teardown_host_macvlan(decky_ip_range: str) -> None:
    _require_net_admin()
    _run(["ip", "route", "del", decky_ip_range, "dev", HOST_MACVLAN_IFACE], check=False)
    _run(["ip", "link", "del", HOST_MACVLAN_IFACE], check=False)


def setup_host_ipvlan(interface: str, host_ipvlan_ip: str, decky_ip_range: str) -> None:
    """
    Create an IPvlan interface on the host so the deployer can reach deckies.
    Idempotent — skips steps that are already done. Drops a stale macvlan
    host-helper first so a prior macvlan deploy doesn't leave its slave
    dangling on the parent NIC after the driver swap.
    """
    _require_net_admin()

    _run(["ip", "link", "del", HOST_MACVLAN_IFACE], check=False)

    _run(["ip", "link", "del", HOST_MACVLAN_IFACE], check=False)

    result = _run(["ip", "link", "show", HOST_IPVLAN_IFACE], check=False)
    if result.returncode != 0:
        _run(["ip", "link", "add", HOST_IPVLAN_IFACE, "link", interface, "type", "ipvlan", "mode", "l2"])

    _run(["ip", "addr", "add", f"{host_ipvlan_ip}/32", "dev", HOST_IPVLAN_IFACE], check=False)
    _run(["ip", "link", "set", HOST_IPVLAN_IFACE, "up"])
    _run(["ip", "route", "add", decky_ip_range, "dev", HOST_IPVLAN_IFACE], check=False)


def teardown_host_ipvlan(decky_ip_range: str) -> None:
    _require_net_admin()
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


# ---------------------------------------------------------------------------
# Container veth resolution (for tc netem tarpit)
# ---------------------------------------------------------------------------

def get_container_pid(container_name: str) -> int:
    """Return the PID of a running container's init process."""
    client = docker.from_env()
    try:
        container = client.containers.get(container_name)
    except docker.errors.NotFound:
        raise LookupError(f"container {container_name!r} not found")
    pid = container.attrs["State"]["Pid"]
    if not pid:
        raise LookupError(f"container {container_name!r} is not running (PID=0)")
    return pid


def get_container_veth(container_name: str) -> str:
    """Return the host veth interface name paired to container_name's eth0.

    Reads /sys/class/net/eth0/iflink from inside the container to get the
    peer interface index, then matches it against ``ip link show`` on the host.
    Requires no nsenter and no elevated privileges beyond what Docker exec grants.
    """
    result = _run(
        ["docker", "exec", container_name, "cat", "/sys/class/net/eth0/iflink"],
        check=False,
    )
    if result.returncode != 0:
        raise LookupError(
            f"container {container_name!r} not reachable: {result.stderr.strip()}"
        )
    peer_index = result.stdout.strip()
    links = _run(["ip", "link", "show"])
    for line in links.stdout.splitlines():
        if line.startswith(f"{peer_index}:"):
            # Format: "42: veth3a4b5c@if41: <BROADCAST,...>"
            iface = line.split(":")[1].strip().split("@")[0]
            return iface
    raise LookupError(
        f"no host veth found for container {container_name!r} (peer ifindex {peer_index})"
    )
