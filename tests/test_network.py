"""
Tests for decnet.network utility functions.
"""

from unittest.mock import MagicMock, patch

import pytest

from decnet.network import (
    HOST_IPVLAN_IFACE,
    HOST_MACVLAN_IFACE,
    MACVLAN_NETWORK_NAME,
    allocate_ips,
    create_ipvlan_network,
    create_macvlan_network,
    detect_interface,
    detect_subnet,
    get_host_ip,
    ips_to_range,
    remove_macvlan_network,
    setup_host_ipvlan,
    setup_host_macvlan,
    teardown_host_ipvlan,
    teardown_host_macvlan,
)


# ---------------------------------------------------------------------------
# ips_to_range
# ---------------------------------------------------------------------------

class TestIpsToRange:
    def test_single_ip(self):
        assert ips_to_range(["192.168.1.100"]) == "192.168.1.100/32"

    def test_consecutive_small_range(self):
        # .97–.101: max^min = 4, bit_length=3, prefix=29 → .96/29
        result = ips_to_range([f"192.168.1.{i}" for i in range(97, 102)])
        from ipaddress import IPv4Network, IPv4Address
        net = IPv4Network(result)
        for i in range(97, 102):
            assert IPv4Address(f"192.168.1.{i}") in net

    def test_range_crossing_cidr_boundary(self):
        # .110–.119 crosses the /28 boundary (.96–.111 vs .112–.127)
        # Subtraction gives /28 (wrong), XOR gives /27 (correct)
        ips = [f"192.168.1.{i}" for i in range(110, 120)]
        result = ips_to_range(ips)
        from ipaddress import IPv4Network, IPv4Address
        net = IPv4Network(result)
        for i in range(110, 120):
            assert IPv4Address(f"192.168.1.{i}") in net, (
                f"192.168.1.{i} not in computed range {result}"
            )

    def test_all_ips_covered(self):
        # Larger spread: .10–.200
        ips = [f"10.0.0.{i}" for i in range(10, 201)]
        result = ips_to_range(ips)
        from ipaddress import IPv4Network, IPv4Address
        net = IPv4Network(result)
        for i in range(10, 201):
            assert IPv4Address(f"10.0.0.{i}") in net

    def test_two_ips_same_cidr(self):
        # .100 and .101 share /31
        result = ips_to_range(["192.168.1.100", "192.168.1.101"])
        from ipaddress import IPv4Network, IPv4Address
        net = IPv4Network(result)
        assert IPv4Address("192.168.1.100") in net
        assert IPv4Address("192.168.1.101") in net


# ---------------------------------------------------------------------------
# create_macvlan_network
# ---------------------------------------------------------------------------

class TestCreateMacvlanNetwork:
    def _make_client(self, existing=None):
        client = MagicMock()
        nets = [MagicMock(name=n) for n in (existing or [])]
        for net, n in zip(nets, (existing or [])):
            net.name = n
        client.networks.list.return_value = nets
        return client

    def test_creates_network_when_absent(self):
        client = self._make_client([])
        create_macvlan_network(client, "eth0", "192.168.1.0/24", "192.168.1.1", "192.168.1.96/27")
        client.networks.create.assert_called_once()
        kwargs = client.networks.create.call_args
        assert kwargs[1]["driver"] == "macvlan"
        assert kwargs[1]["name"] == MACVLAN_NETWORK_NAME
        assert kwargs[1]["options"]["parent"] == "eth0"

    def test_noop_when_network_exists(self):
        client = self._make_client([MACVLAN_NETWORK_NAME])
        create_macvlan_network(client, "eth0", "192.168.1.0/24", "192.168.1.1", "192.168.1.96/27")
        client.networks.create.assert_not_called()


# ---------------------------------------------------------------------------
# create_ipvlan_network
# ---------------------------------------------------------------------------

class TestCreateIpvlanNetwork:
    def _make_client(self, existing=None):
        client = MagicMock()
        nets = [MagicMock(name=n) for n in (existing or [])]
        for net, n in zip(nets, (existing or [])):
            net.name = n
        client.networks.list.return_value = nets
        return client

    def test_creates_ipvlan_network(self):
        client = self._make_client([])
        create_ipvlan_network(client, "wlan0", "192.168.1.0/24", "192.168.1.1", "192.168.1.96/27")
        client.networks.create.assert_called_once()
        kwargs = client.networks.create.call_args
        assert kwargs[1]["driver"] == "ipvlan"
        assert kwargs[1]["options"]["parent"] == "wlan0"
        assert kwargs[1]["options"]["ipvlan_mode"] == "l2"

    def test_noop_when_network_exists(self):
        client = self._make_client([MACVLAN_NETWORK_NAME])
        create_ipvlan_network(client, "wlan0", "192.168.1.0/24", "192.168.1.1", "192.168.1.96/27")
        client.networks.create.assert_not_called()

    def test_uses_same_network_name_as_macvlan(self):
        """Both drivers share the same logical network name so compose files are identical."""
        client = self._make_client([])
        create_ipvlan_network(client, "wlan0", "192.168.1.0/24", "192.168.1.1", "192.168.1.96/27")
        assert client.networks.create.call_args[1]["name"] == MACVLAN_NETWORK_NAME


# ---------------------------------------------------------------------------
# setup_host_macvlan / teardown_host_macvlan
# ---------------------------------------------------------------------------

class TestSetupHostMacvlan:
    @patch("decnet.network.os.geteuid", return_value=0)
    @patch("decnet.network._run")
    def test_creates_interface_when_absent(self, mock_run, _):
        # Simulate interface not existing (returncode != 0)
        mock_run.side_effect = lambda cmd, **kw: MagicMock(returncode=1) if "show" in cmd else MagicMock(returncode=0)
        setup_host_macvlan("eth0", "192.168.1.5", "192.168.1.96/27")
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("macvlan" in c for c in calls)
        assert any("mode" in c and "bridge" in c for c in calls)

    @patch("decnet.network.os.geteuid", return_value=0)
    @patch("decnet.network._run")
    def test_skips_create_when_interface_exists(self, mock_run, _):
        mock_run.return_value = MagicMock(returncode=0)
        setup_host_macvlan("eth0", "192.168.1.5", "192.168.1.96/27")
        calls = [c[0][0] for c in mock_run.call_args_list]
        # "ip link add <iface> link ..." should not be called when iface exists
        assert not any("link" in cmd and "add" in cmd and HOST_MACVLAN_IFACE in cmd for cmd in calls)

    @patch("decnet.network.os.geteuid", return_value=1)
    def test_requires_root(self, _):
        with pytest.raises(PermissionError):
            setup_host_macvlan("eth0", "192.168.1.5", "192.168.1.96/27")


# ---------------------------------------------------------------------------
# setup_host_ipvlan / teardown_host_ipvlan
# ---------------------------------------------------------------------------

class TestSetupHostIpvlan:
    @patch("decnet.network.os.geteuid", return_value=0)
    @patch("decnet.network._run")
    def test_creates_ipvlan_interface(self, mock_run, _):
        mock_run.side_effect = lambda cmd, **kw: MagicMock(returncode=1) if "show" in cmd else MagicMock(returncode=0)
        setup_host_ipvlan("wlan0", "192.168.1.5", "192.168.1.96/27")
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("ipvlan" in c for c in calls)
        assert any("mode" in c and "l2" in c for c in calls)

    @patch("decnet.network.os.geteuid", return_value=0)
    @patch("decnet.network._run")
    def test_uses_ipvlan_iface_name(self, mock_run, _):
        mock_run.side_effect = lambda cmd, **kw: MagicMock(returncode=1) if "show" in cmd else MagicMock(returncode=0)
        setup_host_ipvlan("wlan0", "192.168.1.5", "192.168.1.96/27")
        calls = [str(c) for c in mock_run.call_args_list]
        assert any(HOST_IPVLAN_IFACE in c for c in calls)
        assert not any(HOST_MACVLAN_IFACE in c for c in calls)

    @patch("decnet.network.os.geteuid", return_value=1)
    def test_requires_root(self, _):
        with pytest.raises(PermissionError):
            setup_host_ipvlan("wlan0", "192.168.1.5", "192.168.1.96/27")

    @patch("decnet.network.os.geteuid", return_value=0)
    @patch("decnet.network._run")
    def test_teardown_uses_ipvlan_iface(self, mock_run, _):
        mock_run.return_value = MagicMock(returncode=0)
        teardown_host_ipvlan("192.168.1.96/27")
        calls = [str(c) for c in mock_run.call_args_list]
        assert any(HOST_IPVLAN_IFACE in c for c in calls)
        assert not any(HOST_MACVLAN_IFACE in c for c in calls)


# ---------------------------------------------------------------------------
# allocate_ips (pure logic — no subprocess / Docker)
# ---------------------------------------------------------------------------

class TestAllocateIps:
    def test_basic_allocation(self):
        ips = allocate_ips("192.168.1.0/24", "192.168.1.1", "192.168.1.100", count=3)
        assert len(ips) == 3
        assert "192.168.1.1" not in ips   # gateway skipped
        assert "192.168.1.100" not in ips # host IP skipped

    def test_skips_network_and_broadcast(self):
        ips = allocate_ips("10.0.0.0/30", "10.0.0.1", "10.0.0.3", count=1)
        # /30 hosts: .1 (gateway), .2. .3 is host_ip → only .2 available
        assert ips == ["10.0.0.2"]

    def test_respects_ip_start(self):
        ips = allocate_ips("192.168.1.0/24", "192.168.1.1", "192.168.1.1",
                           count=2, ip_start="192.168.1.50")
        assert all(ip >= "192.168.1.50" for ip in ips)

    def test_raises_when_not_enough_ips(self):
        # /30 only has 2 host addresses; reserving both leaves 0
        with pytest.raises(RuntimeError, match="Not enough free IPs"):
            allocate_ips("10.0.0.0/30", "10.0.0.1", "10.0.0.2", count=3)

    def test_no_duplicates(self):
        ips = allocate_ips("10.0.0.0/24", "10.0.0.1", "10.0.0.2", count=10)
        assert len(ips) == len(set(ips))

    def test_exact_count_returned(self):
        ips = allocate_ips("172.16.0.0/24", "172.16.0.1", "172.16.0.254", count=5)
        assert len(ips) == 5


# ---------------------------------------------------------------------------
# detect_interface
# ---------------------------------------------------------------------------

class TestDetectInterface:
    @patch("decnet.network._run")
    def test_parses_dev_from_route(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="default via 192.168.1.1 dev eth0 proto dhcp\n"
        )
        assert detect_interface() == "eth0"

    @patch("decnet.network._run")
    def test_raises_when_no_dev_found(self, mock_run):
        mock_run.return_value = MagicMock(stdout="")
        with pytest.raises(RuntimeError, match="Could not auto-detect"):
            detect_interface()


# ---------------------------------------------------------------------------
# detect_subnet
# ---------------------------------------------------------------------------

class TestDetectSubnet:
    def _make_run(self, addr_output, route_output):
        def side_effect(cmd, **kwargs):
            if "addr" in cmd:
                return MagicMock(stdout=addr_output)
            return MagicMock(stdout=route_output)
        return side_effect

    @patch("decnet.network._run")
    def test_parses_subnet_and_gateway(self, mock_run):
        mock_run.side_effect = self._make_run(
            "    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth0\n",
            "default via 192.168.1.1 dev eth0\n",
        )
        subnet, gw = detect_subnet("eth0")
        assert subnet == "192.168.1.0/24"
        assert gw == "192.168.1.1"

    @patch("decnet.network._run")
    def test_raises_when_no_inet(self, mock_run):
        mock_run.side_effect = self._make_run("", "default via 192.168.1.1 dev eth0\n")
        with pytest.raises(RuntimeError, match="Could not detect subnet"):
            detect_subnet("eth0")

    @patch("decnet.network._run")
    def test_raises_when_no_gateway(self, mock_run):
        mock_run.side_effect = self._make_run(
            "    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth0\n", ""
        )
        with pytest.raises(RuntimeError, match="Could not detect gateway"):
            detect_subnet("eth0")


# ---------------------------------------------------------------------------
# get_host_ip
# ---------------------------------------------------------------------------

class TestGetHostIp:
    @patch("decnet.network._run")
    def test_returns_host_ip(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
        )
        assert get_host_ip("eth0") == "10.0.0.5"

    @patch("decnet.network._run")
    def test_raises_when_no_inet(self, mock_run):
        mock_run.return_value = MagicMock(stdout="link/ether aa:bb:cc:dd:ee:ff\n")
        with pytest.raises(RuntimeError, match="Could not determine host IP"):
            get_host_ip("eth0")


# ---------------------------------------------------------------------------
# remove_macvlan_network
# ---------------------------------------------------------------------------

class TestRemoveMacvlanNetwork:
    def test_removes_matching_network(self):
        client = MagicMock()
        net = MagicMock()
        net.name = MACVLAN_NETWORK_NAME
        client.networks.list.return_value = [net]
        remove_macvlan_network(client)
        net.remove.assert_called_once()

    def test_noop_when_no_matching_network(self):
        client = MagicMock()
        other = MagicMock()
        other.name = "some-other-network"
        client.networks.list.return_value = [other]
        remove_macvlan_network(client)
        other.remove.assert_not_called()


# ---------------------------------------------------------------------------
# teardown_host_macvlan
# ---------------------------------------------------------------------------

class TestTeardownHostMacvlan:
    @patch("decnet.network.os.geteuid", return_value=0)
    @patch("decnet.network._run")
    def test_deletes_macvlan_iface(self, mock_run, _):
        mock_run.return_value = MagicMock(returncode=0)
        teardown_host_macvlan("192.168.1.96/27")
        calls = [str(c) for c in mock_run.call_args_list]
        assert any(HOST_MACVLAN_IFACE in c for c in calls)

    @patch("decnet.network.os.geteuid", return_value=1)
    def test_requires_root(self, _):
        with pytest.raises(PermissionError):
            teardown_host_macvlan("192.168.1.96/27")
