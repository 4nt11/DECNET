"""
Tests for decnet/fleet.py — fleet builder logic.

Covers build_deckies, build_deckies_from_ini, resolve_distros,
and edge cases like IP exhaustion and missing services.
"""

import pytest

from decnet.archetypes import get_archetype
from decnet.fleet import (
    build_deckies,
    build_deckies_from_ini,
    resolve_distros,
)
from decnet.ini_loader import IniConfig, DeckySpec


# ── resolve_distros ───────────────────────────────────────────────────────────

class TestResolveDistros:
    def test_explicit_distros_cycled(self):
        result = resolve_distros(["debian", "ubuntu22"], False, 5)
        assert result == ["debian", "ubuntu22", "debian", "ubuntu22", "debian"]

    def test_explicit_single_distro(self):
        result = resolve_distros(["rocky9"], False, 3)
        assert result == ["rocky9", "rocky9", "rocky9"]

    def test_randomize_returns_correct_count(self):
        result = resolve_distros(None, True, 4)
        assert len(result) == 4
        # All returned slugs should be valid distro slugs
        from decnet.distros import all_distros
        valid = set(all_distros().keys())
        for slug in result:
            assert slug in valid

    def test_archetype_preferred_distros(self):
        arch = get_archetype("deaddeck")
        result = resolve_distros(None, False, 3, archetype=arch)
        for slug in result:
            assert slug in arch.preferred_distros

    def test_fallback_cycles_all_distros(self):
        result = resolve_distros(None, False, 2)
        from decnet.distros import all_distros
        slugs = list(all_distros().keys())
        assert result[0] == slugs[0]
        assert result[1] == slugs[1]


# ── build_deckies ─────────────────────────────────────────────────────────────

class TestBuildDeckies:
    _IPS: list[str] = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]

    def test_explicit_services(self):
        deckies = build_deckies(3, self._IPS, ["ssh", "http"], False)
        assert len(deckies) == 3
        for decky in deckies:
            assert decky.services == ["ssh", "http"]

    def test_archetype_services(self):
        arch = get_archetype("deaddeck")
        deckies = build_deckies(2, self._IPS[:2], None, False, archetype=arch)
        assert len(deckies) == 2
        for decky in deckies:
            assert set(decky.services) == set(arch.services)
            assert decky.archetype == "deaddeck"
            assert decky.nmap_os == arch.nmap_os

    def test_randomize_services(self):
        deckies = build_deckies(3, self._IPS, None, True)
        assert len(deckies) == 3
        for decky in deckies:
            assert len(decky.services) >= 1

    def test_no_services_raises(self):
        with pytest.raises(ValueError, match="Provide services_explicit"):
            build_deckies(1, self._IPS[:1], None, False)

    def test_names_sequential(self):
        deckies = build_deckies(3, self._IPS, ["ssh"], False)
        assert [d.name for d in deckies] == ["decky-01", "decky-02", "decky-03"]

    def test_ips_assigned_correctly(self):
        deckies = build_deckies(3, self._IPS, ["ssh"], False)
        assert [d.ip for d in deckies] == self._IPS

    def test_mutate_interval_propagated(self):
        deckies = build_deckies(1, self._IPS[:1], ["ssh"], False, mutate_interval=15)
        assert deckies[0].mutate_interval == 15

    def test_distros_explicit(self):
        deckies = build_deckies(2, self._IPS[:2], ["ssh"], False, distros_explicit=["rocky9"])
        for decky in deckies:
            assert decky.distro == "rocky9"

    def test_randomize_distros(self):
        deckies = build_deckies(2, self._IPS[:2], ["ssh"], False, randomize_distros=True)
        from decnet.distros import all_distros
        valid = set(all_distros().keys())
        for decky in deckies:
            assert decky.distro in valid


# ── build_deckies_from_ini ────────────────────────────────────────────────────

class TestBuildDeckiesFromIni:
    _SUBNET: str = "192.168.1.0/24"
    _GATEWAY: str = "192.168.1.1"
    _HOST_IP: str = "192.168.1.2"

    def _make_ini(self, deckies: list[DeckySpec], **kwargs) -> IniConfig:
        defaults: dict = {
            "interface": "eth0",
            "subnet": None,
            "gateway": None,
            "mutate_interval": None,
            "custom_services": [],
        }
        defaults.update(kwargs)
        return IniConfig(deckies=deckies, **defaults)

    def test_explicit_ip(self):
        spec = DeckySpec(name="test-1", ip="192.168.1.50", services=["ssh"])
        ini = self._make_ini([spec])
        deckies = build_deckies_from_ini(ini, self._SUBNET, self._GATEWAY, self._HOST_IP, False)
        assert len(deckies) == 1
        assert deckies[0].ip == "192.168.1.50"

    def test_auto_ip_allocation(self):
        spec = DeckySpec(name="test-1", services=["ssh"])
        ini = self._make_ini([spec])
        deckies = build_deckies_from_ini(ini, self._SUBNET, self._GATEWAY, self._HOST_IP, False)
        assert len(deckies) == 1
        assert deckies[0].ip not in (self._GATEWAY, self._HOST_IP, "192.168.1.0", "192.168.1.255")

    def test_archetype_services(self):
        spec = DeckySpec(name="test-1", archetype="deaddeck")
        ini = self._make_ini([spec])
        deckies = build_deckies_from_ini(ini, self._SUBNET, self._GATEWAY, self._HOST_IP, False)
        arch = get_archetype("deaddeck")
        assert set(deckies[0].services) == set(arch.services)

    def test_randomize_services(self):
        spec = DeckySpec(name="test-1")
        ini = self._make_ini([spec])
        deckies = build_deckies_from_ini(ini, self._SUBNET, self._GATEWAY, self._HOST_IP, True)
        assert len(deckies[0].services) >= 1

    def test_no_services_no_arch_auto_randomizes(self):
        spec = DeckySpec(name="test-1")
        ini = self._make_ini([spec])
        deckies = build_deckies_from_ini(ini, self._SUBNET, self._GATEWAY, self._HOST_IP, False)
        assert len(deckies[0].services) >= 1

    def test_unknown_service_raises(self):
        spec = DeckySpec(name="test-1", services=["nonexistent_svc_xyz"])
        ini = self._make_ini([spec])
        with pytest.raises(ValueError, match="Unknown service"):
            build_deckies_from_ini(ini, self._SUBNET, self._GATEWAY, self._HOST_IP, False)

    def test_mutate_interval_from_cli(self):
        spec = DeckySpec(name="test-1", services=["ssh"])
        ini = self._make_ini([spec])
        deckies = build_deckies_from_ini(
            ini, self._SUBNET, self._GATEWAY, self._HOST_IP, False, cli_mutate_interval=42
        )
        assert deckies[0].mutate_interval == 42

    def test_mutate_interval_from_ini(self):
        spec = DeckySpec(name="test-1", services=["ssh"])
        ini = self._make_ini([spec], mutate_interval=99)
        deckies = build_deckies_from_ini(
            ini, self._SUBNET, self._GATEWAY, self._HOST_IP, False, cli_mutate_interval=None
        )
        assert deckies[0].mutate_interval == 99

    def test_nmap_os_from_spec(self):
        spec = DeckySpec(name="test-1", services=["ssh"], nmap_os="windows")
        ini = self._make_ini([spec])
        deckies = build_deckies_from_ini(ini, self._SUBNET, self._GATEWAY, self._HOST_IP, False)
        assert deckies[0].nmap_os == "windows"

    def test_nmap_os_from_archetype(self):
        spec = DeckySpec(name="test-1", archetype="deaddeck")
        ini = self._make_ini([spec])
        deckies = build_deckies_from_ini(ini, self._SUBNET, self._GATEWAY, self._HOST_IP, False)
        assert deckies[0].nmap_os == "linux"
