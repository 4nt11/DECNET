# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Tests for wiring the cloak into the deploy path:
  - composer.py: windows* base containers get build+command+caps+env; non-mangled
    bases stay byte-for-byte unchanged.
  - composer._decky_open_tcp_ports: service-port enumeration.
  - deployer._sync_cloak_sources: ships the decnet subtree only when needed.
"""
from __future__ import annotations

import pytest

from decnet.composer import _CLOAK_COMMAND, _decky_open_tcp_ports, generate_compose
from decnet.config import DeckyConfig, DecnetConfig


def _decky(nmap_os: str = "linux", services: list[str] | None = None) -> DeckyConfig:
    return DeckyConfig(
        name="decky-01",
        ip="10.0.0.10",
        services=services or ["ssh"],
        distro="debian",
        base_image="debian:bookworm-slim",
        build_base="debian:bookworm-slim",
        hostname="test-host",
        nmap_os=nmap_os,
    )


def _config(decky: DeckyConfig) -> DecnetConfig:
    return DecnetConfig(
        mode="unihost", interface="eth0", subnet="10.0.0.0/24",
        gateway="10.0.0.1", deckies=[decky],
    )


def _base(nmap_os: str, services: list[str] | None = None) -> dict:
    return generate_compose(_config(_decky(nmap_os, services)))["services"]["decky-01"]


# ── port enumeration ────────────────────────────────────────────────────────

def test_open_ports_union_sorted_deduped():
    # smb=[445,139], rdp=[3389]
    assert _decky_open_tcp_ports(["smb", "rdp"]) == [139, 445, 3389]


def test_open_ports_single_and_multiport():
    assert _decky_open_tcp_ports(["ssh"]) == [22]
    assert _decky_open_tcp_ports(["imap"]) == [143, 993]  # multi-port service


# ── non-mangled base is unchanged ───────────────────────────────────────────

def test_linux_base_uses_stock_image_and_sleep():
    base = _base("linux")
    assert base["image"] == "debian:bookworm-slim"
    assert base["command"] == ["sleep", "infinity"]
    assert "build" not in base
    assert "environment" not in base
    assert base["cap_add"] == ["NET_ADMIN"]


@pytest.mark.parametrize("fam", ["embedded", "bsd", "cisco"])
def test_other_families_not_cloaked(fam):
    base = _base(fam)
    assert "build" not in base
    assert base["command"] == ["sleep", "infinity"]
    assert "NET_RAW" not in base["cap_add"]


# ── windows* base gets the cloak ────────────────────────────────────────────

@pytest.mark.parametrize("fam", ["windows", "windows_server"])
def test_windows_base_is_built_cloak_image(fam):
    base = _base(fam, services=["smb", "rdp"])
    assert "image" not in base
    assert base["build"]["args"]["BASE_IMAGE"] == "debian:bookworm-slim"
    assert base["build"]["context"].endswith("templates/_shared/cloak")


@pytest.mark.parametrize("fam", ["windows", "windows_server"])
def test_windows_base_runs_cloak_netns_safe(fam):
    base = _base(fam)
    # supervisor keeps sleep infinity as PID1 so a cloak crash can't kill the netns
    assert base["command"] == _CLOAK_COMMAND
    assert "decnet.cloak" in base["command"][-1]
    assert "sleep infinity" in base["command"][-1]


@pytest.mark.parametrize("fam", ["windows", "windows_server"])
def test_windows_base_caps_include_net_raw(fam):
    base = _base(fam)
    assert "NET_ADMIN" in base["cap_add"]
    assert "NET_RAW" in base["cap_add"]


def test_windows_base_env_carries_profile_and_ports():
    base = _base("windows_server", services=["smb", "rdp"])
    env = base["environment"]
    assert env["DECNET_NMAP_OS"] == "windows_server"
    assert env["DECNET_OPEN_PORTS"] == "139,445,3389"
    assert env["DECKY_IP"] == "10.0.0.10"


def test_windows_base_still_has_sysctls():
    base = _base("windows")
    assert base["sysctls"]["net.ipv4.ip_default_ttl"] == "128"
    assert base["sysctls"]["net.ipv4.tcp_timestamps"] == "1"


# ── deployer sync gating ────────────────────────────────────────────────────

def test_sync_cloak_ships_subtree_only_when_needed(tmp_path, monkeypatch):
    from decnet.engine import deployer

    dest_root = tmp_path / "cloak"
    monkeypatch.setattr(deployer, "_CANONICAL_CLOAK_DIR", dest_root)

    # linux-only → no-op
    deployer._sync_cloak_sources(_config(_decky("linux")))
    assert not (dest_root / "decnet").exists()

    # windows → ships the subtree, package structure preserved
    deployer._sync_cloak_sources(_config(_decky("windows")))
    shipped = dest_root / "decnet"
    assert (shipped / "__init__.py").is_file()
    assert (shipped / "os_fingerprint.py").is_file()
    assert (shipped / "cloak" / "mangler.py").is_file()
    assert (shipped / "logging" / "__init__.py").is_file()
