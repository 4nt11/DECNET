"""
Tests for the OS TCP/IP fingerprint spoof feature.

Covers:
  - os_fingerprint.py: profiles, TTL values, fallback behaviour
  - archetypes.py: every archetype has a valid nmap_os
  - config.py: DeckyConfig carries nmap_os
  - composer.py: base container gets sysctls + cap_add injected
  - cli.py helpers: nmap_os propagated from archetype → DeckyConfig
"""

import pytest

from decnet.archetypes import ARCHETYPES, all_archetypes
from decnet.composer import generate_compose
from decnet.config import DeckyConfig, DecnetConfig
from decnet.os_fingerprint import OS_SYSCTLS, all_os_families, get_os_sysctls


# ---------------------------------------------------------------------------
# os_fingerprint module
# ---------------------------------------------------------------------------

def test_linux_ttl_is_64():
    assert get_os_sysctls("linux")["net.ipv4.ip_default_ttl"] == "64"


def test_windows_ttl_is_128():
    assert get_os_sysctls("windows")["net.ipv4.ip_default_ttl"] == "128"


def test_embedded_ttl_is_255():
    assert get_os_sysctls("embedded")["net.ipv4.ip_default_ttl"] == "255"


def test_cisco_ttl_is_255():
    assert get_os_sysctls("cisco")["net.ipv4.ip_default_ttl"] == "255"


def test_bsd_ttl_is_64():
    assert get_os_sysctls("bsd")["net.ipv4.ip_default_ttl"] == "64"


def test_unknown_os_falls_back_to_linux():
    result = get_os_sysctls("nonexistent-os")
    assert result == get_os_sysctls("linux")


def test_get_os_sysctls_returns_copy():
    """Mutating the returned dict must not alter the master profile."""
    s = get_os_sysctls("windows")
    s["net.ipv4.ip_default_ttl"] = "999"
    assert OS_SYSCTLS["windows"]["net.ipv4.ip_default_ttl"] == "128"


def test_all_os_families_non_empty():
    families = all_os_families()
    assert len(families) > 0
    assert "linux" in families
    assert "windows" in families
    assert "embedded" in families


# ---------------------------------------------------------------------------
# Archetypes carry valid nmap_os values
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("slug,arch", list(ARCHETYPES.items()))
def test_archetype_nmap_os_is_known(slug, arch):
    assert arch.nmap_os in all_os_families(), (
        f"Archetype '{slug}' has nmap_os='{arch.nmap_os}' which is not in OS_SYSCTLS"
    )


@pytest.mark.parametrize("slug", ["windows-workstation", "windows-server", "domain-controller"])
def test_windows_archetypes_have_windows_nmap_os(slug):
    assert ARCHETYPES[slug].nmap_os == "windows"


@pytest.mark.parametrize("slug", ["printer", "iot-device", "industrial-control"])
def test_embedded_archetypes_have_embedded_nmap_os(slug):
    assert ARCHETYPES[slug].nmap_os == "embedded"


@pytest.mark.parametrize("slug", ["linux-server", "web-server", "database-server",
                                   "mail-server", "file-server", "voip-server",
                                   "monitoring-node", "devops-host"])
def test_linux_archetypes_have_linux_nmap_os(slug):
    assert ARCHETYPES[slug].nmap_os == "linux"


# ---------------------------------------------------------------------------
# DeckyConfig default
# ---------------------------------------------------------------------------

def _make_decky(nmap_os: str = "linux") -> DeckyConfig:
    return DeckyConfig(
        name="decky-01",
        ip="10.0.0.10",
        services=["ssh"],
        distro="debian",
        base_image="debian:bookworm-slim",
        build_base="debian:bookworm-slim",
        hostname="test-host",
        nmap_os=nmap_os,
    )


def test_deckyconfig_default_nmap_os_is_linux():
    cfg = DeckyConfig(
        name="decky-01",
        ip="10.0.0.10",
        services=["ssh"],
        distro="debian",
        base_image="debian:bookworm-slim",
        build_base="debian:bookworm-slim",
        hostname="test-host",
    )
    assert cfg.nmap_os == "linux"


def test_deckyconfig_accepts_custom_nmap_os():
    cfg = _make_decky(nmap_os="windows")
    assert cfg.nmap_os == "windows"


# ---------------------------------------------------------------------------
# Composer injects sysctls + cap_add into base container
# ---------------------------------------------------------------------------

def _make_config(nmap_os: str = "linux") -> DecnetConfig:
    return DecnetConfig(
        mode="unihost",
        interface="eth0",
        subnet="10.0.0.0/24",
        gateway="10.0.0.1",
        deckies=[_make_decky(nmap_os=nmap_os)],
    )


def test_compose_base_has_sysctls():
    compose = generate_compose(_make_config("linux"))
    base = compose["services"]["decky-01"]
    assert "sysctls" in base


def test_compose_base_has_cap_net_admin():
    compose = generate_compose(_make_config("linux"))
    base = compose["services"]["decky-01"]
    assert "cap_add" in base
    assert "NET_ADMIN" in base["cap_add"]


def test_compose_linux_ttl_64():
    compose = generate_compose(_make_config("linux"))
    sysctls = compose["services"]["decky-01"]["sysctls"]
    assert sysctls["net.ipv4.ip_default_ttl"] == "64"


def test_compose_windows_ttl_128():
    compose = generate_compose(_make_config("windows"))
    sysctls = compose["services"]["decky-01"]["sysctls"]
    assert sysctls["net.ipv4.ip_default_ttl"] == "128"


def test_compose_embedded_ttl_255():
    compose = generate_compose(_make_config("embedded"))
    sysctls = compose["services"]["decky-01"]["sysctls"]
    assert sysctls["net.ipv4.ip_default_ttl"] == "255"


def test_compose_service_containers_have_no_sysctls():
    """Service containers share the base network namespace — no sysctls needed there."""
    compose = generate_compose(_make_config("windows"))
    svc = compose["services"]["decky-01-ssh"]
    assert "sysctls" not in svc


def test_compose_two_deckies_independent_nmap_os():
    """Each decky gets its own OS profile."""
    decky_win = _make_decky(nmap_os="windows")
    decky_lin = DeckyConfig(
        name="decky-02",
        ip="10.0.0.11",
        services=["ssh"],
        distro="debian",
        base_image="debian:bookworm-slim",
        build_base="debian:bookworm-slim",
        hostname="test-host-2",
        nmap_os="linux",
    )
    config = DecnetConfig(
        mode="unihost",
        interface="eth0",
        subnet="10.0.0.0/24",
        gateway="10.0.0.1",
        deckies=[decky_win, decky_lin],
    )
    compose = generate_compose(config)
    assert compose["services"]["decky-01"]["sysctls"]["net.ipv4.ip_default_ttl"] == "128"
    assert compose["services"]["decky-02"]["sysctls"]["net.ipv4.ip_default_ttl"] == "64"


# ---------------------------------------------------------------------------
# CLI helper: nmap_os flows from archetype into DeckyConfig
# ---------------------------------------------------------------------------

def test_build_deckies_windows_archetype_sets_nmap_os():
    from decnet.archetypes import get_archetype
    from decnet.cli import _build_deckies

    arch = get_archetype("windows-workstation")
    deckies = _build_deckies(
        n=1,
        ips=["10.0.0.20"],
        services_explicit=None,
        randomize_services=False,
        archetype=arch,
    )
    assert deckies[0].nmap_os == "windows"


def test_build_deckies_no_archetype_defaults_linux():
    from decnet.cli import _build_deckies

    deckies = _build_deckies(
        n=1,
        ips=["10.0.0.20"],
        services_explicit=["ssh"],
        randomize_services=False,
        archetype=None,
    )
    assert deckies[0].nmap_os == "linux"


def test_build_deckies_embedded_archetype_sets_nmap_os():
    from decnet.archetypes import get_archetype
    from decnet.cli import _build_deckies

    arch = get_archetype("iot-device")
    deckies = _build_deckies(
        n=1,
        ips=["10.0.0.20"],
        services_explicit=None,
        randomize_services=False,
        archetype=arch,
    )
    assert deckies[0].nmap_os == "embedded"
