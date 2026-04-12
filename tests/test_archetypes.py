"""
Tests for machine archetypes and the amount= expansion feature.
"""

from __future__ import annotations

import textwrap
import tempfile
import os
import pytest

from decnet.archetypes import (
    ARCHETYPES,
    all_archetypes,
    get_archetype,
    random_archetype,
)
from decnet.ini_loader import load_ini
from decnet.distros import DISTROS


# ---------------------------------------------------------------------------
# Archetype registry
# ---------------------------------------------------------------------------

def test_all_archetypes_returns_all():
    result = all_archetypes()
    assert isinstance(result, dict)
    assert len(result) == len(ARCHETYPES)


def test_get_archetype_known():
    arch = get_archetype("linux-server")
    assert arch.slug == "linux-server"
    assert "ssh" in arch.services


def test_get_archetype_unknown_raises():
    with pytest.raises(ValueError, match="Unknown archetype"):
        get_archetype("does-not-exist")


def test_random_archetype_returns_valid():
    arch = random_archetype()
    assert arch.slug in ARCHETYPES


def test_every_archetype_has_services():
    for slug, arch in ARCHETYPES.items():
        assert arch.services, f"Archetype '{slug}' has no services"


def test_every_archetype_has_preferred_distros():
    for slug, arch in ARCHETYPES.items():
        assert arch.preferred_distros, f"Archetype '{slug}' has no preferred_distros"


def test_every_archetype_preferred_distro_is_valid():
    valid_slugs = set(DISTROS.keys())
    for slug, arch in ARCHETYPES.items():
        for d in arch.preferred_distros:
            assert d in valid_slugs, (
                f"Archetype '{slug}' references unknown distro '{d}'"
            )


# ---------------------------------------------------------------------------
# INI loader — archetype= parsing
# ---------------------------------------------------------------------------

def _write_ini(content: str) -> str:
    """Write INI content to a temp file and return the path."""
    content = textwrap.dedent(content)
    fd, path = tempfile.mkstemp(suffix=".ini")
    os.write(fd, content.encode())
    os.close(fd)
    return path


def test_ini_archetype_parsed():
    path = _write_ini("""
        [general]
        net=10.0.0.0/24
        gw=10.0.0.1

        [my-server]
        archetype=linux-server
    """)
    cfg = load_ini(path)
    os.unlink(path)
    assert len(cfg.deckies) == 1
    assert cfg.deckies[0].archetype == "linux-server"
    assert cfg.deckies[0].services is None  # not overridden


def test_ini_archetype_with_explicit_services_override():
    """explicit services= must survive alongside archetype="""
    path = _write_ini("""
        [general]
        net=10.0.0.0/24
        gw=10.0.0.1

        [my-server]
        archetype=linux-server
        services=ftp,smb
    """)
    cfg = load_ini(path)
    os.unlink(path)
    assert cfg.deckies[0].archetype == "linux-server"
    assert cfg.deckies[0].services == ["ftp", "smb"]


# ---------------------------------------------------------------------------
# INI loader — amount= expansion
# ---------------------------------------------------------------------------

def test_ini_amount_one_keeps_section_name():
    path = _write_ini("""
        [general]
        net=10.0.0.0/24
        gw=10.0.0.1

        [my-printer]
        archetype=printer
        amount=1
    """)
    cfg = load_ini(path)
    os.unlink(path)
    assert len(cfg.deckies) == 1
    assert cfg.deckies[0].name == "my-printer"


def test_ini_amount_expands_deckies():
    path = _write_ini("""
        [general]
        net=10.0.0.0/24
        gw=10.0.0.1

        [corp-ws]
        archetype=windows-workstation
        amount=5
    """)
    cfg = load_ini(path)
    os.unlink(path)
    assert len(cfg.deckies) == 5
    for i, d in enumerate(cfg.deckies, start=1):
        assert d.name == f"corp-ws-{i:02d}"
        assert d.archetype == "windows-workstation"
        assert d.ip is None  # auto-allocated


def test_ini_amount_with_ip_raises():
    path = _write_ini("""
        [general]
        net=10.0.0.0/24
        gw=10.0.0.1

        [bad-group]
        services=ssh
        ip=10.0.0.50
        amount=3
    """)
    with pytest.raises(ValueError, match="Cannot combine ip="):
        load_ini(path)
    os.unlink(path)


def test_ini_amount_invalid_value_raises():
    path = _write_ini("""
        [general]
        net=10.0.0.0/24
        gw=10.0.0.1

        [bad]
        services=ssh
        amount=potato
    """)
    with pytest.raises(ValueError, match="must be a positive integer"):
        load_ini(path)
    os.unlink(path)


def test_ini_amount_zero_raises():
    path = _write_ini("""
        [general]
        net=10.0.0.0/24
        gw=10.0.0.1

        [bad]
        services=ssh
        amount=0
    """)
    with pytest.raises(ValueError, match="must be a positive integer"):
        load_ini(path)
    os.unlink(path)


def test_ini_amount_multiple_groups():
    """Two groups with different amounts expand independently."""
    path = _write_ini("""
        [general]
        net=10.0.0.0/24
        gw=10.0.0.1

        [workers]
        archetype=linux-server
        amount=3

        [printers]
        archetype=printer
        amount=2
    """)
    cfg = load_ini(path)
    os.unlink(path)
    assert len(cfg.deckies) == 5
    names = [d.name for d in cfg.deckies]
    assert names == ["workers-01", "workers-02", "workers-03", "printers-01", "printers-02"]


# ---------------------------------------------------------------------------
# INI loader — per-service subsections propagate to expanded deckies
# ---------------------------------------------------------------------------

def test_ini_subsection_propagates_to_expanded_deckies():
    """[group.ssh] must apply to group-01, group-02, ..."""
    path = _write_ini("""
        [general]
        net=10.0.0.0/24
        gw=10.0.0.1

        [linux-hosts]
        archetype=linux-server
        amount=3

        [linux-hosts.ssh]
        kernel_version=5.15.0-76-generic
    """)
    cfg = load_ini(path)
    os.unlink(path)
    assert len(cfg.deckies) == 3
    for d in cfg.deckies:
        assert "ssh" in d.service_config
        assert d.service_config["ssh"]["kernel_version"] == "5.15.0-76-generic"


def test_ini_subsection_direct_match_unaffected():
    """A direct [decky.svc] subsection must still work when amount=1."""
    path = _write_ini("""
        [general]
        net=10.0.0.0/24
        gw=10.0.0.1

        [web-01]
        services=http

        [web-01.http]
        server_header=Apache/2.4.51
    """)
    cfg = load_ini(path)
    os.unlink(path)
    assert cfg.deckies[0].service_config["http"]["server_header"] == "Apache/2.4.51"


# ---------------------------------------------------------------------------
# _build_deckies — archetype applied via CLI path
# ---------------------------------------------------------------------------

def test_build_deckies_archetype_sets_services():
    from decnet.fleet import build_deckies as _build_deckies
    from decnet.archetypes import get_archetype
    arch = get_archetype("mail-server")
    result = _build_deckies(
        n=2,
        ips=["10.0.0.10", "10.0.0.11"],
        services_explicit=None,
        randomize_services=False,
        archetype=arch,
    )
    assert len(result) == 2
    for d in result:
        assert set(d.services) == set(arch.services)
        assert d.archetype == "mail-server"


def test_build_deckies_archetype_preferred_distros():
    from decnet.fleet import build_deckies as _build_deckies
    from decnet.archetypes import get_archetype
    arch = get_archetype("iot-device")  # preferred_distros=["alpine"]
    result = _build_deckies(
        n=3,
        ips=["10.0.0.10", "10.0.0.11", "10.0.0.12"],
        services_explicit=None,
        randomize_services=False,
        archetype=arch,
    )
    for d in result:
        assert d.distro == "alpine"


def test_build_deckies_explicit_services_override_archetype():
    from decnet.fleet import build_deckies as _build_deckies
    from decnet.archetypes import get_archetype
    arch = get_archetype("linux-server")
    result = _build_deckies(
        n=1,
        ips=["10.0.0.10"],
        services_explicit=["ftp"],
        randomize_services=False,
        archetype=arch,
    )
    assert result[0].services == ["ftp"]
    assert result[0].archetype == "linux-server"
