"""
Tests for the INI loader — subsection parsing, custom service definitions,
and per-service config propagation.
"""

import pytest
import textwrap
from pathlib import Path
from decnet.ini_loader import load_ini, IniConfig


def _write_ini(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "decnet.ini"
    f.write_text(textwrap.dedent(content))
    return f


# ---------------------------------------------------------------------------
# Basic decky parsing (regression)
# ---------------------------------------------------------------------------

def test_basic_decky_parsed(tmp_path):
    ini_file = _write_ini(tmp_path, """
        [general]
        net = 192.168.1.0/24
        gw = 192.168.1.1

        [decky-01]
        ip = 192.168.1.101
        services = ssh, http
    """)
    cfg = load_ini(ini_file)
    assert len(cfg.deckies) == 1
    assert cfg.deckies[0].name == "decky-01"
    assert cfg.deckies[0].services == ["ssh", "http"]
    assert cfg.deckies[0].service_config == {}


# ---------------------------------------------------------------------------
# Per-service subsection parsing
# ---------------------------------------------------------------------------

def test_subsection_parsed_into_service_config(tmp_path):
    ini_file = _write_ini(tmp_path, """
        [decky-01]
        ip = 192.168.1.101
        services = ssh

        [decky-01.ssh]
        kernel_version = 5.15.0-76-generic
        hardware_platform = x86_64
    """)
    cfg = load_ini(ini_file)
    svc_cfg = cfg.deckies[0].service_config
    assert "ssh" in svc_cfg
    assert svc_cfg["ssh"]["kernel_version"] == "5.15.0-76-generic"
    assert svc_cfg["ssh"]["hardware_platform"] == "x86_64"


def test_multiple_subsections_for_same_decky(tmp_path):
    ini_file = _write_ini(tmp_path, """
        [decky-01]
        services = ssh, http

        [decky-01.ssh]
        users = root:toor

        [decky-01.http]
        server_header = nginx/1.18.0
        fake_app = wordpress
    """)
    cfg = load_ini(ini_file)
    svc_cfg = cfg.deckies[0].service_config
    assert svc_cfg["ssh"]["users"] == "root:toor"
    assert svc_cfg["http"]["server_header"] == "nginx/1.18.0"
    assert svc_cfg["http"]["fake_app"] == "wordpress"


def test_subsection_for_unknown_decky_is_ignored(tmp_path):
    ini_file = _write_ini(tmp_path, """
        [decky-01]
        services = ssh

        [ghost.ssh]
        kernel_version = 5.15.0
    """)
    cfg = load_ini(ini_file)
    # ghost.ssh must not create a new decky or error out
    assert len(cfg.deckies) == 1
    assert cfg.deckies[0].name == "decky-01"
    assert cfg.deckies[0].service_config == {}


def test_plain_decky_without_subsections_has_empty_service_config(tmp_path):
    ini_file = _write_ini(tmp_path, """
        [decky-01]
        services = http
    """)
    cfg = load_ini(ini_file)
    assert cfg.deckies[0].service_config == {}


# ---------------------------------------------------------------------------
# Bring-your-own service (BYOS) parsing
# ---------------------------------------------------------------------------

def test_custom_service_parsed(tmp_path):
    ini_file = _write_ini(tmp_path, """
        [general]
        net = 10.0.0.0/24
        gw = 10.0.0.1

        [custom-myservice]
        binary = my-image:latest
        exec = /usr/bin/myapp -p 8080
        ports = 8080
    """)
    cfg = load_ini(ini_file)
    assert len(cfg.custom_services) == 1
    cs = cfg.custom_services[0]
    assert cs.name == "myservice"
    assert cs.image == "my-image:latest"
    assert cs.exec_cmd == "/usr/bin/myapp -p 8080"
    assert cs.ports == [8080]


def test_custom_service_without_ports(tmp_path):
    ini_file = _write_ini(tmp_path, """
        [custom-scanner]
        binary = scanner:1.0
        exec = /usr/bin/scanner
    """)
    cfg = load_ini(ini_file)
    assert cfg.custom_services[0].ports == []


def test_custom_service_not_added_to_deckies(tmp_path):
    ini_file = _write_ini(tmp_path, """
        [decky-01]
        services = ssh

        [custom-myservice]
        binary = foo:bar
        exec = /bin/foo
    """)
    cfg = load_ini(ini_file)
    assert len(cfg.deckies) == 1
    assert cfg.deckies[0].name == "decky-01"
    assert len(cfg.custom_services) == 1


def test_no_custom_services_gives_empty_list(tmp_path):
    ini_file = _write_ini(tmp_path, """
        [decky-01]
        services = http
    """)
    cfg = load_ini(ini_file)
    assert cfg.custom_services == []


# ---------------------------------------------------------------------------
# nmap_os parsing
# ---------------------------------------------------------------------------

def test_nmap_os_parsed_from_ini(tmp_path):
    ini_file = _write_ini(tmp_path, """
        [decky-win]
        ip = 192.168.1.101
        services = rdp, smb
        nmap_os = windows
    """)
    cfg = load_ini(ini_file)
    assert cfg.deckies[0].nmap_os == "windows"


def test_nmap_os_defaults_to_none_when_absent(tmp_path):
    ini_file = _write_ini(tmp_path, """
        [decky-01]
        services = ssh
    """)
    cfg = load_ini(ini_file)
    assert cfg.deckies[0].nmap_os is None


@pytest.mark.parametrize("os_family", ["linux", "windows", "bsd", "embedded", "cisco"])
def test_nmap_os_all_families_accepted(tmp_path, os_family):
    ini_file = _write_ini(tmp_path, f"""
        [decky-01]
        services = ssh
        nmap_os = {os_family}
    """)
    cfg = load_ini(ini_file)
    assert cfg.deckies[0].nmap_os == os_family


def test_nmap_os_propagates_to_amount_expanded_deckies(tmp_path):
    ini_file = _write_ini(tmp_path, """
        [corp-printers]
        services = snmp
        nmap_os  = embedded
        amount   = 3
    """)
    cfg = load_ini(ini_file)
    assert len(cfg.deckies) == 3
    for d in cfg.deckies:
        assert d.nmap_os == "embedded"


def test_nmap_os_hyphen_alias_accepted(tmp_path):
    """nmap-os= (hyphen) should work as an alias for nmap_os=."""
    ini_file = _write_ini(tmp_path, """
        [decky-01]
        services = ssh
        nmap-os = bsd
    """)
    cfg = load_ini(ini_file)
    assert cfg.deckies[0].nmap_os == "bsd"
