"""
Tests for the composer — verifies BASE_IMAGE injection and distro heterogeneity.
"""

import pytest
from decnet.config import DeckyConfig, DecnetConfig
from decnet.composer import generate_compose
from decnet.distros import all_distros, DISTROS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

APT_COMPATIBLE = {
    "debian:bookworm-slim",
    "ubuntu:22.04",
    "ubuntu:20.04",
    "kalilinux/kali-rolling",
}

BUILD_SERVICES = [
    "ssh", "telnet", "http", "rdp", "smb", "ftp", "smtp", "elasticsearch",
    "pop3", "imap", "mysql", "mssql", "redis", "mongodb", "postgres",
    "ldap", "vnc", "docker_api", "k8s", "sip",
    "mqtt", "llmnr", "snmp", "tftp", "conpot"
]

UPSTREAM_SERVICES: list = []


def _make_config(services, distro="debian", base_image=None, build_base=None):
    profile = DISTROS[distro]
    decky = DeckyConfig(
        name="decky-01",
        ip="10.0.0.10",
        services=services,
        distro=distro,
        base_image=base_image or profile.image,
        build_base=build_base or profile.build_base,
        hostname="test-host",
    )
    return DecnetConfig(
        mode="unihost",
        interface="eth0",
        subnet="10.0.0.0/24",
        gateway="10.0.0.1",
        deckies=[decky],
    )


# ---------------------------------------------------------------------------
# BASE_IMAGE injection — build services
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("svc", BUILD_SERVICES)
def test_build_service_gets_base_image_arg(svc):
    """Every build service must have BASE_IMAGE injected in compose args."""
    config = _make_config([svc], distro="debian")
    compose = generate_compose(config)
    key = f"decky-01-{svc}"
    fragment = compose["services"][key]
    assert "build" in fragment, f"{svc}: missing 'build' key"
    assert "args" in fragment["build"], f"{svc}: build section missing 'args'"
    assert "BASE_IMAGE" in fragment["build"]["args"], f"{svc}: BASE_IMAGE not in args"


@pytest.mark.parametrize("distro,expected_build_base", [
    ("debian",   "debian:bookworm-slim"),
    ("ubuntu22", "ubuntu:22.04"),
    ("ubuntu20", "ubuntu:20.04"),
    ("kali",     "kalilinux/kali-rolling"),
    ("rocky9",   "debian:bookworm-slim"),
    ("alpine",   "debian:bookworm-slim"),
])
def test_build_service_base_image_matches_distro(distro, expected_build_base):
    """BASE_IMAGE arg must match the distro's build_base."""
    config = _make_config(["http"], distro=distro)
    compose = generate_compose(config)
    fragment = compose["services"]["decky-01-http"]
    assert fragment["build"]["args"]["BASE_IMAGE"].startswith(expected_build_base)


# ---------------------------------------------------------------------------
# BASE_IMAGE NOT injected for upstream-image services
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("svc", UPSTREAM_SERVICES)
def test_upstream_service_has_no_build_section(svc):
    """Upstream-image services must not receive a build section or BASE_IMAGE."""
    config = _make_config([svc])
    compose = generate_compose(config)
    fragment = compose["services"][f"decky-01-{svc}"]
    assert "build" not in fragment
    assert "image" in fragment


# ---------------------------------------------------------------------------
# service_config propagation tests
# ---------------------------------------------------------------------------

def test_service_config_http_server_header():
    """service_config for http must inject SERVER_HEADER into compose env."""
    from decnet.config import DeckyConfig, DecnetConfig
    from decnet.distros import DISTROS
    profile = DISTROS["debian"]
    decky = DeckyConfig(
        name="decky-01", ip="10.0.0.10",
        services=["http"], distro="debian",
        base_image=profile.image, build_base=profile.build_base,
        hostname="test-host",
        service_config={"http": {"server_header": "nginx/1.18.0"}},
    )
    config = DecnetConfig(
        mode="unihost", interface="eth0",
        subnet="10.0.0.0/24", gateway="10.0.0.1",
        deckies=[decky],
    )
    compose = generate_compose(config)
    env = compose["services"]["decky-01-http"]["environment"]
    assert env.get("SERVER_HEADER") == "nginx/1.18.0"


def test_service_config_ssh_password():
    """service_config for ssh must inject SSH_ROOT_PASSWORD."""
    from decnet.config import DeckyConfig, DecnetConfig
    from decnet.distros import DISTROS
    profile = DISTROS["debian"]
    decky = DeckyConfig(
        name="decky-01", ip="10.0.0.10",
        services=["ssh"], distro="debian",
        base_image=profile.image, build_base=profile.build_base,
        hostname="test-host",
        service_config={"ssh": {"password": "s3cr3t!"}},
    )
    config = DecnetConfig(
        mode="unihost", interface="eth0",
        subnet="10.0.0.0/24", gateway="10.0.0.1",
        deckies=[decky],
    )
    compose = generate_compose(config)
    env = compose["services"]["decky-01-ssh"]["environment"]
    assert env.get("SSH_ROOT_PASSWORD") == "s3cr3t!"
    assert not any(k.startswith("COWRIE_") for k in env)


def test_service_config_for_one_service_does_not_affect_another():
    """service_config for http must not bleed into ftp fragment."""
    from decnet.config import DeckyConfig, DecnetConfig
    from decnet.distros import DISTROS
    profile = DISTROS["debian"]
    decky = DeckyConfig(
        name="decky-01", ip="10.0.0.10",
        services=["http", "ftp"], distro="debian",
        base_image=profile.image, build_base=profile.build_base,
        hostname="test-host",
        service_config={"http": {"server_header": "nginx/1.18.0"}},
    )
    config = DecnetConfig(
        mode="unihost", interface="eth0",
        subnet="10.0.0.0/24", gateway="10.0.0.1",
        deckies=[decky],
    )
    compose = generate_compose(config)
    ftp_env = compose["services"]["decky-01-ftp"]["environment"]
    assert "SERVER_HEADER" not in ftp_env


def test_no_service_config_produces_no_extra_env():
    """A decky with no service_config must not have new persona env vars."""
    config = _make_config(["http", "mysql"])
    compose = generate_compose(config)
    for svc in ("http", "mysql"):
        env = compose["services"][f"decky-01-{svc}"]["environment"]
        assert "SERVER_HEADER" not in env
        assert "MYSQL_VERSION" not in env


# ---------------------------------------------------------------------------
# Base container uses distro image, not build_base
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distro", list(DISTROS.keys()))
def test_base_container_uses_full_distro_image(distro):
    """The IP-holder base container must use distro.image, not build_base."""
    config = _make_config(["ssh"], distro=distro)
    compose = generate_compose(config)
    base = compose["services"]["decky-01"]
    expected = DISTROS[distro].image
    assert base["image"] == expected, (
        f"distro={distro}: base container image '{base['image']}' != '{expected}'"
    )


# ---------------------------------------------------------------------------
# Distro profile — build_base is always apt-compatible
# ---------------------------------------------------------------------------

def test_all_distros_have_build_base():
    for slug, profile in all_distros().items():
        assert profile.build_base, f"Distro '{slug}' has empty build_base"


def test_all_distro_build_bases_are_apt_compatible():
    for slug, profile in all_distros().items():
        tag = profile.build_base.split("@")[0]
        assert tag in APT_COMPATIBLE, (
            f"Distro '{slug}' build_base '{profile.build_base}' is not apt-compatible. "
            f"Allowed: {APT_COMPATIBLE}"
        )


# ---------------------------------------------------------------------------
# Heterogeneity — multiple deckies with different distros get different images
# ---------------------------------------------------------------------------

def test_multiple_deckies_different_build_bases():
    """A multi-decky deployment with ubuntu22 and debian must differ in BASE_IMAGE."""
    deckies = [
        DeckyConfig(
            name="decky-01", ip="10.0.0.10",
            services=["http"], distro="debian",
            base_image="debian:bookworm-slim", build_base="debian:bookworm-slim",
            hostname="host-01",
        ),
        DeckyConfig(
            name="decky-02", ip="10.0.0.11",
            services=["http"], distro="ubuntu22",
            base_image="ubuntu:22.04", build_base="ubuntu:22.04",
            hostname="host-02",
        ),
    ]
    config = DecnetConfig(
        mode="unihost", interface="eth0",
        subnet="10.0.0.0/24", gateway="10.0.0.1",
        deckies=deckies,
    )
    compose = generate_compose(config)

    base_img_01 = compose["services"]["decky-01-http"]["build"]["args"]["BASE_IMAGE"]
    base_img_02 = compose["services"]["decky-02-http"]["build"]["args"]["BASE_IMAGE"]

    assert base_img_01 == "debian:bookworm-slim"
    assert base_img_02 == "ubuntu:22.04"
    assert base_img_01 != base_img_02


# ---------------------------------------------------------------------------
# Fleet ownership labels — collector keys off these to recognize freshly-
# deployed containers without consulting decnet-state.json (the previous
# state-file lookup race silently dropped containers whose Docker start
# event arrived before the state write completed).
# ---------------------------------------------------------------------------

def test_service_container_carries_fleet_labels():
    config = _make_config(["http"], distro="debian")
    compose = generate_compose(config)
    labels = compose["services"]["decky-01-http"]["labels"]
    assert labels["decnet.fleet.service"] == "true"
    assert labels["decnet.fleet.decky"] == "decky-01"
    assert labels["decnet.fleet.service_name"] == "http"


def test_base_container_does_not_carry_service_label():
    """Base containers run sleep — they don't emit logs and must NOT be
    streamed by the collector, so the service marker stays off them."""
    config = _make_config(["http"], distro="debian")
    compose = generate_compose(config)
    base = compose["services"]["decky-01"]
    assert "decnet.fleet.service" not in (base.get("labels") or {})
