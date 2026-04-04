"""
Tests for all 25 DECNET service plugins.

Covers:
- Service registration via the plugin registry
- compose_fragment structure (container_name, restart, image/build)
- LOG_TARGET propagation for custom-build services
- dockerfile_context returns Path for build services, None for upstream-image services
"""

import pytest
from pathlib import Path
from decnet.services.registry import all_services, get_service


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fragment(name: str, log_target: str | None = None) -> dict:
    return get_service(name).compose_fragment("test-decky", log_target)


def _is_build_service(name: str) -> bool:
    svc = get_service(name)
    return svc.default_image == "build"


# ---------------------------------------------------------------------------
# Tier 1: upstream-image services
# ---------------------------------------------------------------------------

UPSTREAM_SERVICES = {
    "ssh":           ("cowrie/cowrie",       [22, 2222]),
    "telnet":        ("cowrie/cowrie",       [23]),
    "smtp":          ("dtagdevsec/mailoney", [25, 587]),
    "elasticsearch": ("dtagdevsec/elasticpot", [9200]),
    "conpot":        ("honeynet/conpot",     [502, 161, 80]),
}

# ---------------------------------------------------------------------------
# Tier 2: custom-build services
# ---------------------------------------------------------------------------

BUILD_SERVICES = {
    "http":       ([80, 443],    "http"),
    "rdp":        ([3389],       "rdp"),
    "smb":        ([445, 139],   "smb"),
    "ftp":        ([21],         "ftp"),
    "pop3":       ([110, 995],   "pop3"),
    "imap":       ([143, 993],   "imap"),
    "mysql":      ([3306],       "mysql"),
    "mssql":      ([1433],       "mssql"),
    "redis":      ([6379],       "redis"),
    "mongodb":    ([27017],      "mongodb"),
    "postgres":   ([5432],       "postgres"),
    "ldap":       ([389, 636],   "ldap"),
    "vnc":        ([5900],       "vnc"),
    "docker_api": ([2375, 2376], "docker_api"),
    "k8s":        ([6443, 8080], "k8s"),
    "sip":        ([5060],       "sip"),
    "mqtt":       ([1883],       "mqtt"),
    "llmnr":      ([5355, 5353], "llmnr"),
    "snmp":       ([161],        "snmp"),
    "tftp":       ([69],         "tftp"),
}

ALL_SERVICE_NAMES = list(UPSTREAM_SERVICES) + list(BUILD_SERVICES)


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ALL_SERVICE_NAMES)
def test_service_registered(name):
    """Every service must appear in the registry."""
    registry = all_services()
    assert name in registry, f"Service '{name}' not found in registry"


@pytest.mark.parametrize("name", ALL_SERVICE_NAMES)
def test_service_ports_defined(name):
    """Every service must declare at least one port."""
    svc = get_service(name)
    assert isinstance(svc.ports, list)
    assert len(svc.ports) >= 1


# ---------------------------------------------------------------------------
# Upstream-image service tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    (n, (img, ports)) for n, (img, ports) in UPSTREAM_SERVICES.items()
])
def test_upstream_image(name, expected):
    expected_image, _ = expected
    frag = _fragment(name)
    assert frag.get("image") == expected_image


@pytest.mark.parametrize("name", UPSTREAM_SERVICES)
def test_upstream_no_dockerfile_context(name):
    assert get_service(name).dockerfile_context() is None


@pytest.mark.parametrize("name", UPSTREAM_SERVICES)
def test_upstream_container_name(name):
    frag = _fragment(name)
    assert frag["container_name"] == f"test-decky-{name.replace('_', '-')}"


@pytest.mark.parametrize("name", UPSTREAM_SERVICES)
def test_upstream_restart_policy(name):
    frag = _fragment(name)
    assert frag.get("restart") == "unless-stopped"


# ---------------------------------------------------------------------------
# Build-service tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", BUILD_SERVICES)
def test_build_service_uses_build(name):
    frag = _fragment(name)
    assert "build" in frag, f"Service '{name}' fragment missing 'build' key"
    assert "context" in frag["build"]


@pytest.mark.parametrize("name", BUILD_SERVICES)
def test_build_service_dockerfile_context_is_path(name):
    ctx = get_service(name).dockerfile_context()
    assert isinstance(ctx, Path), f"Service '{name}' dockerfile_context should return a Path"


@pytest.mark.parametrize("name", BUILD_SERVICES)
def test_build_service_dockerfile_exists(name):
    ctx = get_service(name).dockerfile_context()
    dockerfile = ctx / "Dockerfile"
    assert dockerfile.exists(), f"Dockerfile missing at {dockerfile}"


@pytest.mark.parametrize("name", BUILD_SERVICES)
def test_build_service_container_name(name):
    frag = _fragment(name)
    slug = name.replace("_", "-")
    assert frag["container_name"] == f"test-decky-{slug}"


@pytest.mark.parametrize("name", BUILD_SERVICES)
def test_build_service_restart_policy(name):
    frag = _fragment(name)
    assert frag.get("restart") == "unless-stopped"


@pytest.mark.parametrize("name", BUILD_SERVICES)
def test_build_service_honeypot_name_env(name):
    frag = _fragment(name)
    env = frag.get("environment", {})
    assert "HONEYPOT_NAME" in env
    assert env["HONEYPOT_NAME"] == "test-decky"


@pytest.mark.parametrize("name", BUILD_SERVICES)
def test_build_service_log_target_propagated(name):
    frag = _fragment(name, log_target="10.0.0.1:5140")
    env = frag.get("environment", {})
    assert env.get("LOG_TARGET") == "10.0.0.1:5140"


@pytest.mark.parametrize("name", BUILD_SERVICES)
def test_build_service_no_log_target_by_default(name):
    frag = _fragment(name)
    env = frag.get("environment", {})
    assert "LOG_TARGET" not in env


# ---------------------------------------------------------------------------
# Port coverage tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    (n, ports) for n, (ports, _) in BUILD_SERVICES.items()
])
def test_build_service_ports(name, expected):
    svc = get_service(name)
    assert svc.ports == expected


@pytest.mark.parametrize("name,expected", [
    (n, ports) for n, (_, ports) in UPSTREAM_SERVICES.items()
])
def test_upstream_service_ports(name, expected):
    svc = get_service(name)
    assert svc.ports == expected


# ---------------------------------------------------------------------------
# Registry completeness
# ---------------------------------------------------------------------------

def test_total_service_count():
    """Sanity check: at least 25 services registered."""
    assert len(all_services()) >= 25
