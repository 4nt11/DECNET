"""
Tests for all 25 DECNET service plugins.

Covers:
- Service registration via the plugin registry
- compose_fragment structure (container_name, restart, image/build)
- LOG_TARGET propagation for custom-build services
- dockerfile_context returns Path for build services, None for upstream-image services
- Per-service persona config (service_cfg) propagation
"""

import pytest
from pathlib import Path
from decnet.services.registry import all_services, get_service


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fragment(name: str, log_target: str | None = None, service_cfg: dict | None = None) -> dict:
    return get_service(name).compose_fragment("test-decky", log_target, service_cfg)


def _is_build_service(name: str) -> bool:
    svc = get_service(name)
    return svc.default_image == "build"


# ---------------------------------------------------------------------------
# Tier 1: upstream-image services (non-build)
# ---------------------------------------------------------------------------

UPSTREAM_SERVICES = {
    "telnet": ("cowrie/cowrie",  [23]),
    "conpot": ("honeynet/conpot", [502, 161, 80]),
}

# ---------------------------------------------------------------------------
# Tier 2: custom-build services (including ssh, which now uses build)
# ---------------------------------------------------------------------------

BUILD_SERVICES = {
    "ssh":           ([22, 2222],   "ssh"),
    "http":          ([80, 443],    "http"),
    "rdp":           ([3389],       "rdp"),
    "smb":           ([445, 139],   "smb"),
    "ftp":           ([21],         "ftp"),
    "smtp":          ([25, 587],    "smtp"),
    "elasticsearch": ([9200],       "elasticsearch"),
    "pop3":          ([110, 995],   "pop3"),
    "imap":          ([143, 993],   "imap"),
    "mysql":         ([3306],       "mysql"),
    "mssql":         ([1433],       "mssql"),
    "redis":         ([6379],       "redis"),
    "mongodb":       ([27017],      "mongodb"),
    "postgres":      ([5432],       "postgres"),
    "ldap":          ([389, 636],   "ldap"),
    "vnc":           ([5900],       "vnc"),
    "docker_api":    ([2375, 2376], "docker_api"),
    "k8s":           ([6443, 8080], "k8s"),
    "sip":           ([5060],       "sip"),
    "mqtt":          ([1883],       "mqtt"),
    "llmnr":         ([5355, 5353], "llmnr"),
    "snmp":          ([161],        "snmp"),
    "tftp":          ([69],         "tftp"),
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
def test_build_service_node_name_env(name):
    frag = _fragment(name)
    env = frag.get("environment", {})
    assert "NODE_NAME" in env
    assert env["NODE_NAME"] == "test-decky"


# SSH uses COWRIE_OUTPUT_TCP_* instead of LOG_TARGET — exclude from generic tests
_LOG_TARGET_SERVICES = [n for n in BUILD_SERVICES if n != "ssh"]


@pytest.mark.parametrize("name", _LOG_TARGET_SERVICES)
def test_build_service_log_target_propagated(name):
    frag = _fragment(name, log_target="10.0.0.1:5140")
    env = frag.get("environment", {})
    assert env.get("LOG_TARGET") == "10.0.0.1:5140"


@pytest.mark.parametrize("name", _LOG_TARGET_SERVICES)
def test_build_service_no_log_target_by_default(name):
    frag = _fragment(name)
    env = frag.get("environment", {})
    assert "LOG_TARGET" not in env


def test_ssh_log_target_uses_cowrie_tcp_output():
    """SSH forwards logs via Cowrie TCP output, not LOG_TARGET."""
    env = _fragment("ssh", log_target="10.0.0.1:5140").get("environment", {})
    assert env.get("COWRIE_OUTPUT_TCP_ENABLED") == "true"
    assert env.get("COWRIE_OUTPUT_TCP_HOST") == "10.0.0.1"
    assert env.get("COWRIE_OUTPUT_TCP_PORT") == "5140"
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


# ---------------------------------------------------------------------------
# Per-service persona config (service_cfg)
# ---------------------------------------------------------------------------

# HTTP -----------------------------------------------------------------------

def test_http_default_no_extra_env():
    """No service_cfg → none of the new env vars should appear."""
    env = _fragment("http").get("environment", {})
    for key in ("SERVER_HEADER", "RESPONSE_CODE", "FAKE_APP", "EXTRA_HEADERS", "CUSTOM_BODY", "FILES_DIR"):
        assert key not in env, f"Expected {key} absent by default"


def test_http_server_header():
    env = _fragment("http", service_cfg={"server_header": "nginx/1.18.0"}).get("environment", {})
    assert env.get("SERVER_HEADER") == "nginx/1.18.0"


def test_http_response_code():
    env = _fragment("http", service_cfg={"response_code": 200}).get("environment", {})
    assert env.get("RESPONSE_CODE") == "200"


def test_http_fake_app():
    env = _fragment("http", service_cfg={"fake_app": "wordpress"}).get("environment", {})
    assert env.get("FAKE_APP") == "wordpress"


def test_http_extra_headers():
    import json
    env = _fragment("http", service_cfg={"extra_headers": {"X-Frame-Options": "SAMEORIGIN"}}).get("environment", {})
    assert "EXTRA_HEADERS" in env
    assert json.loads(env["EXTRA_HEADERS"]) == {"X-Frame-Options": "SAMEORIGIN"}


def test_http_custom_body():
    env = _fragment("http", service_cfg={"custom_body": "<html>hi</html>"}).get("environment", {})
    assert env.get("CUSTOM_BODY") == "<html>hi</html>"


def test_http_empty_service_cfg_no_extra_env():
    env = _fragment("http", service_cfg={}).get("environment", {})
    assert "SERVER_HEADER" not in env


# SSH ------------------------------------------------------------------------

def test_ssh_default_no_persona_env():
    env = _fragment("ssh").get("environment", {})
    for key in ("COWRIE_HONEYPOT_KERNEL_VERSION", "COWRIE_HONEYPOT_HARDWARE_PLATFORM",
                "COWRIE_SSH_VERSION", "COWRIE_USERDB_ENTRIES"):
        assert key not in env, f"Expected {key} absent by default"


def test_ssh_kernel_version():
    env = _fragment("ssh", service_cfg={"kernel_version": "5.15.0-76-generic"}).get("environment", {})
    assert env.get("COWRIE_HONEYPOT_KERNEL_VERSION") == "5.15.0-76-generic"


def test_ssh_hardware_platform():
    env = _fragment("ssh", service_cfg={"hardware_platform": "aarch64"}).get("environment", {})
    assert env.get("COWRIE_HONEYPOT_HARDWARE_PLATFORM") == "aarch64"


def test_ssh_banner():
    env = _fragment("ssh", service_cfg={"ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3"}).get("environment", {})
    assert env.get("COWRIE_SSH_VERSION") == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3"


def test_ssh_users():
    env = _fragment("ssh", service_cfg={"users": "root:toor,admin:admin123"}).get("environment", {})
    assert env.get("COWRIE_USERDB_ENTRIES") == "root:toor,admin:admin123"


# SMTP -----------------------------------------------------------------------

def test_smtp_banner():
    env = _fragment("smtp", service_cfg={"banner": "220 mail.corp.local ESMTP Sendmail"}).get("environment", {})
    assert env.get("SMTP_BANNER") == "220 mail.corp.local ESMTP Sendmail"


def test_smtp_mta():
    env = _fragment("smtp", service_cfg={"mta": "mail.corp.local"}).get("environment", {})
    assert env.get("SMTP_MTA") == "mail.corp.local"


def test_smtp_default_no_extra_env():
    env = _fragment("smtp").get("environment", {})
    assert "SMTP_BANNER" not in env
    assert "SMTP_MTA" not in env


# MySQL ----------------------------------------------------------------------

def test_mysql_version():
    env = _fragment("mysql", service_cfg={"version": "8.0.33"}).get("environment", {})
    assert env.get("MYSQL_VERSION") == "8.0.33"


def test_mysql_default_no_version_env():
    env = _fragment("mysql").get("environment", {})
    assert "MYSQL_VERSION" not in env


# Redis ----------------------------------------------------------------------

def test_redis_version():
    env = _fragment("redis", service_cfg={"version": "6.2.14"}).get("environment", {})
    assert env.get("REDIS_VERSION") == "6.2.14"


def test_redis_os_string():
    env = _fragment("redis", service_cfg={"os_string": "Linux 4.19.0"}).get("environment", {})
    assert env.get("REDIS_OS") == "Linux 4.19.0"


def test_redis_default_no_extra_env():
    env = _fragment("redis").get("environment", {})
    assert "REDIS_VERSION" not in env
    assert "REDIS_OS" not in env
