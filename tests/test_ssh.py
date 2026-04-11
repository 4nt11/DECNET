"""
Tests for the SSHService plugin (real OpenSSH, Cowrie removed).
"""

from decnet.services.registry import all_services, get_service


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fragment(service_cfg: dict | None = None, log_target: str | None = None) -> dict:
    return get_service("ssh").compose_fragment(
        "test-decky", log_target=log_target, service_cfg=service_cfg
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_ssh_registered():
    assert "ssh" in all_services()


def test_ssh_ports():
    assert get_service("ssh").ports == [22]


def test_ssh_is_build_service():
    assert get_service("ssh").default_image == "build"


def test_ssh_dockerfile_context_exists():
    svc = get_service("ssh")
    ctx = svc.dockerfile_context()
    assert ctx.is_dir(), f"Dockerfile context missing: {ctx}"
    assert (ctx / "Dockerfile").exists()
    assert (ctx / "entrypoint.sh").exists()


# ---------------------------------------------------------------------------
# No Cowrie env vars
# ---------------------------------------------------------------------------

def test_no_cowrie_vars():
    env = _fragment()["environment"]
    cowrie_keys = [k for k in env if k.startswith("COWRIE_") or k == "NODE_NAME"]
    assert cowrie_keys == [], f"Unexpected Cowrie vars: {cowrie_keys}"


# ---------------------------------------------------------------------------
# compose_fragment structure
# ---------------------------------------------------------------------------

def test_fragment_has_build():
    frag = _fragment()
    assert "build" in frag and "context" in frag["build"]


def test_fragment_container_name():
    assert _fragment()["container_name"] == "test-decky-ssh"


def test_fragment_restart_policy():
    assert _fragment()["restart"] == "unless-stopped"


def test_fragment_cap_add():
    assert "NET_BIND_SERVICE" in _fragment().get("cap_add", [])


def test_default_password():
    assert _fragment()["environment"]["SSH_ROOT_PASSWORD"] == "admin"


def test_custom_password():
    assert _fragment(service_cfg={"password": "h4x!"})["environment"]["SSH_ROOT_PASSWORD"] == "h4x!"


def test_custom_hostname():
    assert _fragment(service_cfg={"hostname": "prod-db-01"})["environment"]["SSH_HOSTNAME"] == "prod-db-01"


def test_no_hostname_by_default():
    assert "SSH_HOSTNAME" not in _fragment()["environment"]


def test_no_log_target_in_env():
    assert "LOG_TARGET" not in _fragment(log_target="10.0.0.1:5140").get("environment", {})
