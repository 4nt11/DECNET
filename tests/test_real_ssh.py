"""
Tests for the RealSSHService plugin and the deaddeck archetype.
"""

import pytest
from pathlib import Path

from decnet.services.registry import all_services, get_service
from decnet.archetypes import get_archetype


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fragment(service_cfg: dict | None = None, log_target: str | None = None) -> dict:
    return get_service("real_ssh").compose_fragment(
        "test-decky", log_target=log_target, service_cfg=service_cfg
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_real_ssh_registered():
    assert "real_ssh" in all_services()


def test_real_ssh_ports():
    svc = get_service("real_ssh")
    assert svc.ports == [22]


def test_real_ssh_is_build_service():
    svc = get_service("real_ssh")
    assert svc.default_image == "build"


def test_real_ssh_dockerfile_context_exists():
    svc = get_service("real_ssh")
    ctx = svc.dockerfile_context()
    assert ctx is not None
    assert ctx.is_dir(), f"Dockerfile context directory missing: {ctx}"
    assert (ctx / "Dockerfile").exists(), "Dockerfile missing in real_ssh template dir"
    assert (ctx / "entrypoint.sh").exists(), "entrypoint.sh missing in real_ssh template dir"


# ---------------------------------------------------------------------------
# compose_fragment structure
# ---------------------------------------------------------------------------

def test_compose_fragment_has_build():
    frag = _fragment()
    assert "build" in frag
    assert "context" in frag["build"]


def test_compose_fragment_container_name():
    frag = _fragment()
    assert frag["container_name"] == "test-decky-real-ssh"


def test_compose_fragment_restart_policy():
    frag = _fragment()
    assert frag["restart"] == "unless-stopped"


def test_compose_fragment_cap_add():
    frag = _fragment()
    assert "NET_BIND_SERVICE" in frag.get("cap_add", [])


def test_compose_fragment_default_password():
    frag = _fragment()
    env = frag["environment"]
    assert env["SSH_ROOT_PASSWORD"] == "admin"


# ---------------------------------------------------------------------------
# service_cfg overrides
# ---------------------------------------------------------------------------

def test_custom_password():
    frag = _fragment(service_cfg={"password": "s3cr3t!"})
    assert frag["environment"]["SSH_ROOT_PASSWORD"] == "s3cr3t!"


def test_custom_hostname():
    frag = _fragment(service_cfg={"hostname": "srv-prod-01"})
    assert frag["environment"]["SSH_HOSTNAME"] == "srv-prod-01"


def test_no_hostname_by_default():
    frag = _fragment()
    assert "SSH_HOSTNAME" not in frag["environment"]


# ---------------------------------------------------------------------------
# log_target: real_ssh does not forward logs via LOG_TARGET
# (no log aggregation on the entry-point — attacker shouldn't see it)
# ---------------------------------------------------------------------------

def test_no_log_target_env_injected():
    frag = _fragment(log_target="10.0.0.1:5140")
    assert "LOG_TARGET" not in frag.get("environment", {})


# ---------------------------------------------------------------------------
# Deaddeck archetype
# ---------------------------------------------------------------------------

def test_deaddeck_archetype_exists():
    arch = get_archetype("deaddeck")
    assert arch.slug == "deaddeck"


def test_deaddeck_uses_real_ssh():
    arch = get_archetype("deaddeck")
    assert "real_ssh" in arch.services


def test_deaddeck_nmap_os():
    arch = get_archetype("deaddeck")
    assert arch.nmap_os == "linux"


def test_deaddeck_preferred_distros_not_empty():
    arch = get_archetype("deaddeck")
    assert len(arch.preferred_distros) >= 1
