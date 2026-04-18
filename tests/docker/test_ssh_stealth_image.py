"""
End-to-end stealth assertions for the built SSH honeypot image.

These tests build the `templates/ssh/` Dockerfile and then introspect the
running container to verify that:

- `/opt/emit_capture.py`, `/opt/syslog_bridge.py` are absent.
- `/usr/libexec/udev/journal-relay` is absent (only the `kmsg-watch`
  symlink remains).
- The renamed argv-zap shim is installed at the multiarch path.
- A file drop still produces a `file_captured` RFC 5424 log line.

Marked `docker` so they're skipped by default (see pyproject.toml).
"""

from __future__ import annotations

import subprocess
import time
import uuid

import pytest

from decnet.services.registry import get_service

pytestmark = pytest.mark.docker

IMAGE_TAG = "decnet-ssh-stealth-test"


def _run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
    )


@pytest.fixture(scope="module")
def ssh_stealth_image() -> str:
    ctx = get_service("ssh").dockerfile_context()
    _run(["docker", "build", "-t", IMAGE_TAG, str(ctx)])
    yield IMAGE_TAG
    _run(["docker", "rmi", "-f", IMAGE_TAG], check=False)


@pytest.fixture()
def running_container(ssh_stealth_image):
    name = f"ssh-stealth-{uuid.uuid4().hex[:8]}"
    _run(["docker", "run", "-d", "--rm", "--name", name, ssh_stealth_image])
    # Give entrypoint time to decode + launch the capture loop.
    time.sleep(3)
    try:
        yield name
    finally:
        _run(["docker", "stop", name], check=False)


def _exec(container: str, shell_cmd: str) -> str:
    return _run(["docker", "exec", container, "sh", "-c", shell_cmd]).stdout


# ---------------------------------------------------------------------------
# On-disk artifact hiding
# ---------------------------------------------------------------------------

def test_no_python_capture_sources_on_disk(running_container):
    out = _exec(
        running_container,
        'find / \\( -name "emit_capture*" -o -name "syslog_bridge*" \\) '
        '-not -path "/proc/*" 2>/dev/null',
    )
    assert out.strip() == "", f"capture python sources leaked: {out!r}"


def test_no_journal_relay_file(running_container):
    out = _exec(running_container, "ls /usr/libexec/udev/")
    assert "journal-relay" not in out
    # The kmsg-watch symlink is the only expected entry.
    assert "kmsg-watch" in out


def test_opt_is_empty(running_container):
    out = _exec(running_container, "ls -A /opt")
    assert out.strip() == "", f"/opt should be empty, got: {out!r}"


def test_preload_shim_installed_at_multiarch_path(running_container):
    out = _exec(running_container, "ls /usr/lib/x86_64-linux-gnu/libudev-shared.so.1")
    assert "libudev-shared.so.1" in out


def test_no_argv_zap_name_anywhere(running_container):
    out = _exec(
        running_container,
        'find / -name "argv_zap*" -not -path "/proc/*" 2>/dev/null',
    )
    assert out.strip() == "", f"argv_zap name leaked: {out!r}"


# ---------------------------------------------------------------------------
# Runtime process disguise
# ---------------------------------------------------------------------------

def test_process_list_shows_disguised_names(running_container):
    out = _exec(running_container, "ps -eo comm")
    # Must see the cover names.
    assert "journal-relay" in out
    assert "kmsg-watch" in out
    # Must NOT see the real script / source paths in the process list.
    assert "emit_capture" not in out
    assert "argv_zap" not in out


# ---------------------------------------------------------------------------
# Functional: capture still works
# ---------------------------------------------------------------------------

def test_file_drop_produces_capture_log(running_container):
    _exec(running_container, 'echo "payload-data" > /root/loot.txt')
    # Capture is async — inotify → bash → python → rsyslog → stdout.
    time.sleep(3)
    logs = _run(["docker", "logs", running_container]).stdout
    assert "file_captured" in logs, f"no capture event in logs:\n{logs}"
    assert "loot.txt" in logs
    assert "sha256=" in logs
