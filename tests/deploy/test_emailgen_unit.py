"""Smoke tests for the emailgen systemd unit + decnet.target wiring.

These don't exercise systemd (the test host wouldn't have it), they
just assert the static contents of ``deploy/decnet-emailgen.service.j2``
and ``deploy/decnet.target`` match what ``decnet init`` will install.
A regression here would only surface on a fresh host install — cheap
to catch at CI time.
"""
from __future__ import annotations

from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent.parent
DEPLOY = REPO / "deploy"


@pytest.fixture
def unit_text() -> str:
    return (DEPLOY / "decnet-emailgen.service.j2").read_text()


@pytest.fixture
def target_text() -> str:
    return (DEPLOY / "decnet.target").read_text()


# ── unit file ────────────────────────────────────────────────────────────────


def test_emailgen_unit_exists():
    assert (DEPLOY / "decnet-emailgen.service.j2").exists()


def test_emailgen_unit_uses_run_subcommand(unit_text):
    """`decnet emailgen` is a sub-app now — the unit must call `run`,
    not bare `emailgen` (which still works but is implicit-default and
    fragile to future changes)."""
    assert "decnet emailgen run" in unit_text


def test_emailgen_unit_has_docker_supplementary_group(unit_text):
    """Driver shells `docker exec` to drop EMLs in the spool — without
    this group the worker can't reach the docker socket."""
    assert "SupplementaryGroups=docker" in unit_text


def test_emailgen_unit_orders_after_bus(unit_text):
    """Bus must come up first so emailgen's heartbeat publishes land."""
    assert "After=network-online.target decnet-bus.service" in unit_text
    assert "Wants=network-online.target decnet-bus.service" in unit_text


def test_emailgen_unit_has_security_hardening(unit_text):
    """Same hardening shape as orchestrator.service — defence in depth."""
    for directive in (
        "NoNewPrivileges=yes",
        "ProtectSystem=full",
        "ProtectHome=read-only",
        "PrivateTmp=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
    ):
        assert directive in unit_text, f"missing {directive}"


def test_emailgen_unit_writes_to_log_dir(unit_text):
    assert "/var/log/decnet/decnet.emailgen.log" in unit_text
    assert "ReadWritePaths={{ install_dir }} /var/log/decnet" in unit_text


def test_emailgen_unit_restart_on_failure(unit_text):
    assert "Restart=on-failure" in unit_text


# ── target wiring ────────────────────────────────────────────────────────────


def test_target_wants_emailgen(target_text):
    """A fresh `decnet init` must bring up emailgen with the rest of
    the fleet."""
    assert "decnet-emailgen.service" in target_text


def test_target_wants_orchestrator(target_text):
    """Orchestrator was an oversight historically — bundling it in here
    too while we're touching the file."""
    assert "decnet-orchestrator.service" in target_text
