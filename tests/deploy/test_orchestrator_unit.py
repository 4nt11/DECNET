"""Smoke tests for the orchestrator systemd unit + decnet.target wiring.

These don't exercise systemd (the test host wouldn't have it); they
just assert the static contents of ``deploy/decnet-orchestrator.service.j2``
and ``deploy/decnet.target`` match what ``decnet init`` will install.

Anti-regressions for two specific failure modes:

1. After the realism migration (stage 5), ``decnet-emailgen.service``
   is gone — the orchestrator covers the email branch.  A regression
   that re-introduces the emailgen unit file or the ``decnet.target``
   entry would only surface on a fresh host install; cheap to catch
   here.
2. The orchestrator unit must ship the ``DECNET_REALISM_*`` env block
   so the LLM enrichment + persona-pool path are configurable per
   host without editing the .j2.
"""
from __future__ import annotations

from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent.parent
DEPLOY = REPO / "deploy"


@pytest.fixture
def unit_text() -> str:
    return (DEPLOY / "decnet-orchestrator.service.j2").read_text()


@pytest.fixture
def target_text() -> str:
    return (DEPLOY / "decnet.target").read_text()


# ── orchestrator unit ────────────────────────────────────────────────────────


def test_orchestrator_unit_exists():
    assert (DEPLOY / "decnet-orchestrator.service.j2").exists()


def test_orchestrator_unit_uses_orchestrate_subcommand(unit_text):
    assert "decnet orchestrate" in unit_text


def test_orchestrator_unit_has_docker_supplementary_group(unit_text):
    """SSHDriver shells `docker exec` against decky containers — without
    this group the worker can't reach the docker socket."""
    assert "SupplementaryGroups=docker" in unit_text


def test_orchestrator_unit_orders_after_bus(unit_text):
    """Bus must be up first so heartbeats publish from the start."""
    assert "After=network-online.target decnet-bus.service" in unit_text
    assert "Wants=network-online.target decnet-bus.service" in unit_text


def test_orchestrator_unit_has_security_hardening(unit_text):
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


def test_orchestrator_unit_writes_to_log_dir(unit_text):
    assert "/var/log/decnet/decnet.orchestrator.log" in unit_text
    assert "ReadWritePaths={{ install_dir }} /var/log/decnet" in unit_text


def test_orchestrator_unit_restart_on_failure(unit_text):
    assert "Restart=on-failure" in unit_text


def test_orchestrator_unit_carries_realism_env_block(unit_text):
    """Stage 5 + 6 contract: the orchestrator's LLM enrichment and
    persona-pool path are configured per host via DECNET_REALISM_*
    env vars.  Shipping them in the .j2 means an operator who never
    drops a .env.local still gets sane defaults."""
    for var in (
        "DECNET_REALISM_LLM",
        "DECNET_REALISM_MODEL",
        "DECNET_REALISM_TIMEOUT",
        "DECNET_REALISM_PERSONAS",
    ):
        assert var in unit_text, f"missing {var} in unit"


def test_orchestrator_unit_does_not_carry_legacy_emailgen_envs(unit_text):
    """Pre-v1 clean break per the realism migration: the
    DECNET_EMAILGEN_* env vars are no longer read.  Carrying them in
    the unit would mislead operators into thinking they still apply."""
    for legacy in (
        "DECNET_EMAILGEN_LLM",
        "DECNET_EMAILGEN_MODEL",
        "DECNET_EMAILGEN_TIMEOUT",
        "DECNET_EMAILGEN_PERSONAS",
    ):
        assert legacy not in unit_text, (
            f"legacy env {legacy} still referenced; clean-break broken"
        )


# ── decnet.target ────────────────────────────────────────────────────────────


def test_target_wants_orchestrator(target_text):
    assert "decnet-orchestrator.service" in target_text


def test_target_does_not_want_emailgen(target_text):
    """Stage 5 of the realism migration deleted decnet-emailgen.service.
    A fresh `decnet init` against a target file that still mentions it
    fails systemctl start with `Unit decnet-emailgen.service could not
    be found`, blocking the whole target.  Anti-regression."""
    assert "decnet-emailgen.service" not in target_text


def test_target_wants_canary(target_text):
    """Canary worker is a peer of orchestrator; both are part of the
    realism + callback story.  Bundle check."""
    assert "decnet-canary.service" in target_text


def test_target_orders_after_bus(target_text):
    """Whole target depends on the bus being up."""
    assert "After=decnet-bus.service" in target_text


# ── unit file no longer exists ───────────────────────────────────────────────


def test_emailgen_unit_template_is_gone():
    """The pre-collapse ``deploy/decnet-emailgen.service.j2`` must stay
    deleted.  A future commit that re-creates it (e.g. by accident
    during a partial revert) would break the realism migration's
    service-collapse contract."""
    assert not (DEPLOY / "decnet-emailgen.service.j2").exists(), (
        "decnet-emailgen.service.j2 reappeared — service collapse undone?"
    )
