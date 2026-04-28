"""Sanity check on the decnet-canary.service unit + decnet.target.

Tests are deliberately static (no rendering, no systemd) — they just
confirm the unit file exists, references the canary CLI command, is
included in the master target, and follows the same security
hardening posture as decnet-webhook.service.
"""
from __future__ import annotations

from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"


def test_canary_unit_exists() -> None:
    assert (DEPLOY / "decnet-canary.service.j2").exists()


def test_canary_unit_runs_decnet_canary() -> None:
    body = (DEPLOY / "decnet-canary.service.j2").read_text()
    assert "{{ venv_dir }}/bin/decnet canary" in body
    assert "After=" in body and "decnet-bus.service" in body


def test_canary_unit_has_security_hardening() -> None:
    """Canary handles attacker traffic — must mirror webhook's hardening."""
    body = (DEPLOY / "decnet-canary.service.j2").read_text()
    for required in (
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
        assert required in body, f"missing hardening directive: {required}"


def test_canary_listed_in_master_target() -> None:
    body = (DEPLOY / "decnet.target").read_text()
    assert "decnet-canary.service" in body
