# SPDX-License-Identifier: AGPL-3.0-or-later
"""Worker agent re-localizes master-built configs to its own NIC/subnet.

The master ships a DecnetConfig populated from *its own* network (master
NIC name, master subnet, master-chosen decky IPs).  The worker cannot run
the deployer against that as-is: `ip addr show <master-nic>` blows up on
any worker whose NIC differs from the master's, which is ~always the
case in a heterogeneous fleet.

The agent's executor overrides interface/subnet/gateway/host_ip with
locally-detected values before calling into the deployer, and if the
subnet doesn't match, it re-allocates decky IPs from the local subnet.
"""
from __future__ import annotations

import pytest

from decnet.agent import executor
from decnet.models import DecnetConfig, DeckyConfig


def _cfg(subnet: str, interface: str = "wlp6s0") -> DecnetConfig:
    return DecnetConfig(
        mode="swarm",
        interface=interface,
        subnet=subnet,
        gateway=subnet.rsplit(".", 1)[0] + ".1",
        deckies=[
            DeckyConfig(
                name=f"decky-0{i}",
                ip=subnet.rsplit(".", 1)[0] + f".{10 + i}",
                services=["ssh"],
                distro="debian",
                base_image="debian:bookworm-slim",
                hostname=f"decky-0{i}",
            )
            for i in range(1, 3)
        ],
    )


def test_relocalize_swaps_interface_and_subnet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "detect_interface", lambda: "enp0s3")
    monkeypatch.setattr(executor, "detect_subnet", lambda _i: ("10.0.0.0/24", "10.0.0.1"))
    monkeypatch.setattr(executor, "get_host_ip", lambda _i: "10.0.0.99")
    monkeypatch.setattr(
        executor, "allocate_ips",
        lambda **kw: [f"10.0.0.{20 + i}" for i in range(kw["count"])],
    )

    incoming = _cfg("192.168.1.0/24")
    out = executor._relocalize(incoming)

    assert out.interface == "enp0s3"
    assert out.subnet == "10.0.0.0/24"
    assert out.gateway == "10.0.0.1"
    # Subnet changed → IPs re-allocated from the worker's subnet.
    assert [d.ip for d in out.deckies] == ["10.0.0.20", "10.0.0.21"]
    # Non-network fields survive.
    assert [d.name for d in out.deckies] == ["decky-01", "decky-02"]
    assert [d.services for d in out.deckies] == [["ssh"], ["ssh"]]


def test_relocalize_keeps_ips_when_subnet_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "detect_interface", lambda: "enp0s3")
    monkeypatch.setattr(executor, "detect_subnet", lambda _i: ("192.168.1.0/24", "192.168.1.1"))
    monkeypatch.setattr(executor, "get_host_ip", lambda _i: "192.168.1.50")
    # allocate_ips should NOT be called in the matching-subnet branch.
    def _fail(**_kw):  # pragma: no cover
        raise AssertionError("allocate_ips must not be called when subnets match")
    monkeypatch.setattr(executor, "allocate_ips", _fail)

    incoming = _cfg("192.168.1.0/24")
    out = executor._relocalize(incoming)

    assert out.interface == "enp0s3"
    assert out.subnet == "192.168.1.0/24"
    # Decky IPs preserved verbatim.
    assert [d.ip for d in out.deckies] == ["192.168.1.11", "192.168.1.12"]


@pytest.mark.asyncio
async def test_deploy_relocalizes_before_calling_deployer(monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: agent.deploy(..) must not pass the master's interface
    through to the blocking deployer."""
    monkeypatch.setattr(executor, "detect_interface", lambda: "enp0s3")
    monkeypatch.setattr(executor, "detect_subnet", lambda _i: ("192.168.1.0/24", "192.168.1.1"))
    monkeypatch.setattr(executor, "get_host_ip", lambda _i: "192.168.1.50")

    seen: dict = {}

    def _fake_deploy(cfg, dry_run, no_cache, parallel):
        seen["interface"] = cfg.interface
        seen["subnet"] = cfg.subnet

    monkeypatch.setattr(executor._deployer, "deploy", _fake_deploy)

    await executor.deploy(_cfg("192.168.1.0/24", interface="wlp6s0-master"), dry_run=True)
    assert seen == {"interface": "enp0s3", "subnet": "192.168.1.0/24"}


@pytest.mark.asyncio
async def test_deploy_unihost_mode_skips_relocalize(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unihost configs have already been built against the local box — we
    must not second-guess them."""
    def _fail(*_a, **_kw):  # pragma: no cover
        raise AssertionError("detect_interface must not be called for unihost")
    monkeypatch.setattr(executor, "detect_interface", _fail)

    captured: dict = {}

    def _fake_deploy(cfg, dry_run, no_cache, parallel):
        captured["interface"] = cfg.interface

    monkeypatch.setattr(executor._deployer, "deploy", _fake_deploy)

    cfg = _cfg("192.168.1.0/24", interface="eth0").model_copy(update={"mode": "unihost"})
    await executor.deploy(cfg, dry_run=True)
    assert captured["interface"] == "eth0"
