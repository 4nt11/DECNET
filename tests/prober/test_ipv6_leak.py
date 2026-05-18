"""Active IPv6 link-local solicitation prober tests.

Tests _ipv6_leak_phase() via monkeypatching — no actual scapy send/receive,
no sniff threads.  Validates:
- Phase skips when attacker is not on-link.
- Phase skips on second call (dedup via ip_probed sentinel).
- Phase emits log + publish_fn when solicit_ipv6_leak returns evidence.
- Phase is silent when solicit_ipv6_leak returns None.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch


def _phase(
    ip: str = "10.0.0.9",
    ip_probed: dict | None = None,
    log_path: Path | None = None,
    json_path: Path | None = None,
    timeout: float = 1.0,
    publish_fn=None,
):
    from decnet.prober.worker import _ipv6_leak_phase
    if ip_probed is None:
        ip_probed = {}
    if log_path is None:
        log_path = Path("/dev/null")
    if json_path is None:
        json_path = Path("/dev/null")
    _ipv6_leak_phase(ip, ip_probed, log_path, json_path, timeout, publish_fn)


_EVIDENCE = {
    "addr": "fe80::aabb:ccff:fedd:eeff",
    "mac_oui": "a8:bb:cc",
    "iid_kind": "eui64",
    "vector": "active_echo",
    "on_iface": "eth0",
    "attacker_v4": "10.0.0.9",
    "observed_at": "2026-01-01T00:00:00+00:00",
}


def test_phase_skips_when_not_on_link() -> None:
    published: list[Any] = []
    with (
        patch("decnet.prober.ipv6_leak._is_on_link", return_value=False),
        patch("decnet.prober.ipv6_leak._resolve_iface_for_ip", return_value="eth0"),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", return_value=_EVIDENCE) as mock_sol,
    ):
        _phase(publish_fn=lambda k, p: published.append((k, p)))
    mock_sol.assert_not_called()
    assert published == []


def test_phase_skips_when_no_iface() -> None:
    published: list[Any] = []
    with (
        patch("decnet.prober.ipv6_leak._is_on_link", return_value=True),
        patch("decnet.prober.ipv6_leak._resolve_iface_for_ip", return_value=None),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", return_value=_EVIDENCE) as mock_sol,
    ):
        _phase(publish_fn=lambda k, p: published.append((k, p)))
    mock_sol.assert_not_called()
    assert published == []


def test_phase_emits_on_evidence() -> None:
    published: list[Any] = []
    with (
        patch("decnet.prober.ipv6_leak._is_on_link", return_value=True),
        patch("decnet.prober.ipv6_leak._resolve_iface_for_ip", return_value="eth0"),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", return_value=_EVIDENCE),
    ):
        _phase(publish_fn=lambda k, p: published.append((k, p)))
    assert len(published) == 1
    kind, payload = published[0]
    assert kind == "ipv6_leak"
    assert payload["addr"] == _EVIDENCE["addr"]
    assert payload["iid_kind"] == "eui64"
    assert payload["mac_oui"] == "a8:bb:cc"


def test_phase_silent_when_solicit_returns_none() -> None:
    published: list[Any] = []
    with (
        patch("decnet.prober.ipv6_leak._is_on_link", return_value=True),
        patch("decnet.prober.ipv6_leak._resolve_iface_for_ip", return_value="eth0"),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", return_value=None),
    ):
        _phase(publish_fn=lambda k, p: published.append((k, p)))
    assert published == []


def test_phase_dedup_skips_on_second_call() -> None:
    published: list[Any] = []
    ip_probed: dict = {}
    with (
        patch("decnet.prober.ipv6_leak._is_on_link", return_value=True),
        patch("decnet.prober.ipv6_leak._resolve_iface_for_ip", return_value="eth0"),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", return_value=_EVIDENCE) as mock_sol,
    ):
        _phase(ip_probed=ip_probed, publish_fn=lambda k, p: published.append((k, p)))
        _phase(ip_probed=ip_probed, publish_fn=lambda k, p: published.append((k, p)))
    # solicit called only once despite two phase invocations
    mock_sol.assert_called_once()
    assert len(published) == 1


def test_phase_handles_solicit_exception_silently() -> None:
    published: list[Any] = []
    with (
        patch("decnet.prober.ipv6_leak._is_on_link", return_value=True),
        patch("decnet.prober.ipv6_leak._resolve_iface_for_ip", return_value="eth0"),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", side_effect=RuntimeError("boom")),
    ):
        _phase(publish_fn=lambda k, p: published.append((k, p)))
    assert published == []
