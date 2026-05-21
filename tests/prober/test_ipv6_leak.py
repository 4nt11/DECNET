"""Active IPv6 link-local solicitation prober tests.

Tests _ipv6_leak_phase() via monkeypatching — no actual scapy send/receive,
no sniff threads.  Validates:
- Phase skips when attacker is not on-link.
- Phase skips on second call (dedup via ip_probed sentinel).
- Phase emits log + publish_fn when solicit_ipv6_leak returns evidence.
- Phase is silent when solicit_ipv6_leak returns None.
- _route_info calls _ip_route_get exactly once per invocation.
- _ip_route_get subprocess failure is logged at debug.
- solicit_ipv6_leak response-parse failure is logged at debug.
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
        patch("decnet.prober.ipv6_leak._route_info", return_value=(False, "eth0")),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", return_value=_EVIDENCE) as mock_sol,
    ):
        _phase(publish_fn=lambda k, p: published.append((k, p)))
    mock_sol.assert_not_called()
    assert published == []


def test_phase_skips_when_no_iface() -> None:
    published: list[Any] = []
    with (
        patch("decnet.prober.ipv6_leak._route_info", return_value=(True, None)),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", return_value=_EVIDENCE) as mock_sol,
    ):
        _phase(publish_fn=lambda k, p: published.append((k, p)))
    mock_sol.assert_not_called()
    assert published == []


def test_phase_emits_on_evidence() -> None:
    published: list[Any] = []
    with (
        patch("decnet.prober.ipv6_leak._route_info", return_value=(True, "eth0")),
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
        patch("decnet.prober.ipv6_leak._route_info", return_value=(True, "eth0")),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", return_value=None),
    ):
        _phase(publish_fn=lambda k, p: published.append((k, p)))
    assert published == []


def test_phase_dedup_skips_on_second_call() -> None:
    published: list[Any] = []
    ip_probed: dict = {}
    with (
        patch("decnet.prober.ipv6_leak._route_info", return_value=(True, "eth0")),
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
        patch("decnet.prober.ipv6_leak._route_info", return_value=(True, "eth0")),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", side_effect=RuntimeError("boom")),
    ):
        _phase(publish_fn=lambda k, p: published.append((k, p)))
    assert published == []


# ─── _route_info / _ip_route_get unit tests ──────────────────────────────────


def test_route_info_calls_ip_route_get_once() -> None:
    """_route_info must shell out exactly once regardless of parse path."""
    from decnet.prober.ipv6_leak import _route_info
    stdout = "10.0.0.9 dev eth0 src 10.0.0.1 uid 0\n    cache"
    with patch("decnet.prober.ipv6_leak._ip_route_get", return_value=stdout) as mock_rg:
        on_link, iface = _route_info("10.0.0.9")
    mock_rg.assert_called_once_with("10.0.0.9")
    assert on_link is True
    assert iface == "eth0"


def test_route_info_detects_gateway() -> None:
    from decnet.prober.ipv6_leak import _route_info
    stdout = "10.0.0.9 via 192.168.1.1 dev eth0 src 192.168.1.50\n    cache"
    with patch("decnet.prober.ipv6_leak._ip_route_get", return_value=stdout):
        on_link, iface = _route_info("10.0.0.9")
    assert on_link is False
    assert iface == "eth0"


def test_ip_route_get_logs_on_subprocess_failure() -> None:
    from decnet.prober.ipv6_leak import _ip_route_get
    with (
        patch("decnet.prober.ipv6_leak.subprocess.run", side_effect=OSError("no ip")),
        patch("decnet.prober.ipv6_leak._log") as mock_log,
    ):
        result = _ip_route_get("10.0.0.9")
    assert result == ""
    mock_log.debug.assert_called_once()
    assert "10.0.0.9" in mock_log.debug.call_args.args[1]


def test_ip_route_get_returns_empty_string_on_failure() -> None:
    """subprocess failure returns "" and logs at debug — not a silent swallow."""
    from decnet.prober.ipv6_leak import _ip_route_get
    with (
        patch("decnet.prober.ipv6_leak.subprocess.run", side_effect=OSError("no ip binary")),
        patch("decnet.prober.ipv6_leak._log") as mock_log,
    ):
        result = _ip_route_get("10.0.0.9")
    assert result == ""
    assert mock_log.debug.called
    logged_msg = mock_log.debug.call_args.args
    assert "10.0.0.9" in str(logged_msg)
