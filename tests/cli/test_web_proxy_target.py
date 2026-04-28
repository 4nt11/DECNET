"""The web dashboard proxy must follow DECNET_API_HOST.

Hardcoding 127.0.0.1 broke deploys where the operator binds the API to
a specific tailnet/VPN address: the API drops loopback entirely and the
proxy gets ECONNREFUSED. Wildcard binds still proxy via loopback because
both processes share the host.
"""
from __future__ import annotations

from decnet.cli.web import _proxy_target


def test_loopback_passthrough() -> None:
    assert _proxy_target("127.0.0.1") == "127.0.0.1"


def test_wildcard_v4_falls_back_to_loopback() -> None:
    assert _proxy_target("0.0.0.0") == "127.0.0.1"


def test_wildcard_v6_falls_back_to_loopback() -> None:
    assert _proxy_target("::") == "127.0.0.1"


def test_empty_falls_back_to_loopback() -> None:
    assert _proxy_target("") == "127.0.0.1"


def test_specific_address_is_followed() -> None:
    # The case that was broken: API bound only on tailnet IP, proxy
    # tried loopback and got ECONNREFUSED.
    assert _proxy_target("100.64.1.7") == "100.64.1.7"


def test_hostname_is_followed() -> None:
    assert _proxy_target("decnet-master.tailnet.ts.net") == "decnet-master.tailnet.ts.net"
