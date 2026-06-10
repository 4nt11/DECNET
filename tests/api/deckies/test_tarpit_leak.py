# SPDX-License-Identifier: AGPL-3.0-or-later
"""V7.1.2 regression: tarpit endpoints must NOT leak raw tc stderr to API callers.

Covers both fleet (deckies) and topology tarpit paths.  Forces a tc failure
by monkeypatching _apply_tarpit / _remove_tarpit to raise RuntimeError with
a realistic iproute2/kernel error string (veth name, qdisc id, errno text),
then asserts:

  1. Status code is 409.
  2. The response body detail is a generic string.
  3. The response body contains NO raw tc output — no veth names, no
     "RTNETLINK", no kernel errno strings, no qdisc identifiers.
"""
from __future__ import annotations

import pytest
import httpx

from decnet.web.router.deckies import api_tarpit as _deckies_tarpit
from decnet.web.router.topology import api_tarpit as _topology_tarpit

_FLEET_URL = "/api/v1/deckies/web1/tarpit"
_TOPO_URL = "/api/v1/topologies/topo1/deckies/web1/tarpit"

# Realistic iproute2 stderr fragments — must NOT appear in any API response.
_TC_STDERR_FRAGMENTS = [
    "RTNETLINK",
    "veth",
    "qdisc",
    "Cannot find device",
    "No such file or directory",
    "Error: Exclusivity flag on, cannot modify.",
    "NLMSG_ERROR",
    "errno",
]

# Realistic docker exec / runtime stderr fragments that must NOT leak via the
# get_container_veth LookupError path (V7.1.2 — 404 path).
_DOCKER_STDERR_FRAGMENTS = [
    "Error response from daemon",
    "No such container",
    "OCI runtime",
    "exec failed",
    "permission denied",
]

_TARPIT_BODY = {"ports": [22, 80], "delay_ms": 500}


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _assert_no_tc_leak(body: dict) -> None:
    """Assert that the response detail contains no raw tc/kernel output."""
    detail = str(body.get("detail", ""))
    for fragment in _TC_STDERR_FRAGMENTS:
        assert fragment not in detail, (
            f"V7.1.2 leak: raw tc stderr fragment {fragment!r} found in API response: {detail!r}"
        )


# ── fleet / deckies ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fleet_enable_tarpit_tc_failure_returns_generic_detail(
    client: httpx.AsyncClient,
    auth_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST fleet tarpit with forced tc failure yields 409 + generic detail."""

    def _fake_apply(veth: str, ports: list[int], delay_ms: int) -> None:
        raise RuntimeError(
            "RTNETLINK answers: File exists\n"
            f"Error: Exclusivity flag on, cannot modify. veth={veth} qdisc=1:"
        )

    monkeypatch.setattr(_deckies_tarpit, "_apply_tarpit", _fake_apply)

    # Also patch get_container_veth so the 404 path doesn't fire first.
    monkeypatch.setattr(
        _deckies_tarpit,
        "get_container_veth",
        lambda name: f"veth-{name}-abc123",
    )

    res = await client.post(_FLEET_URL, json=_TARPIT_BODY, headers=_hdr(auth_token))
    assert res.status_code == 409, res.text
    _assert_no_tc_leak(res.json())


@pytest.mark.asyncio
async def test_fleet_disable_tarpit_tc_failure_returns_generic_detail(
    client: httpx.AsyncClient,
    auth_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DELETE fleet tarpit with forced tc failure yields 409 + generic detail."""

    def _fake_remove(veth: str) -> bool:
        raise RuntimeError(
            f"RTNETLINK answers: No such file or directory\nveth={veth}"
        )

    monkeypatch.setattr(_deckies_tarpit, "_remove_tarpit", _fake_remove)
    monkeypatch.setattr(
        _deckies_tarpit,
        "get_container_veth",
        lambda name: f"veth-{name}-abc123",
    )

    res = await client.delete(_FLEET_URL, headers=_hdr(auth_token))
    assert res.status_code == 409, res.text
    _assert_no_tc_leak(res.json())


# ── topology ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_topology_enable_tarpit_tc_failure_returns_generic_detail(
    client: httpx.AsyncClient,
    auth_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST topology tarpit with forced tc failure yields 409 + generic detail."""

    def _fake_apply(veth: str, ports: list[int], delay_ms: int) -> None:
        raise RuntimeError(
            f"RTNETLINK answers: File exists\nveth={veth} qdisc=1: NLMSG_ERROR errno=17"
        )

    monkeypatch.setattr(_topology_tarpit, "_apply_tarpit", _fake_apply)

    async def _fake_resolve(repo, decky_name, *, topology_id):
        return f"decnet_t_{decky_name}"

    monkeypatch.setattr(
        _topology_tarpit,
        "resolve_decky_container",
        _fake_resolve,
    )
    monkeypatch.setattr(
        _topology_tarpit,
        "get_container_veth",
        lambda name: f"veth-{name}-abc123",
    )

    res = await client.post(_TOPO_URL, json=_TARPIT_BODY, headers=_hdr(auth_token))
    assert res.status_code == 409, res.text
    _assert_no_tc_leak(res.json())


@pytest.mark.asyncio
async def test_topology_disable_tarpit_tc_failure_returns_generic_detail(
    client: httpx.AsyncClient,
    auth_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DELETE topology tarpit with forced tc failure yields 409 + generic detail."""

    def _fake_remove(veth: str) -> bool:
        raise RuntimeError(
            f"RTNETLINK answers: No such file or directory\nveth={veth} errno=2"
        )

    monkeypatch.setattr(_topology_tarpit, "_remove_tarpit", _fake_remove)

    async def _fake_resolve(repo, decky_name, *, topology_id):
        return f"decnet_t_{decky_name}"

    monkeypatch.setattr(
        _topology_tarpit,
        "resolve_decky_container",
        _fake_resolve,
    )
    monkeypatch.setattr(
        _topology_tarpit,
        "get_container_veth",
        lambda name: f"veth-{name}-abc123",
    )

    res = await client.delete(_TOPO_URL, headers=_hdr(auth_token))
    assert res.status_code == 409, res.text
    _assert_no_tc_leak(res.json())


# ── veth LookupError 404 path (V7.1.2 — docker stderr must not leak) ────────


def _assert_no_docker_stderr_leak(body: dict) -> None:
    """Assert that the response detail contains no raw docker/runtime output."""
    detail = str(body.get("detail", ""))
    for fragment in _DOCKER_STDERR_FRAGMENTS:
        assert fragment not in detail, (
            f"V7.1.2 leak: raw docker stderr fragment {fragment!r} found in 404 detail: {detail!r}"
        )
    # The detail must NOT contain a colon-separated suffix (i.e. no ': <stderr>')
    # — generic message ends with 'not reachable', nothing after.
    assert "Error response from daemon" not in detail
    assert "OCI runtime" not in detail


@pytest.mark.asyncio
async def test_fleet_enable_tarpit_veth_failure_does_not_leak_stderr(
    client: httpx.AsyncClient,
    auth_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST fleet tarpit: veth LookupError 404 must not expose docker stderr."""

    def _fake_veth(name: str) -> str:
        raise LookupError(f"container {name!r} not reachable")

    monkeypatch.setattr(_deckies_tarpit, "get_container_veth", _fake_veth)

    res = await client.post(_FLEET_URL, json=_TARPIT_BODY, headers=_hdr(auth_token))
    assert res.status_code == 404, res.text
    body = res.json()
    detail = str(body.get("detail", ""))
    # Generic message present, no docker runtime fragments
    assert "not reachable" in detail
    _assert_no_docker_stderr_leak(body)
    # Specifically assert the colon+stderr suffix is absent
    assert ":" not in detail.split("not reachable", 1)[-1]


@pytest.mark.asyncio
async def test_fleet_disable_tarpit_veth_failure_does_not_leak_stderr(
    client: httpx.AsyncClient,
    auth_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DELETE fleet tarpit: veth LookupError 404 must not expose docker stderr."""

    def _fake_veth(name: str) -> str:
        raise LookupError(f"container {name!r} not reachable")

    monkeypatch.setattr(_deckies_tarpit, "get_container_veth", _fake_veth)

    res = await client.delete(_FLEET_URL, headers=_hdr(auth_token))
    assert res.status_code == 404, res.text
    body = res.json()
    detail = str(body.get("detail", ""))
    assert "not reachable" in detail
    _assert_no_docker_stderr_leak(body)
    assert ":" not in detail.split("not reachable", 1)[-1]


@pytest.mark.asyncio
async def test_topology_enable_tarpit_veth_failure_does_not_leak_stderr(
    client: httpx.AsyncClient,
    auth_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST topology tarpit: veth LookupError 404 must not expose docker stderr."""

    def _fake_veth(name: str) -> str:
        raise LookupError(f"container {name!r} not reachable")

    async def _fake_resolve(repo, decky_name, *, topology_id):
        return f"decnet_t_{decky_name}"

    monkeypatch.setattr(_topology_tarpit, "resolve_decky_container", _fake_resolve)
    monkeypatch.setattr(_topology_tarpit, "get_container_veth", _fake_veth)

    res = await client.post(_TOPO_URL, json=_TARPIT_BODY, headers=_hdr(auth_token))
    assert res.status_code == 404, res.text
    body = res.json()
    detail = str(body.get("detail", ""))
    assert "not reachable" in detail
    _assert_no_docker_stderr_leak(body)
    assert ":" not in detail.split("not reachable", 1)[-1]
