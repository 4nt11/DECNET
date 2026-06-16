# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for decnet/templates/rdp/server.py — X.224 CR cookie capture.

Drives the asyncio handler with an in-memory StreamReader, asserts:
* mstshash cookie in CR is captured as principal/username.
* rdpNegRequest.requestedProtocols is recorded.
* X.224 Connection Confirm is well-formed and selects PROTOCOL_RDP.
* Malformed / oversized TPKT does not crash the handler.
"""
from __future__ import annotations

import asyncio
import importlib.util
import struct
import sys
from unittest.mock import MagicMock

import pytest

from .conftest import load_real_instance_seed, make_fake_syslog_bridge


# ── Module loader ─────────────────────────────────────────────────────────────


def _load_real_ntlmssp():
    spec = importlib.util.spec_from_file_location(
        "ntlmssp", "decnet/templates/_shared/ntlmssp.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_rdp():
    for key in ("rdp_server", "syslog_bridge", "instance_seed", "ntlmssp"):
        sys.modules.pop(key, None)
    sys.modules["syslog_bridge"] = make_fake_syslog_bridge()
    sys.modules["instance_seed"] = load_real_instance_seed()
    sys.modules["ntlmssp"] = _load_real_ntlmssp()
    spec = importlib.util.spec_from_file_location(
        "rdp_server", "decnet/templates/rdp/server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def rdp_mod():
    return _load_rdp()


# ── PDU builders ──────────────────────────────────────────────────────────────


def _x224_connection_request(cookie: str | None = None, requested_protocols: int | None = None) -> bytes:
    """Build TPKT(X.224 CR [+ Cookie] [+ rdpNegRequest])."""
    var = b""
    if cookie is not None:
        var += f"Cookie: mstshash={cookie}\r\n".encode("ascii")
    if requested_protocols is not None:
        var += (
            bytes([0x01, 0x00])
            + (8).to_bytes(2, "little")
            + requested_protocols.to_bytes(4, "little")
        )
    li = 6 + len(var)  # length indicator covers bytes after itself
    x224 = bytes([li, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]) + var
    tpkt = bytes([0x03, 0x00]) + (4 + len(x224)).to_bytes(2, "big")
    return tpkt + x224


def _make_streams():
    reader = asyncio.StreamReader()
    writer = MagicMock()
    written: list[bytes] = []
    writer.write.side_effect = written.append
    writer.get_extra_info.return_value = ("203.0.113.42", 49152)

    async def _drained():
        return None

    async def _wait_closed():
        return None

    writer.drain = _drained
    writer.wait_closed = _wait_closed
    return reader, writer, written


def _drive(rdp_mod, request_bytes: bytes):
    async def _run():
        reader, writer, written = _make_streams()
        reader.feed_data(request_bytes)
        reader.feed_eof()
        await asyncio.wait_for(rdp_mod._handle_client(reader, writer), timeout=2.0)
        return writer, written

    return asyncio.run(_run())


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_cookie_is_captured_as_principal():
    mod = _load_rdp()
    log_mock = sys.modules["syslog_bridge"]
    _drive(mod, _x224_connection_request(cookie="alice"))
    cookie_calls = [
        c for c in log_mock.syslog_line.call_args_list
        if len(c.args) >= 3 and c.args[2] == "rdp_cookie"
    ]
    assert cookie_calls, "expected an rdp_cookie event"
    kwargs = cookie_calls[0].kwargs
    assert kwargs["principal"] == "alice"
    assert kwargs["username"] == "alice"


def test_requested_protocols_recorded():
    mod = _load_rdp()
    log_mock = sys.modules["syslog_bridge"]
    _drive(mod, _x224_connection_request(cookie="bob", requested_protocols=0x03))  # SSL|HYBRID
    cookie_calls = [
        c for c in log_mock.syslog_line.call_args_list
        if len(c.args) >= 3 and c.args[2] == "rdp_cookie"
    ]
    assert cookie_calls
    assert cookie_calls[0].kwargs["requested_protocols"] == 0x03


def test_connection_confirm_well_formed(rdp_mod):
    _, written = _drive(rdp_mod, _x224_connection_request(cookie="charlie"))
    blob = b"".join(written)
    assert blob[0] == 0x03  # TPKT version
    total = int.from_bytes(blob[2:4], "big")
    assert total == len(blob)
    # X.224 CC type byte at offset 5
    assert blob[5] == 0xD0
    # rdpNegRsp begins at offset 11; SelectedProtocol at offset 15 (4 bytes LE)
    selected = int.from_bytes(blob[15:19], "little")
    assert selected == 0x00000000  # PROTOCOL_RDP


def test_no_cookie_still_replies(rdp_mod):
    _, written = _drive(rdp_mod, _x224_connection_request(cookie=None, requested_protocols=0x00))
    assert written, "server must still reply with X.224 CC even without cookie"
    blob = b"".join(written)
    assert blob[5] == 0xD0  # CC


def test_no_cookie_emits_connection_request_event():
    mod = _load_rdp()
    log_mock = sys.modules["syslog_bridge"]
    _drive(mod, _x224_connection_request(cookie=None))
    types = [
        c.args[2] for c in log_mock.syslog_line.call_args_list
        if len(c.args) >= 3
    ]
    assert "connection_request" in types
    assert "rdp_cookie" not in types


def test_oversized_tpkt_is_dropped(rdp_mod):
    # TPKT len = 65535 → above MAX_TPKT_LEN; handler must reject without
    # waiting for the full body.
    bad = bytes([0x03, 0x00, 0xFF, 0xFF])
    _, written = _drive(rdp_mod, bad)
    assert written == []


def test_non_tpkt_first_byte_is_dropped(rdp_mod):
    bad = b"\x16\x03\x01\x00\x10" + b"\x00" * 11  # looks like TLS ClientHello
    _, written = _drive(rdp_mod, bad)
    assert written == []
