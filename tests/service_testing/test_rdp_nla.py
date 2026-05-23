# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the RDP NLA / CredSSP credential-capture path.

The TLS layer is exercised end-to-end in deploy verification; here we
unit-test the inner pieces: DER length reader, TSRequest builder,
TSRequest reader, and the ``_handle_nla`` loop driving canned CredSSP
DER bytes carrying NTLMSSP Type 1 / Type 3 messages.
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


def _load_rdp(*, enable_nla: bool = True, monkeypatch=None):
    if monkeypatch is not None:
        if enable_nla:
            monkeypatch.setenv("RDP_ENABLE_NLA", "true")
        else:
            monkeypatch.delenv("RDP_ENABLE_NLA", raising=False)
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


# ── Helpers ───────────────────────────────────────────────────────────────────


def _ntlmssp_type1() -> bytes:
    return b"NTLMSSP\x00" + struct.pack("<I", 1) + struct.pack("<I", 0xE2088297) + b"\x00" * 24


def _ntlmssp_type3(username: str, domain: str, nt_response: bytes) -> bytes:
    user_b = username.encode("utf-16-le")
    dom_b = domain.encode("utf-16-le")
    payload = nt_response + dom_b + user_b
    nt_off = 72
    dom_off = nt_off + len(nt_response)
    user_off = dom_off + len(dom_b)
    ws_off = user_off + len(user_b)
    flags = 0x00000001
    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 3)
        + struct.pack("<HHI", 0, 0, ws_off)
        + struct.pack("<HHI", len(nt_response), len(nt_response), nt_off)
        + struct.pack("<HHI", len(dom_b), len(dom_b), dom_off)
        + struct.pack("<HHI", len(user_b), len(user_b), user_off)
        + struct.pack("<HHI", 0, 0, ws_off)
        + struct.pack("<HHI", 0, 0, ws_off)
        + struct.pack("<I", flags)
        + b"\x00" * 8
        + payload
    )


def _make_writer():
    writer = MagicMock()
    written: list[bytes] = []
    writer.write.side_effect = written.append

    async def _drained():
        return None

    writer.drain = _drained
    return writer, written


# ── Builder / reader unit tests ───────────────────────────────────────────────


def test_der_len_short_form(monkeypatch):
    mod = _load_rdp(monkeypatch=monkeypatch)
    assert mod._der_len(0) == b"\x00"
    assert mod._der_len(0x7F) == b"\x7f"


def test_der_len_long_form(monkeypatch):
    mod = _load_rdp(monkeypatch=monkeypatch)
    assert mod._der_len(0x80) == b"\x81\x80"
    assert mod._der_len(0x100) == b"\x82\x01\x00"


def test_tsrequest_with_token_round_trip(monkeypatch):
    mod = _load_rdp(monkeypatch=monkeypatch)
    payload = b"NTLMSSP\x00" + b"\x02" + b"\x00" * 31
    blob = mod._build_tsrequest_with_token(version=6, ntlm_blob=payload)
    # Outer SEQUENCE
    assert blob[0] == 0x30
    # Find the inner OCTET STRING content, confirm payload is intact
    assert payload in blob


def test_read_one_tsrequest_returns_full_blob(monkeypatch):
    mod = _load_rdp(monkeypatch=monkeypatch)
    payload = mod._build_tsrequest_with_token(6, b"NTLMSSP\x00" + b"\x03" + b"\x00" * 200)

    async def _run():
        reader = asyncio.StreamReader()
        reader.feed_data(payload)
        reader.feed_eof()
        return await mod._read_one_tsrequest(reader)

    out = asyncio.run(_run())
    assert out == payload


def test_read_one_tsrequest_rejects_oversized(monkeypatch):
    mod = _load_rdp(monkeypatch=monkeypatch)
    # Hand-craft a SEQUENCE with body length > MAX_TSREQUEST_LEN
    over = mod.MAX_TSREQUEST_LEN + 1
    bad = b"\x30\x84" + over.to_bytes(4, "big")  # 4-byte length

    async def _run():
        reader = asyncio.StreamReader()
        reader.feed_data(bad)
        reader.feed_eof()
        with pytest.raises(ValueError):
            await mod._read_one_tsrequest(reader)

    asyncio.run(_run())


# ── _handle_nla integration ───────────────────────────────────────────────────


def test_type1_then_type3_captures_credential(monkeypatch):
    mod = _load_rdp(monkeypatch=monkeypatch)
    log_mock = sys.modules["syslog_bridge"]
    nt_response = b"\xcc" * 32
    ts1 = mod._build_tsrequest_with_token(6, _ntlmssp_type1())
    ts3 = mod._build_tsrequest_with_token(6, _ntlmssp_type3("alice", "ACME", nt_response))

    async def _run():
        reader = asyncio.StreamReader()
        reader.feed_data(ts1 + ts3)
        reader.feed_eof()
        writer, written = _make_writer()
        await mod._handle_nla(reader, writer, "192.0.2.5", 51000)
        return written

    written = asyncio.run(_run())
    # Server replied to Type 1 with a Type 2 challenge wrapped in TSRequest
    assert written, "expected a TSRequest response to Type 1"
    resp = b"".join(written)
    assert b"NTLMSSP\x00" in resp
    type_byte = resp[resp.index(b"NTLMSSP\x00") + 8]
    assert type_byte == 0x02

    auth_calls = [
        c for c in log_mock.syslog_line.call_args_list
        if len(c.args) >= 3 and c.args[2] == "auth_attempt"
    ]
    assert auth_calls
    kwargs = auth_calls[0].kwargs
    assert kwargs["principal"] == "ACME\\alice"
    assert kwargs["secret_kind"] == "ntlmssp_v2"
    assert kwargs["auth_path"] == "nla"


def test_handle_nla_returns_cleanly_on_garbage(monkeypatch):
    mod = _load_rdp(monkeypatch=monkeypatch)

    async def _run():
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x00\x01\x02\x03not a sequence")
        reader.feed_eof()
        writer, _ = _make_writer()
        await mod._handle_nla(reader, writer, "198.51.100.9", 1234)

    asyncio.run(_run())  # must not raise


def test_per_instance_challenge_is_not_constant_across_node_names(monkeypatch):
    monkeypatch.setenv("NODE_NAME", "decky-alpha")
    monkeypatch.setenv("RDP_ENABLE_NLA", "true")
    mod_a = _load_rdp(monkeypatch=monkeypatch)
    chal_a = mod_a.SERVER_CHALLENGE

    monkeypatch.setenv("NODE_NAME", "decky-bravo")
    mod_b = _load_rdp(monkeypatch=monkeypatch)
    chal_b = mod_b.SERVER_CHALLENGE

    assert chal_a != chal_b
    assert len(chal_a) == 8 and len(chal_b) == 8
