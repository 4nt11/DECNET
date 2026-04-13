"""
Tests for templates/snmp/server.py

Exercises behavior with SNMP_ARCHETYPE modifications.
Uses asyncio DatagramProtocol directly.
"""

import importlib.util
import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_fake_decnet_logging() -> ModuleType:
    mod = ModuleType("decnet_logging")
    def syslog_line(*args, **kwargs):
        print("LOG:", args, kwargs)
        return ""
    mod.syslog_line = syslog_line
    mod.write_syslog_file = MagicMock()
    mod.forward_syslog = MagicMock()
    mod.SEVERITY_WARNING = 4
    mod.SEVERITY_INFO = 6
    return mod


def _load_snmp(archetype: str = "default"):
    env = {
        "NODE_NAME": "testhost",
        "SNMP_ARCHETYPE": archetype,
    }
    for key in list(sys.modules):
        if key in ("snmp_server", "decnet_logging"):
            del sys.modules[key]

    sys.modules["decnet_logging"] = _make_fake_decnet_logging()

    spec = importlib.util.spec_from_file_location("snmp_server", "templates/snmp/server.py")
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", env, clear=False):
        spec.loader.exec_module(mod)
    return mod


def _make_protocol(mod):
    proto = mod.SNMPProtocol()
    transport = MagicMock()
    sent: list[tuple] = []

    def sendto(data, addr):
        sent.append((data, addr))

    transport.sendto = sendto
    proto.connection_made(transport)
    sent.clear()
    return proto, transport, sent


def _send(proto, data: bytes, addr=("127.0.0.1", 12345)) -> None:
    proto.datagram_received(data, addr)

# ── Packet Helpers ────────────────────────────────────────────────────────────

def _ber_tlv(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    elif length < 0x100:
        return bytes([tag, 0x81, length]) + value
    else:
        return bytes([tag, 0x82]) + int.to_bytes(length, 2, "big") + value

def _get_request_packet(community: str, request_id: int, oid_enc: bytes) -> bytes:
    # Build a simple GetRequest for a single OID
    varbind = _ber_tlv(0x30, _ber_tlv(0x06, oid_enc) + _ber_tlv(0x05, b"")) # 0x05 is NULL
    varbind_list = _ber_tlv(0x30, varbind)
    req_id_tlv = _ber_tlv(0x02, request_id.to_bytes(4, "big"))
    err_stat = _ber_tlv(0x02, b"\x00")
    err_idx = _ber_tlv(0x02, b"\x00")
    pdu = _ber_tlv(0xa0, req_id_tlv + err_stat + err_idx + varbind_list)
    ver = _ber_tlv(0x02, b"\x01") # v2c
    comm = _ber_tlv(0x04, community.encode())
    return _ber_tlv(0x30, ver + comm + pdu)

# 1.3.6.1.2.1.1.1.0 = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
SYS_DESCR_OID_ENC = b"\x2b\x06\x01\x02\x01\x01\x01\x00"

# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def snmp_default():
    return _load_snmp()

@pytest.fixture
def snmp_water_plant():
    return _load_snmp("water_plant")


def test_sysdescr_default(snmp_default):
    proto, transport, sent = _make_protocol(snmp_default)
    packet = _get_request_packet("public", 1, SYS_DESCR_OID_ENC)
    _send(proto, packet)

    assert len(sent) == 1
    resp, addr = sent[0]
    assert addr == ("127.0.0.1", 12345)

    # default sysDescr has "Ubuntu SMP" in it
    assert b"Ubuntu SMP" in resp

def test_sysdescr_water_plant(snmp_water_plant):
    proto, transport, sent = _make_protocol(snmp_water_plant)
    packet = _get_request_packet("public", 2, SYS_DESCR_OID_ENC)
    _send(proto, packet)

    assert len(sent) == 1
    resp, _ = sent[0]

    assert b"Debian" in resp

# ── Negative Tests ────────────────────────────────────────────────────────────

def test_invalid_asn1_sequence(snmp_default):
    proto, transport, sent = _make_protocol(snmp_default)
    # 0x31 instead of 0x30
    _send(proto, b"\x31\x02\x00\x00")
    assert len(sent) == 0 # Caught and logged

def test_truncated_packet(snmp_default):
    proto, transport, sent = _make_protocol(snmp_default)
    packet = _get_request_packet("public", 3, SYS_DESCR_OID_ENC)
    _send(proto, packet[:10]) # chop it
    assert len(sent) == 0

def test_invalid_pdu_type(snmp_default):
    proto, transport, sent = _make_protocol(snmp_default)
    packet = _get_request_packet("public", 4, SYS_DESCR_OID_ENC).replace(b"\xa0", b"\xa3", 1)
    _send(proto, packet)
    assert len(sent) == 0

def test_bad_oid_encoding(snmp_default):
    proto, transport, sent = _make_protocol(snmp_default)
    _send(proto, b"\x30\x84\xff\xff\xff\xff")
    assert len(sent) == 0
