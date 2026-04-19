#!/usr/bin/env python3
"""
SNMP server (UDP 161).
Parses SNMPv1/v2c GetRequest PDUs, logs the community string and OID list,
then responds with a GetResponse containing plausible system OID values.
Logs all requests as JSON.
"""

import asyncio
import os
import struct
from syslog_bridge import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "switch")
SERVICE_NAME   = "snmp"
LOG_TARGET = os.environ.get("LOG_TARGET", "")
SNMP_ARCHETYPE = os.environ.get("SNMP_ARCHETYPE", "default")


def _get_archetype_values() -> dict:
    archetypes = {
        "water_plant": {
            "sysDescr": f"Linux {NODE_NAME} 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64",
            "sysContact": "ICS Admin <ics-admin@plant.local>",
            "sysName": NODE_NAME,
            "sysLocation": "Water Treatment Facility — Pump Room B",
        },
        "factory": {
            "sysDescr": "VxWorks 6.9 (Rockwell Automation Allen-Bradley ControlLogix 5580)",
            "sysContact": "Factory Floor Support <support@factory.local>",
            "sysName": NODE_NAME,
            "sysLocation": "Factory Floor",
        },
        "substation": {
            "sysDescr": "SEL Real-Time Automation Controller RTAC SEL-3555 firmware 1.9.7.0",
            "sysContact": "Grid Ops <gridops@utility.local>",
            "sysName": NODE_NAME,
            "sysLocation": "Main Substation",
        },
        "hospital": {
            "sysDescr": f"Linux {NODE_NAME} 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 x86_64",
            "sysContact": "Medical IT <medit@hospital.local>",
            "sysName": NODE_NAME,
            "sysLocation": "ICU Ward 3",
        },
        "default": {
            "sysDescr": f"Linux {NODE_NAME} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64",
            "sysContact": "admin@localhost",
            "sysName": NODE_NAME,
            "sysLocation": "Server Room",
        }
    }
    return archetypes.get(SNMP_ARCHETYPE, archetypes["default"])

_arch = _get_archetype_values()

# OID value map — fake but plausible
_OID_VALUES = {
    "1.3.6.1.2.1.1.1.0": _arch["sysDescr"],
    "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.8072.3.2.10",
    "1.3.6.1.2.1.1.3.0": "12345678",  # sysUpTime
    "1.3.6.1.2.1.1.4.0": _arch["sysContact"],
    "1.3.6.1.2.1.1.5.0": _arch["sysName"],
    "1.3.6.1.2.1.1.6.0": _arch["sysLocation"],
    "1.3.6.1.2.1.1.7.0": "72",
}


def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


def _read_ber_length(data: bytes, pos: int):
    if pos >= len(data):
        raise ValueError("Unexpected end of data reading ASN.1 length")
    b = data[pos]
    if b < 0x80:
        return b, pos + 1
    n = b & 0x7f
    if pos + 1 + n > len(data):
        raise ValueError("BER length bytes truncated")
    length = int.from_bytes(data[pos + 1:pos + 1 + n], "big")
    return length, pos + 1 + n


def _decode_oid(data: bytes) -> str:
    if not data:
        return ""
    first = data[0]
    oid = [first // 40, first % 40]
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7f)
        if not (b & 0x80):
            oid.append(val)
            val = 0
    return ".".join(map(str, oid))


def _encode_oid(oid_str: str) -> bytes:
    parts = list(map(int, oid_str.split(".")))
    if len(parts) < 2:
        return b""
    result = bytes([parts[0] * 40 + parts[1]])
    for n in parts[2:]:
        if n == 0:
            result += b"\x00"
        else:
            encoded = []
            while n:
                encoded.append(n & 0x7f)
                n >>= 7
            encoded.reverse()
            for i, b in enumerate(encoded):
                result += bytes([b | (0x80 if i < len(encoded) - 1 else 0)])
    return result


def _ber_tlv(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    elif length < 0x100:
        return bytes([tag, 0x81, length]) + value
    else:
        return bytes([tag, 0x82]) + struct.pack(">H", length) + value


def _parse_snmp(data: bytes):
    """Return (version, community, request_id, oids) or raise."""
    pos = 0
    if len(data) == 0 or data[pos] != 0x30:
        raise ValueError("Not a valid ASN.1 sequence")
    pos += 1
    _, pos = _read_ber_length(data, pos)
    # version
    if pos >= len(data) or data[pos] != 0x02:
        raise ValueError("Expected SNMP version INTEGER")
    pos += 1
    v_len, pos = _read_ber_length(data, pos)
    version = int.from_bytes(data[pos:pos + v_len], "big")
    pos += v_len
    # community
    if pos >= len(data) or data[pos] != 0x04:
        raise ValueError("Expected SNMP community OCTET STREAM")
    pos += 1
    c_len, pos = _read_ber_length(data, pos)
    community = data[pos:pos + c_len].decode(errors="replace")
    pos += c_len
    # PDU type (0xa0 = GetRequest, 0xa1 = GetNextRequest)
    if pos >= len(data):
        raise ValueError("Missing PDU type")

    pdu_type = data[pos]
    if pdu_type not in (0xa0, 0xa1):
        raise ValueError(f"Invalid PDU type {pdu_type}")

    pos += 1
    _, pos = _read_ber_length(data, pos)
    # request-id
    if pos >= len(data) or data[pos] != 0x02:
        raise ValueError("Expected Request ID INTEGER")
    pos += 1
    r_len, pos = _read_ber_length(data, pos)
    request_id = int.from_bytes(data[pos:pos + r_len], "big")
    pos += r_len
    # skip error-status
    if pos >= len(data) or data[pos] != 0x02:
        raise ValueError("Expected error-status INTEGER")
    pos += 1
    e_len, pos = _read_ber_length(data, pos)
    pos += e_len
    # skip error-index
    if pos >= len(data) or data[pos] != 0x02:
        raise ValueError("Expected error-index INTEGER")
    pos += 1
    i_len, pos = _read_ber_length(data, pos)
    pos += i_len
    # varbind list
    if pos >= len(data) or data[pos] != 0x30:
        raise ValueError("Expected varbind list SEQUENCE")
    pos += 1
    vbl_len, pos = _read_ber_length(data, pos)
    end = pos + vbl_len
    oids = []
    while pos < end:
        if data[pos] != 0x30:
            raise ValueError("Expected varbind SEQUENCE")
        pos += 1
        vb_len, pos = _read_ber_length(data, pos)
        if data[pos] != 0x06:
            raise ValueError("Expected Object Identifier")
        pos += 1
        oid_len, pos = _read_ber_length(data, pos)
        oid = _decode_oid(data[pos:pos + oid_len])
        pos += oid_len
        oids.append(oid)
        pos += vb_len - oid_len - 2  # skip value
    return version, community, request_id, oids


def _build_response(version: int, community: str, request_id: int, oids: list) -> bytes:
    varbinds = b""
    for oid in oids:
        oid_enc = _encode_oid(oid)
        value_str = _OID_VALUES.get(oid, "")
        oid_tlv = _ber_tlv(0x06, oid_enc)
        val_tlv = _ber_tlv(0x04, value_str.encode())
        varbinds += _ber_tlv(0x30, oid_tlv + val_tlv)
    varbind_list = _ber_tlv(0x30, varbinds)
    req_id_tlv = _ber_tlv(0x02, request_id.to_bytes(4, "big"))
    error_status = _ber_tlv(0x02, b"\x00")
    error_index  = _ber_tlv(0x02, b"\x00")
    pdu = _ber_tlv(0xa2, req_id_tlv + error_status + error_index + varbind_list)
    ver_tlv = _ber_tlv(0x02, version.to_bytes(1, "big"))
    comm_tlv = _ber_tlv(0x04, community.encode())
    return _ber_tlv(0x30, ver_tlv + comm_tlv + pdu)


class SNMPProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self._transport = None

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        try:
            version, community, request_id, oids = _parse_snmp(data)
            _log("get_request", src=addr[0], src_port=addr[1],
                 version=version, community=community, oids=oids)
            response = _build_response(version, community, request_id, oids)
            self._transport.sendto(response, addr)
        except Exception as e:
            _log("parse_error", severity=4, src=addr[0], error=str(e), data=data[:64].hex())

    def error_received(self, exc):
        pass


async def main():
    _log("startup", msg=f"SNMP server starting as {NODE_NAME} with archetype {SNMP_ARCHETYPE}")
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        SNMPProtocol, local_addr=("0.0.0.0", 161)  # nosec B104
    )
    try:
        await asyncio.sleep(float("inf"))
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())
