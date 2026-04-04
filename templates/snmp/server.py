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
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "switch")
SERVICE_NAME   = "snmp"
LOG_TARGET = os.environ.get("LOG_TARGET", "")

# OID value map — fake but plausible
_OID_VALUES = {
    "1.3.6.1.2.1.1.1.0": f"Linux {NODE_NAME} 5.15.0-76-generic #83-Ubuntu SMP x86_64",
    "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.8072.3.2.10",
    "1.3.6.1.2.1.1.3.0": "12345678",  # sysUpTime
    "1.3.6.1.2.1.1.4.0": "admin@localhost",
    "1.3.6.1.2.1.1.5.0": NODE_NAME,
    "1.3.6.1.2.1.1.6.0": "Server Room",
    "1.3.6.1.2.1.1.7.0": "72",
}




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    print(line, flush=True)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


def _read_ber_length(data: bytes, pos: int):
    b = data[pos]
    if b < 0x80:
        return b, pos + 1
    n = b & 0x7f
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
    assert data[pos] == 0x30
    pos += 1
    _, pos = _read_ber_length(data, pos)
    # version
    assert data[pos] == 0x02
    pos += 1
    v_len, pos = _read_ber_length(data, pos)
    version = int.from_bytes(data[pos:pos + v_len], "big")
    pos += v_len
    # community
    assert data[pos] == 0x04
    pos += 1
    c_len, pos = _read_ber_length(data, pos)
    community = data[pos:pos + c_len].decode(errors="replace")
    pos += c_len
    # PDU type (0xa0 = GetRequest, 0xa1 = GetNextRequest)
    pos += 1
    _, pos = _read_ber_length(data, pos)
    # request-id
    assert data[pos] == 0x02
    pos += 1
    r_len, pos = _read_ber_length(data, pos)
    request_id = int.from_bytes(data[pos:pos + r_len], "big")
    pos += r_len
    pos += 4  # skip error-status and error-index
    # varbind list
    assert data[pos] == 0x30
    pos += 1
    vbl_len, pos = _read_ber_length(data, pos)
    end = pos + vbl_len
    oids = []
    while pos < end:
        assert data[pos] == 0x30
        pos += 1
        vb_len, pos = _read_ber_length(data, pos)
        assert data[pos] == 0x06
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
            _log("parse_error", src=addr[0], error=str(e), data=data[:64].hex())

    def error_received(self, exc):
        pass


async def main():
    _log("startup", msg=f"SNMP server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        SNMPProtocol, local_addr=("0.0.0.0", 161)
    )
    try:
        await asyncio.sleep(float("inf"))
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())
