#!/usr/bin/env python3
"""
LLMNR / mDNS poisoning detector (UDP 5355 and UDP 5353).
Listens for any incoming name-resolution queries. Any traffic here is a
strong signal of an attacker running Responder or similar tools on the LAN.
Logs every packet with source IP and decoded query name where possible.
"""

import asyncio
import os
import struct
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "lan-host")
SERVICE_NAME   = "llmnr"
LOG_TARGET = os.environ.get("LOG_TARGET", "")




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    print(line, flush=True)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


def _decode_dns_name(data: bytes, offset: int) -> str:
    """Decode a DNS-encoded label sequence starting at offset."""
    labels = []
    visited = set()
    pos = offset
    while pos < len(data):
        if pos in visited:
            break
        visited.add(pos)
        length = data[pos]
        if length == 0:
            break
        if length & 0xc0 == 0xc0:  # pointer
            if pos + 1 >= len(data):
                break
            ptr = ((length & 0x3f) << 8) | data[pos + 1]
            labels.append(_decode_dns_name(data, ptr))
            break
        pos += 1
        labels.append(data[pos:pos + length].decode(errors="replace"))
        pos += length
    return ".".join(labels)


def _parse_query(data: bytes, proto: str, src_addr) -> None:
    """Parse DNS/LLMNR/mDNS query and log the queried name."""
    try:
        if len(data) < 12:
            raise ValueError("too short")
        flags = struct.unpack(">H", data[2:4])[0]
        qr = (flags >> 15) & 1
        qdcount = struct.unpack(">H", data[4:6])[0]
        if qr != 0 or qdcount < 1:
            return  # not a query or no questions
        name = _decode_dns_name(data, 12)
        pos = 12
        while pos < len(data) and data[pos] != 0:
            pos += data[pos] + 1
        pos += 1
        qtype = struct.unpack(">H", data[pos:pos + 2])[0] if pos + 2 <= len(data) else 0
        _log(
            "query",
            proto=proto,
            src=src_addr[0],
            src_port=src_addr[1],
            name=name,
            qtype=qtype,
        )
    except Exception as e:
        _log("raw_packet", proto=proto, src=src_addr[0], data=data[:64].hex(), error=str(e))


class LLMNRProtocol(asyncio.DatagramProtocol):
    def __init__(self, proto_label: str):
        self._proto = proto_label

    def datagram_received(self, data, addr):
        _parse_query(data, self._proto, addr)

    def error_received(self, exc):
        pass


async def main():
    _log("startup", msg=f"LLMNR/mDNS server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()

    # LLMNR: UDP 5355
    llmnr_transport, _ = await loop.create_datagram_endpoint(
        lambda: LLMNRProtocol("LLMNR"),
        local_addr=("0.0.0.0", 5355),
    )
    # mDNS: UDP 5353
    mdns_transport, _ = await loop.create_datagram_endpoint(
        lambda: LLMNRProtocol("mDNS"),
        local_addr=("0.0.0.0", 5353),
    )

    try:
        await asyncio.sleep(float("inf"))
    finally:
        llmnr_transport.close()
        mdns_transport.close()


if __name__ == "__main__":
    asyncio.run(main())
