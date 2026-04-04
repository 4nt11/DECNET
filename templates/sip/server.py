#!/usr/bin/env python3
"""
SIP server (UDP + TCP port 5060).
Parses SIP REGISTER and INVITE messages, logs credentials from the
Authorization header and call metadata, then responds with 401 Unauthorized.
"""

import asyncio
import json
import os
import re
import socket
from datetime import datetime, timezone

NODE_NAME = os.environ.get("NODE_NAME", "pbx")
LOG_TARGET = os.environ.get("LOG_TARGET", "")

_401 = (
    "SIP/2.0 401 Unauthorized\r\n"
    "Via: {via}\r\n"
    "From: {from_}\r\n"
    "To: {to}\r\n"
    "Call-ID: {call_id}\r\n"
    "CSeq: {cseq}\r\n"
    'WWW-Authenticate: Digest realm="{host}", nonce="decnet0000", algorithm=MD5\r\n'
    "Content-Length: 0\r\n\r\n"
)


def _forward(event: dict) -> None:
    if not LOG_TARGET:
        return
    try:
        host, port = LOG_TARGET.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=3) as s:
            s.sendall((json.dumps(event) + "\n").encode())
    except Exception:
        pass


def _log(event_type: str, **kwargs) -> None:
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "service": "sip",
        "host": NODE_NAME,
        "event": event_type,
        **kwargs,
    }
    print(json.dumps(event), flush=True)
    _forward(event)


def _parse_headers(msg: str) -> dict:
    headers = {}
    for line in msg.splitlines()[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers


def _handle_message(data: bytes, src_addr) -> bytes | None:
    try:
        msg = data.decode(errors="replace")
    except Exception:
        return None
    first_line = msg.splitlines()[0] if msg else ""
    method = first_line.split()[0] if first_line else "UNKNOWN"
    headers = _parse_headers(msg)

    auth_header = headers.get("authorization", "")
    username = ""
    if auth_header:
        m = re.search(r'username="([^"]+)"', auth_header)
        username = m.group(1) if m else ""

    _log(
        "request",
        src=src_addr[0],
        src_port=src_addr[1],
        method=method,
        from_=headers.get("from", ""),
        to=headers.get("to", ""),
        username=username,
        auth=auth_header[:256],
    )

    if method in ("REGISTER", "INVITE", "OPTIONS"):
        response = _401.format(
            via=headers.get("via", ""),
            from_=headers.get("from", ""),
            to=headers.get("to", ""),
            call_id=headers.get("call-id", ""),
            cseq=headers.get("cseq", ""),
            host=NODE_NAME,
        )
        return response.encode()
    return None


class SIPUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self._transport = None

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        response = _handle_message(data, addr)
        if response and self._transport:
            self._transport.sendto(response, addr)


class SIPTCPProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = None
        self._buf = b""

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))

    def data_received(self, data):
        self._buf += data
        if b"\r\n\r\n" in self._buf or b"\n\n" in self._buf:
            response = _handle_message(self._buf, self._peer)
            self._buf = b""
            if response:
                self._transport.write(response)

    def connection_lost(self, exc):
        pass


async def main():
    _log("startup", msg=f"SIP server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    udp_transport, _ = await loop.create_datagram_endpoint(
        SIPUDPProtocol, local_addr=("0.0.0.0", 5060)
    )
    tcp_server = await loop.create_server(SIPTCPProtocol, "0.0.0.0", 5060)
    async with tcp_server:
        await tcp_server.serve_forever()
    udp_transport.close()


if __name__ == "__main__":
    asyncio.run(main())
