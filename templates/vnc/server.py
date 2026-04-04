#!/usr/bin/env python3
"""
VNC (RFB)server.
Performs the RFB 3.8 handshake, offers VNC authentication, captures the
24-byte DES-encrypted challenge response, then rejects with "Authentication
failed". Logs the raw response for offline cracking.
"""

import asyncio
import os
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "desktop")
SERVICE_NAME   = "vnc"
LOG_TARGET = os.environ.get("LOG_TARGET", "")

# RFB challenge — fixed so captured responses are reproducible
_CHALLENGE = bytes(range(16)) * 1 + b"\x10\x11\x12\x13\x14\x15\x16\x17"  # 24 bytes




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    print(line, flush=True)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


class VNCProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = None
        self._buf = b""
        self._state = "version"

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])
        # Send RFB version
        transport.write(b"RFB 003.008\n")

    def data_received(self, data):
        self._buf += data
        self._process()

    def _process(self):
        if self._state == "version":
            if b"\n" not in self._buf:
                return
            line, self._buf = self._buf.split(b"\n", 1)
            client_version = line.decode(errors="replace").strip()
            _log("version", src=self._peer[0], client_version=client_version)
            # Send security types: 1 type = VNC Authentication (2)
            self._transport.write(b"\x01\x02")
            self._state = "security_choice"

        elif self._state == "security_choice":
            if len(self._buf) < 1:
                return
            chosen = self._buf[0]
            self._buf = self._buf[1:]
            _log("security_choice", src=self._peer[0], type=chosen)
            # Send 16-byte challenge
            self._transport.write(_CHALLENGE[:16])
            self._state = "auth_response"

        elif self._state == "auth_response":
            if len(self._buf) < 16:
                return
            response = self._buf[:16]
            self._buf = self._buf[16:]
            _log("auth_response", src=self._peer[0], response=response.hex())
            # SecurityResult: 1 = failed
            self._transport.write(b"\x00\x00\x00\x01")
            # Failure reason
            reason = b"Authentication failed"
            import struct
            self._transport.write(struct.pack(">I", len(reason)) + reason)
            self._transport.close()

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"VNC server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(VNCProtocol, "0.0.0.0", 5900)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
