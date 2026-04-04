#!/usr/bin/env python3
"""
POP3server.
Presents a convincing POP3 banner, collects USER/PASS credentials, then
stalls with a generic error. Logs every interaction as JSON and forwards
to LOG_TARGET if set.
"""

import asyncio
import json
import os
import socket
from datetime import datetime, timezone
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "mailserver")
SERVICE_NAME   = "pop3"
LOG_TARGET = os.environ.get("LOG_TARGET", "")
BANNER = f"+OK {NODE_NAME} POP3 server ready\r\n"




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    print(line, flush=True)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


class POP3Protocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = None
        self._user = None
        self._buf = b""

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])
        transport.write(BANNER.encode())

    def data_received(self, data):
        self._buf += data
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            self._handle_line(line.decode(errors="replace").strip())

    def _handle_line(self, line: str):
        upper = line.upper()
        if upper.startswith("USER "):
            self._user = line[5:].strip()
            _log("user", src=self._peer[0], username=self._user)
            self._transport.write(b"+OK\r\n")
        elif upper.startswith("PASS "):
            password = line[5:].strip()
            _log("auth", src=self._peer[0], username=self._user, password=password)
            self._transport.write(b"-ERR Authentication failed\r\n")
        elif upper == "QUIT":
            self._transport.write(b"+OK Bye\r\n")
            self._transport.close()
        elif upper == "CAPA":
            self._transport.write(b"+OK Capability list follows\r\nUSER\r\n.\r\n")
        else:
            _log("command", src=self._peer[0], cmd=line[:128])
            self._transport.write(b"-ERR Unknown command\r\n")

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"POP3 server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(POP3Protocol, "0.0.0.0", 110)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
