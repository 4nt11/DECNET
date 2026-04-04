#!/usr/bin/env python3
"""
IMAP honeypot.
Presents an IMAP4rev1 banner, captures LOGIN credentials (plaintext and
AUTHENTICATE), then returns a NO response. Logs all commands as JSON.
"""

import asyncio
import json
import os
import socket
from datetime import datetime, timezone

HONEYPOT_NAME = os.environ.get("HONEYPOT_NAME", "mailserver")
LOG_TARGET = os.environ.get("LOG_TARGET", "")
BANNER = f"* OK [{HONEYPOT_NAME}] IMAP4rev1 Service Ready\r\n"


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
        "service": "imap",
        "host": HONEYPOT_NAME,
        "event": event_type,
        **kwargs,
    }
    print(json.dumps(event), flush=True)
    _forward(event)


class IMAPProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = None
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
        parts = line.split(None, 2)
        if not parts:
            return
        tag = parts[0]
        cmd = parts[1].upper() if len(parts) > 1 else ""
        args = parts[2] if len(parts) > 2 else ""

        if cmd == "LOGIN":
            creds = args.split(None, 1)
            username = creds[0].strip('"') if creds else ""
            password = creds[1].strip('"') if len(creds) > 1 else ""
            _log("auth", src=self._peer[0], username=username, password=password)
            self._transport.write(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n".encode())
        elif cmd == "CAPABILITY":
            self._transport.write(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN\r\n")
            self._transport.write(f"{tag} OK CAPABILITY completed\r\n".encode())
        elif cmd == "LOGOUT":
            self._transport.write(b"* BYE IMAP4rev1 Server logging out\r\n")
            self._transport.write(f"{tag} OK LOGOUT completed\r\n".encode())
            self._transport.close()
        else:
            _log("command", src=self._peer[0], cmd=line[:128])
            self._transport.write(f"{tag} BAD Command not recognized\r\n".encode())

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"IMAP honeypot starting as {HONEYPOT_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(IMAPProtocol, "0.0.0.0", 143)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
