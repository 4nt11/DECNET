#!/usr/bin/env python3
"""
SMTP server — emulates a realistic ESMTP server (Postfix-style).
Logs EHLO/AUTH/MAIL FROM/RCPT TO attempts as JSON, then denies auth.
"""

import asyncio
import json
import os
import socket
from datetime import datetime, timezone
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME   = os.environ.get("NODE_NAME", "mailserver")
SERVICE_NAME   = "smtp"
LOG_TARGET  = os.environ.get("LOG_TARGET", "")
_SMTP_BANNER = os.environ.get("SMTP_BANNER", f"220 {NODE_NAME} ESMTP Postfix (Debian/GNU)")
_SMTP_MTA    = os.environ.get("SMTP_MTA", NODE_NAME)




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    print(line, flush=True)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


class SMTPProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = ("?", 0)
        self._buf = b""

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])
        transport.write(f"{_SMTP_BANNER}\r\n".encode())

    def data_received(self, data):
        self._buf += data
        while b"\r\n" in self._buf:
            line, self._buf = self._buf.split(b"\r\n", 1)
            self._handle_line(line.decode(errors="replace").strip())

    def _handle_line(self, line: str) -> None:
        cmd = line.split()[0].upper() if line.split() else ""

        if cmd in ("EHLO", "HELO"):
            domain = line.split(None, 1)[1] if " " in line else ""
            _log("ehlo", src=self._peer[0], domain=domain)
            self._transport.write(
                f"250-{_SMTP_MTA}\r\n"
                f"250-PIPELINING\r\n"
                f"250-SIZE 10240000\r\n"
                f"250-VRFY\r\n"
                f"250-ETRN\r\n"
                f"250-AUTH PLAIN LOGIN\r\n"
                f"250-ENHANCEDSTATUSCODES\r\n"
                f"250-8BITMIME\r\n"
                f"250 DSN\r\n".encode()
            )
        elif cmd == "AUTH":
            _log("auth_attempt", src=self._peer[0], command=line)
            self._transport.write(b"535 5.7.8 Error: authentication failed: UGFzc3dvcmQ6\r\n")
            self._transport.close()
        elif cmd == "MAIL":
            _log("mail_from", src=self._peer[0], value=line)
            self._transport.write(b"250 2.1.0 Ok\r\n")
        elif cmd == "RCPT":
            _log("rcpt_to", src=self._peer[0], value=line)
            self._transport.write(b"250 2.1.5 Ok\r\n")
        elif cmd == "DATA":
            self._transport.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
        elif cmd == "VRFY":
            _log("vrfy", src=self._peer[0], value=line)
            self._transport.write(b"252 2.0.0 Cannot VRFY user\r\n")
        elif cmd == "QUIT":
            self._transport.write(b"221 2.0.0 Bye\r\n")
            self._transport.close()
        elif cmd == "NOOP":
            self._transport.write(b"250 2.0.0 Ok\r\n")
        elif cmd == "RSET":
            self._transport.write(b"250 2.0.0 Ok\r\n")
        elif cmd == "STARTTLS":
            # Pretend we don't support upgrading mid-session
            self._transport.write(b"454 4.7.0 TLS not available due to local problem\r\n")
        else:
            _log("unknown_command", src=self._peer[0], command=line)
            self._transport.write(b"502 5.5.2 Error: command not recognized\r\n")

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"SMTP server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(SMTPProtocol, "0.0.0.0", 25)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
