#!/usr/bin/env python3
"""
POP3 server (port 110/995).
Presents a POP3 banner, captures USER and PASS credentials.
Implements a basic POP3 state machine (AUTHORIZATION -> TRANSACTION).
Provides hardcoded bait emails.
Logs commands as JSON.
"""

import asyncio
import os
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "mailserver")
SERVICE_NAME   = "pop3"
LOG_TARGET = os.environ.get("LOG_TARGET", "")
POP3_BANNER = os.environ.get("IMAP_BANNER", f"+OK [{NODE_NAME}] Dovecot ready.\r\n")

IMAP_USERS = os.environ.get("IMAP_USERS", "admin:admin123,root:toor")

_BAIT_EMAILS = [
    "Date: Tue, 01 Nov 2023 10:00:00 +0000\r\nFrom: sysadmin@company.com\r\nSubject: AWS Credentials\r\n\r\nHere are the new AWS keys:\r\nAKIAIOSFODNN7EXAMPLE\r\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n",
    "Date: Wed, 02 Nov 2023 11:30:00 +0000\r\nFrom: devops@company.com\r\nSubject: DB Password Reset\r\n\r\nThe production database password has been temporarily set to:\r\nProdDB_temp_2023!!\r\n",
]

def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    print(line, flush=True)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)

class POP3Protocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = None
        self._buf = b""
        self._state = "AUTHORIZATION"
        self._valid_users = dict(u.split(":", 1) for u in IMAP_USERS.split(",") if ":" in u)
        self._current_user = None

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])
        if POP3_BANNER:
            if not POP3_BANNER.endswith("\r\n"):
                padded_banner = POP3_BANNER + "\r\n"
            else:
                padded_banner = POP3_BANNER
            if not padded_banner.startswith("+OK"):
                padded_banner = "+OK " + padded_banner.lstrip("* OK ") # replace IMAP prefix with POP3
            transport.write(padded_banner.encode())

    def data_received(self, data):
        self._buf += data
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            self._handle_line(line.decode(errors="replace").strip())

    def _handle_line(self, line: str):
        parts = line.split(None, 1)
        if not parts:
            return
        cmd = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""

        _log("command", src=self._peer[0], cmd=line[:128], state=self._state)

        if cmd == "CAPA":
            self._transport.write(b"+OK Capability list follows\r\nUSER\r\n.\r\n")

        elif cmd == "USER":
            if self._state != "AUTHORIZATION":
                self._transport.write(b"-ERR Already authenticated.\r\n")
                return
            self._current_user = args
            self._transport.write(b"+OK User name accepted, password please\r\n")

        elif cmd == "PASS":
            if self._state != "AUTHORIZATION":
                self._transport.write(b"-ERR Already authenticated.\r\n")
                return
            if not self._current_user:
                self._transport.write(b"-ERR USER required first.\r\n")
                return
                
            password = args
            username = self._current_user
            
            if username in self._valid_users and self._valid_users[username] == password:
                self._state = "TRANSACTION"
                _log("auth", src=self._peer[0], username=username, password=password, status="success")
                self._transport.write(b"+OK Logged in.\r\n")
            else:
                _log("auth", src=self._peer[0], username=username, password=password, status="failed")
                self._transport.write(b"-ERR Authentication failed.\r\n")
                self._current_user = None

        elif cmd == "STAT":
            if self._state != "TRANSACTION":
                self._transport.write(b"-ERR Not authenticated\r\n")
                return
            total_size = sum(len(e) for e in _BAIT_EMAILS)
            self._transport.write(f"+OK {len(_BAIT_EMAILS)} {total_size}\r\n".encode())

        elif cmd == "LIST":
            if self._state != "TRANSACTION":
                self._transport.write(b"-ERR Not authenticated\r\n")
                return
            
            if args:
                try:
                    idx = int(args) - 1
                    if 0 <= idx < len(_BAIT_EMAILS):
                        self._transport.write(f"+OK {idx + 1} {len(_BAIT_EMAILS[idx])}\r\n".encode())
                    else:
                        self._transport.write(b"-ERR No such message\r\n")
                except ValueError:
                    self._transport.write(b"-ERR Invalid argument\r\n")
            else:
                total_size = sum(len(e) for e in _BAIT_EMAILS)
                self._transport.write(f"+OK {len(_BAIT_EMAILS)} messages ({total_size} octets)\r\n".encode())
                for i, email in enumerate(_BAIT_EMAILS):
                    self._transport.write(f"{i + 1} {len(email)}\r\n".encode())
                self._transport.write(b".\r\n")

        elif cmd == "RETR":
            if self._state != "TRANSACTION":
                self._transport.write(b"-ERR Not authenticated\r\n")
                return
            try:
                idx = int(args) - 1
                if 0 <= idx < len(_BAIT_EMAILS):
                    email = _BAIT_EMAILS[idx]
                    self._transport.write(f"+OK {len(email)} octets\r\n".encode())
                    self._transport.write(email.encode())
                    self._transport.write(b".\r\n")
                else:
                    self._transport.write(b"-ERR No such message\r\n")
            except ValueError:
                self._transport.write(b"-ERR Invalid argument\r\n")

        elif cmd == "QUIT":
            self._transport.write(b"+OK Logging out.\r\n")
            self._transport.close()
            
        else:
            self._transport.write(b"-ERR Command not recognized\r\n")

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")

async def main():
    _log("startup", msg=f"POP3 server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(POP3Protocol, "0.0.0.0", 110)  # nosec B104
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
