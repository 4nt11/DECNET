#!/usr/bin/env python3
"""
IMAP server (port 143/993).
Presents an IMAP4rev1 banner, captures LOGIN credentials.
Implements a basic IMAP state machine (NOT_AUTHENTICATED -> AUTHENTICATED -> SELECTED).
Provides hardcoded bait emails containing AWS API keys to attackers.
Logs commands as JSON.
"""

import asyncio
import os
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "mailserver")
SERVICE_NAME   = "imap"
LOG_TARGET = os.environ.get("LOG_TARGET", "")
IMAP_BANNER = os.environ.get("IMAP_BANNER", f"* OK [{NODE_NAME}] Dovecot ready.\r\n")

IMAP_USERS = os.environ.get("IMAP_USERS", "admin:admin123,root:toor")

_BAIT_EMAILS = [
    (1, "Date: Tue, 01 Nov 2023 10:00:00 +0000\r\nFrom: sysadmin@company.com\r\nSubject: AWS Credentials\r\n\r\nHere are the new AWS keys:\r\nAKIAIOSFODNN7EXAMPLE\r\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n"),
    (2, "Date: Wed, 02 Nov 2023 11:30:00 +0000\r\nFrom: devops@company.com\r\nSubject: DB Password Reset\r\n\r\nThe production database password has been temporarily set to:\r\nProdDB_temp_2023!!\r\n"),
]

def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    print(line, flush=True)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)

class IMAPProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = None
        self._buf = b""
        self._state = "NOT_AUTHENTICATED"
        self._valid_users = dict(u.split(":", 1) for u in IMAP_USERS.split(",") if ":" in u)

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])
        if IMAP_BANNER:
            if not IMAP_BANNER.endswith("\r\n"):
                padded_banner = IMAP_BANNER + "\r\n"
            else:
                padded_banner = IMAP_BANNER
            transport.write(padded_banner.encode())

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

        _log("command", src=self._peer[0], cmd=line[:128], state=self._state)

        if cmd == "CAPABILITY":
            self._transport.write(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN\r\n")
            self._transport.write(f"{tag} OK CAPABILITY completed\r\n".encode())
            
        elif cmd == "LOGIN":
            if self._state != "NOT_AUTHENTICATED":
                self._transport.write(f"{tag} BAD Already authenticated\r\n".encode())
                return
            creds = args.split(None, 1)
            username = creds[0].strip('"') if creds else ""
            password = creds[1].strip('"') if len(creds) > 1 else ""
            
            if username in self._valid_users and self._valid_users[username] == password:
                self._state = "AUTHENTICATED"
                _log("auth", src=self._peer[0], username=username, password=password, status="success")
                self._transport.write(f"{tag} OK [CAPABILITY IMAP4rev1] Logged in\r\n".encode())
            else:
                _log("auth", src=self._peer[0], username=username, password=password, status="failed")
                self._transport.write(f"{tag} NO [AUTHENTICATIONFAILED] Authentication failed.\r\n".encode())
                
        elif cmd == "SELECT" or cmd == "EXAMINE":
            if self._state == "NOT_AUTHENTICATED":
                self._transport.write(f"{tag} BAD Not authenticated\r\n".encode())
                return
            
            self._state = "SELECTED"
            count = len(_BAIT_EMAILS)
            self._transport.write(f"* {count} EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n".encode())
            self._transport.write(f"{tag} OK [READ-WRITE] Select completed.\r\n".encode())

        elif cmd == "FETCH":
            if self._state != "SELECTED":
                self._transport.write(f"{tag} BAD Not selected\r\n".encode())
                return
                
            # rudimentary fetch match simply returning all if any match
            # an attacker usually sends "FETCH 1:* (BODY[])" or similar
            if "RFC822" in args.upper() or "BODY" in args.upper():
                for uid, content in _BAIT_EMAILS:
                    content_encoded = content.encode()
                    self._transport.write(f"* {uid} FETCH (RFC822 {{{len(content_encoded)}}}\r\n".encode())
                    self._transport.write(content_encoded)
                    self._transport.write(b")\r\n")
            self._transport.write(f"{tag} OK Fetch completed.\r\n".encode())

        elif cmd == "LOGOUT":
            self._transport.write(b"* BYE Logging out\r\n")
            self._transport.write(f"{tag} OK Logout completed.\r\n".encode())
            self._transport.close()
            
        else:
            self._transport.write(f"{tag} BAD Command not recognized or unsupported\r\n".encode())

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"IMAP server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(IMAPProtocol, "0.0.0.0", 143)  # nosec B104
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
