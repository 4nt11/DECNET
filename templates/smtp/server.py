#!/usr/bin/env python3
"""
SMTP server — emulates a realistic ESMTP server (Postfix-style).

Two modes of operation, controlled by SMTP_OPEN_RELAY:

  SMTP_OPEN_RELAY=0 (default) — credential harvester
    AUTH attempts are logged and rejected (535).
    RCPT TO is rejected with 554 (relay denied) for all recipients.
    This captures credential stuffing and scanning activity.

  SMTP_OPEN_RELAY=1 — open relay bait
    AUTH is accepted for any credentials (235).
    RCPT TO is accepted for any domain (250).
    DATA is fully buffered until CRLF.CRLF and acknowledged with a
    queued-as message ID. Attractive to spam relay operators.

The DATA state machine (and the 502-per-line bug) is fixed in both modes.
"""

import asyncio
import base64
import os
import random
import string
from decnet_logging import SEVERITY_WARNING, syslog_line, write_syslog_file, forward_syslog

NODE_NAME   = os.environ.get("NODE_NAME", "mailserver")
SERVICE_NAME = "smtp"
LOG_TARGET  = os.environ.get("LOG_TARGET", "")
PORT        = int(os.environ.get("PORT", "25"))
OPEN_RELAY  = os.environ.get("SMTP_OPEN_RELAY", "0").strip() == "1"

_SMTP_BANNER = os.environ.get("SMTP_BANNER", f"220 {NODE_NAME} ESMTP Postfix (Debian/GNU)")
_SMTP_MTA    = os.environ.get("SMTP_MTA", NODE_NAME)


def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


def _rand_msg_id() -> str:
    """Return a Postfix-style 12-char alphanumeric queue ID."""
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choices(chars, k=12))


def _decode_auth_plain(blob: str) -> tuple[str, str]:
    """Decode SASL PLAIN: base64(authzid\0authcid\0passwd) → (user, pass)."""
    try:
        decoded = base64.b64decode(blob + "==").decode(errors="replace")
        parts = decoded.split("\x00")
        if len(parts) >= 3:
            return parts[1], parts[2]
        if len(parts) == 2:
            return parts[0], parts[1]
    except Exception:
        pass
    return blob, ""


class SMTPProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer      = ("?", 0)
        self._buf       = b""
        # per-transaction state
        self._mail_from  = ""
        self._rcpt_to: list[str] = []
        # DATA accumulation
        self._in_data   = False
        self._data_buf: list[str] = []
        # AUTH multi-step state (LOGIN mechanism sends user/pass in separate lines)
        self._auth_state  = ""   # "" | "await_user" | "await_pass"
        self._auth_user   = ""

    # ── asyncio.Protocol ──────────────────────────────────────────────────────

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])
        transport.write(f"{_SMTP_BANNER}\r\n".encode())

    def data_received(self, data):
        self._buf += data
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            # Strip trailing \r so both CRLF and bare LF work
            self._handle_line(line.rstrip(b"\r").decode(errors="replace"))

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")

    # ── Command dispatch ──────────────────────────────────────────────────────

    def _handle_line(self, line: str) -> None:
        # ── DATA body accumulation ────────────────────────────────────────────
        if self._in_data:
            if line == ".":
                body = "\r\n".join(self._data_buf)
                msg_id = _rand_msg_id()
                _log("message_accepted",
                     src=self._peer[0],
                     mail_from=self._mail_from,
                     rcpt_to=",".join(self._rcpt_to),
                     body_bytes=len(body),
                     msg_id=msg_id)
                self._transport.write(f"250 2.0.0 Ok: queued as {msg_id}\r\n".encode())
                self._in_data   = False
                self._data_buf  = []
                self._mail_from = ""
                self._rcpt_to   = []
            else:
                # RFC 5321 dot-stuffing: strip leading dot
                self._data_buf.append(line[1:] if line.startswith(".") else line)
            return

        # ── AUTH multi-step (LOGIN / PLAIN continuation) ─────────────────────
        if self._auth_state == "await_plain":
            user, password = _decode_auth_plain(line)
            self._finish_auth(user, password)
            self._auth_state = ""
            return
        if self._auth_state == "await_user":
            self._auth_user  = base64.b64decode(line + "==").decode(errors="replace")
            self._auth_state = "await_pass"
            self._transport.write(b"334 UGFzc3dvcmQ6\r\n")  # "Password:"
            return
        if self._auth_state == "await_pass":
            password = base64.b64decode(line + "==").decode(errors="replace")
            self._finish_auth(self._auth_user, password)
            self._auth_state = ""
            self._auth_user  = ""
            return

        # ── Normal command dispatch ───────────────────────────────────────────
        parts = line.split(None, 1)
        cmd   = parts[0].upper() if parts else ""
        args  = parts[1] if len(parts) > 1 else ""

        if cmd in ("EHLO", "HELO"):
            _log("ehlo", src=self._peer[0], domain=args)
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
            self._handle_auth(args)

        elif cmd == "MAIL":
            addr = args.split(":", 1)[1].strip() if ":" in args else args
            self._mail_from = addr
            _log("mail_from", src=self._peer[0], value=addr)
            self._transport.write(b"250 2.1.0 Ok\r\n")

        elif cmd == "RCPT":
            addr = args.split(":", 1)[1].strip() if ":" in args else args
            if OPEN_RELAY:
                self._rcpt_to.append(addr)
                _log("rcpt_to", src=self._peer[0], value=addr)
                self._transport.write(b"250 2.1.5 Ok\r\n")
            else:
                _log("rcpt_denied", src=self._peer[0], value=addr,
                     severity=SEVERITY_WARNING)
                self._transport.write(
                    b"554 5.7.1 <" + addr.encode() + b">: Relay access denied\r\n"
                )

        elif cmd == "DATA":
            if not self._rcpt_to:
                self._transport.write(b"503 5.5.1 Error: need RCPT command\r\n")
            else:
                self._in_data = True
                self._transport.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")

        elif cmd == "RSET":
            self._mail_from  = ""
            self._rcpt_to    = []
            self._in_data    = False
            self._data_buf   = []
            self._auth_state = ""
            self._auth_user  = ""
            self._transport.write(b"250 2.0.0 Ok\r\n")

        elif cmd == "VRFY":
            _log("vrfy", src=self._peer[0], value=args)
            self._transport.write(b"252 2.0.0 Cannot VRFY user\r\n")

        elif cmd == "NOOP":
            self._transport.write(b"250 2.0.0 Ok\r\n")

        elif cmd == "STARTTLS":
            self._transport.write(b"454 4.7.0 TLS not available due to local problem\r\n")

        elif cmd == "QUIT":
            self._transport.write(b"221 2.0.0 Bye\r\n")
            self._transport.close()

        else:
            _log("unknown_command", src=self._peer[0], command=line[:128])
            self._transport.write(b"502 5.5.2 Error: command not recognized\r\n")

    # ── AUTH helpers ──────────────────────────────────────────────────────────

    def _handle_auth(self, args: str) -> None:
        parts    = args.split(None, 1)
        mech     = parts[0].upper() if parts else ""
        initial  = parts[1] if len(parts) > 1 else ""

        if mech == "PLAIN":
            if initial:
                user, password = _decode_auth_plain(initial)
                self._finish_auth(user, password)
            else:
                # Client will send credentials on next line
                self._auth_state = "await_plain"
                self._transport.write(b"334 \r\n")
        elif mech == "LOGIN":
            if initial:
                self._auth_user  = base64.b64decode(initial + "==").decode(errors="replace")
                self._auth_state = "await_pass"
                self._transport.write(b"334 UGFzc3dvcmQ6\r\n")  # "Password:"
            else:
                self._auth_state = "await_user"
                self._transport.write(b"334 VXNlcm5hbWU6\r\n")  # "Username:"
        else:
            self._transport.write(b"504 5.5.4 Unrecognized authentication mechanism\r\n")

    def _finish_auth(self, username: str, password: str) -> None:
        _log("auth_attempt", src=self._peer[0],
             username=username, password=password,
             severity=SEVERITY_WARNING)
        if OPEN_RELAY:
            self._transport.write(b"235 2.7.0 Authentication successful\r\n")
        else:
            self._transport.write(b"535 5.7.8 Error: authentication failed\r\n")


async def main():
    mode = "open-relay" if OPEN_RELAY else "credential-harvester"
    _log("startup", msg=f"SMTP server starting as {NODE_NAME} ({mode})")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(SMTPProtocol, "0.0.0.0", PORT)  # nosec B104
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
