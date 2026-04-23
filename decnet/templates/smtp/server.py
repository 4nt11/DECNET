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
import hashlib
import json
import os
import random as _rand
import re
import time
from datetime import datetime, timezone
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message

import instance_seed as _seed
from syslog_bridge import SEVERITY_WARNING, syslog_line, write_syslog_file, forward_syslog

NODE_NAME   = os.environ.get("NODE_NAME", "mailserver")
SERVICE_NAME = "smtp"
LOG_TARGET  = os.environ.get("LOG_TARGET", "")
PORT        = int(os.environ.get("PORT", "25"))
OPEN_RELAY  = os.environ.get("SMTP_OPEN_RELAY", "0").strip() == "1"

# In open-relay mode, optionally restrict which creds succeed. Blank means
# "accept anything". Format: "user1,user2,..." — any name not in the list
# gets a 535 instead of 235, so the relay looks realistically selective.
_AUTH_WHITELIST = {u.strip() for u in os.environ.get("SMTP_AUTH_WHITELIST", "").split(",") if u.strip()}

# Open-relay filtering. Even compromised/misconfigured relays aren't pure
# tarpits — Postfix rejects malformed addresses at RCPT time, and many drop
# a small fraction of external recipients under greylisting or reputation
# checks. Accepting literally every RCPT is a honeypot tell.
_ADDR_RE = re.compile(r"^<?([^\s<>@]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})>?$")
_BLOCKED_TLDS = {"invalid", "test", "localhost", "local", "example"}
_RCPT_DROP_RATE = float(os.environ.get("SMTP_RCPT_DROP_RATE", "0.08"))

_SMTP_BANNER = os.environ.get("SMTP_BANNER", f"220 {NODE_NAME} ESMTP Postfix (Debian/GNU)")
_SMTP_MTA    = os.environ.get("SMTP_MTA", NODE_NAME)

# Full-message capture: bind-mounted quarantine dir (host path
# /var/lib/decnet/artifacts/{decky}/smtp). When unset, capture is skipped —
# the container still accepts mail, it just doesn't persist the body. Used by
# tests and by deployments that don't want disk persistence.
_QUARANTINE_DIR = os.environ.get("SMTP_QUARANTINE_DIR", "")
# EHLO advertises SIZE 10240000 (10 MB). Cap the accumulator at the same
# value so a crafted client can't OOM the container by streaming forever.
_MAX_BODY_BYTES = int(os.environ.get("SMTP_MAX_BODY_BYTES", "10485760"))

# Postfix's queue-ID character set (real one: excludes vowels and look-alikes
# like 0/O, 1/I, so scanners that know Postfix's alphabet are satisfied).
_QUEUE_CHARS = "BCDFGHJKLMNPQRSTVWXYZ23456789"
_Q_BASE = len(_QUEUE_CHARS)


def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


def _rand_msg_id() -> str:
    """Postfix-style queue ID.

    Real Postfix derives its short queue IDs from the message's arrival
    microseconds, base-encoded with a vowel-free alphabet — so IDs are
    monotonically increasing and visually distinctive. We encode the current
    microsecond count with Postfix's actual character set, then append a
    short per-instance suffix so two deckies never emit identical IDs at
    the same instant.
    """
    us = int(time.time() * 1_000_000)
    out: list[str] = []
    while us and len(out) < 10:
        us, r = divmod(us, _Q_BASE)
        out.append(_QUEUE_CHARS[r])
    base = "".join(reversed(out)) or _QUEUE_CHARS[0]
    suffix_idx = _seed.rng.randint(0, _Q_BASE - 1)
    return base + _QUEUE_CHARS[suffix_idx]


def _decode_header(raw: str | None) -> str:
    """Best-effort decode of an RFC 2047 encoded-word header to Unicode.

    Returns "" for missing / undecodable values so callers can treat the
    result as a plain string.
    """
    if not raw:
        return ""
    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        return raw
# Stored_as format mirrors the SSH artifact convention so the existing
# /api/v1/artifacts/{decky}/{stored_as} endpoint and its filename regex
# accept SMTP drops unchanged: <iso_ts>_<sha12>_<basename>. The basename
# always ends in .eml so operators can open it in any MUA.
_STORED_AS_BASE_RE = re.compile(r"[^A-Za-z0-9._-]")


def _summarize_message(body: bytes, msg_id: str) -> dict:
    """Parse the DATA body and extract forensic metadata.

    Returns a dict with:
        subject, from_hdr, to_hdr, date_hdr, message_id_hdr, content_type,
        attachments: list of {filename, content_type, size, sha256}.
    Headers are RFC 2047 decoded. Attachment hashing uses the *decoded*
    payload so operators can match against VT / MalwareBazaar directly.
    """
    try:
        msg: Message = message_from_bytes(body)
    except Exception:
        return {
            "subject": "", "from_hdr": "", "to_hdr": "", "date_hdr": "",
            "message_id_hdr": "", "content_type": "", "attachments": [],
        }

    attachments: list[dict] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = (part.get("Content-Disposition") or "").lower()
        filename = part.get_filename()
        # Treat any part with an explicit filename as an attachment, even
        # when Content-Disposition is missing — spam kits frequently omit it.
        if not filename and "attachment" not in disposition:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        attachments.append({
            "filename": _decode_header(filename) or "",
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
        })

    return {
        "subject": _decode_header(msg.get("Subject")),
        "from_hdr": _decode_header(msg.get("From")),
        "to_hdr": _decode_header(msg.get("To")),
        "date_hdr": _decode_header(msg.get("Date")),
        "message_id_hdr": _decode_header(msg.get("Message-ID")),
        "content_type": msg.get_content_type(),
        "attachments": attachments,
    }


def _persist_message(body: bytes, msg_id: str) -> str | None:
    """Write the raw DATA body to the quarantine dir as a .eml file.

    Returns the stored_as basename on success, None if capture is disabled
    or the write failed. The SMTP reply is always 250 regardless — a real
    relay is opaque about its storage path.
    """
    if not _QUARANTINE_DIR:
        return None
    sha = hashlib.sha256(body).hexdigest()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    safe_id = _STORED_AS_BASE_RE.sub("_", msg_id)[:32] or "msg"
    stored_as = f"{ts}_{sha[:12]}_{safe_id}.eml"
    try:
        with open(os.path.join(_QUARANTINE_DIR, stored_as), "wb") as fh:
            fh.write(body)
        return stored_as
    except OSError:
        return None


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
        # Running byte count for the DATA body; once this exceeds
        # _MAX_BODY_BYTES we stop appending to _data_buf but keep
        # consuming lines so the session still terminates cleanly.
        self._data_bytes = 0
        self._data_truncated = False
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
                body_str = "\r\n".join(self._data_buf)
                body = body_str.encode("utf-8", errors="replace")
                msg_id = _rand_msg_id()
                _log("message_accepted",
                     src=self._peer[0],
                     mail_from=self._mail_from,
                     rcpt_to=",".join(self._rcpt_to),
                     body_bytes=len(body),
                     truncated=int(self._data_truncated),
                     msg_id=msg_id)
                # Persist the full .eml into the quarantine bind mount
                # (if configured) and emit a richer event so the collector
                # can index attachments + headers. This is the hook the
                # dashboard's "sent mail" viewer reads.
                stored_as = _persist_message(body, msg_id)
                if stored_as is not None:
                    summary = _summarize_message(body, msg_id)
                    _log(
                        "message_stored",
                        src=self._peer[0],
                        msg_id=msg_id,
                        stored_as=stored_as,
                        sha256=hashlib.sha256(body).hexdigest(),
                        size=len(body),
                        truncated=int(self._data_truncated),
                        mail_from=self._mail_from,
                        rcpt_to=",".join(self._rcpt_to),
                        subject=summary["subject"][:512],
                        from_hdr=summary["from_hdr"][:256],
                        to_hdr=summary["to_hdr"][:512],
                        date_hdr=summary["date_hdr"][:64],
                        message_id_hdr=summary["message_id_hdr"][:256],
                        content_type=summary["content_type"],
                        attachment_count=len(summary["attachments"]),
                        # Full manifest (filename/sha256/size/content_type)
                        # rides as a compact JSON blob — the SD-value escape
                        # in syslog_bridge handles the quotes and brackets.
                        attachments_json=json.dumps(summary["attachments"], separators=(",", ":")),
                    )
                # Real MTAs take tens of ms to queue; instantaneous replies
                # on DATA are a tell.
                _seed.jitter_sync(30, 180)
                self._transport.write(f"250 2.0.0 Ok: queued as {msg_id}\r\n".encode())
                self._in_data         = False
                self._data_buf        = []
                self._data_bytes      = 0
                self._data_truncated  = False
                self._mail_from       = ""
                self._rcpt_to         = []
            else:
                # RFC 5321 dot-stuffing: strip leading dot
                decoded = line[1:] if line.startswith(".") else line
                # +2 accounts for the CRLF that rejoins this line to the body.
                new_total = self._data_bytes + len(decoded.encode("utf-8", errors="replace")) + 2
                if new_total <= _MAX_BODY_BYTES:
                    self._data_buf.append(decoded)
                    self._data_bytes = new_total
                else:
                    # Stop appending but keep consuming so the client's
                    # final CRLF.CRLF still terminates the state machine.
                    self._data_truncated = True
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
            if not args:
                self._transport.write(
                    f"501 5.5.4 Syntax: {cmd} hostname\r\n".encode()
                )
                return
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
                match = _ADDR_RE.match(addr)
                if not match:
                    _log("rcpt_rejected_syntax", src=self._peer[0], value=addr,
                         severity=SEVERITY_WARNING)
                    self._transport.write(
                        b"501 5.1.3 Bad recipient address syntax\r\n"
                    )
                elif match.group(2).rsplit(".", 1)[-1].lower() in _BLOCKED_TLDS:
                    _log("rcpt_rejected_tld", src=self._peer[0], value=addr,
                         severity=SEVERITY_WARNING)
                    self._transport.write(
                        b"550 5.1.2 <" + addr.encode()
                        + b">: Recipient address rejected: Domain not found\r\n"
                    )
                elif _rand.random() < _RCPT_DROP_RATE:
                    _log("rcpt_greylisted", src=self._peer[0], value=addr)
                    self._transport.write(
                        b"451 4.7.1 <" + addr.encode()
                        + b">: Recipient address rejected: Greylisted, try again later\r\n"
                    )
                else:
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
            self._data_bytes = 0
            self._data_truncated = False
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
        if not OPEN_RELAY:
            self._transport.write(b"535 5.7.8 Error: authentication failed\r\n")
            return
        # Open-relay mode: still be selective so the decoy doesn't look like a
        # tarpit that accepts literally anything. If no whitelist is set,
        # accept; otherwise gate on username presence.
        accepted = not _AUTH_WHITELIST or username in _AUTH_WHITELIST
        if accepted:
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
