#!/usr/bin/env python3
"""
POP3 server (port 110).
Full POP3 state machine with bait mailbox.

States: AUTHORIZATION → TRANSACTION

Credentials via IMAP_USERS env var (shared with IMAP service).
10 bait emails containing AWS keys, DB passwords, tokens etc.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import cast
from syslog_bridge import (
    SEVERITY_WARNING,
    encode_secret,
    forward_syslog,
    syslog_line,
    write_syslog_file,
)

NODE_NAME    = os.environ.get("NODE_NAME", "mailserver")
SERVICE_NAME  = "pop3"
LOG_TARGET   = os.environ.get("LOG_TARGET", "")
PORT         = int(os.environ.get("PORT", "110"))
POP3_BANNER  = os.environ.get("POP3_BANNER", f"+OK {NODE_NAME} Dovecot POP3 ready.")
_RAW_USERS   = os.environ.get("IMAP_USERS", "admin:admin123,root:toor,mail:mail,user:user")

VALID_USERS: dict[str, str] = {
    u: p for part in _RAW_USERS.split(",") if ":" in part for u, p in [part.split(":", 1)]
}

# Operator/realism-engine email seed source.  Two shapes accepted:
#   1. Directory: walked recursively for ``*.eml`` (RFC 822 on disk —
#      what the realism-engine emailgen worker drops in) and ``*.json``
#      (operator-curated lists of dicts; each dict formatted into RFC
#      5322 on load).
#   2. Single ``*.json`` or ``*.eml`` file.
# Loaded entries are CONCATENATED with ``_BAIT_EMAILS`` — never replace.
_EMAIL_SEED_PATH = os.environ.get("POP3_EMAIL_SEED", "")
_SEED_RESCAN_INTERVAL = float(os.environ.get("POP3_EMAIL_SEED_RESCAN", "5"))

# ── Bait emails ───────────────────────────────────────────────────────────────

_BAIT_EMAILS: list[str] = [
    (
        "Date: Mon, 06 Nov 2023 09:12:33 +0000\r\n"
        "From: DevOps Team <devops@company.internal>\r\n"
        "To: admin@company.internal\r\n"
        "Subject: AWS credentials rotation\r\n"
        "Message-ID: <1@company.internal>\r\n"
        "\r\n"
        "Team,\r\n\r\n"
        "New AWS credentials have been issued. Old keys deactivated.\r\n\r\n"
        "Access Key ID:     AKIAIOSFODNN7EXAMPLE\r\n"
        "Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n\r\n"
        "Update ~/.aws/credentials immediately.\r\n\r\n-- DevOps\r\n"
    ),
    (
        "Date: Tue, 07 Nov 2023 14:05:11 +0000\r\n"
        "From: Monitoring <monitoring@company.internal>\r\n"
        "To: admin@company.internal\r\n"
        "Subject: DB password changed\r\n"
        "Message-ID: <2@company.internal>\r\n"
        "\r\n"
        "Production database password was rotated.\r\n\r\n"
        "Connection string: mysql://admin:Sup3rS3cr3t!@10.0.1.5:3306/production\r\n\r\n"
        "Update all app configs.\r\n"
    ),
    (
        "Date: Wed, 08 Nov 2023 08:30:00 +0000\r\n"
        "From: GitHub <noreply@github.com>\r\n"
        "To: admin@company.internal\r\n"
        "Subject: Your personal access token\r\n"
        "Message-ID: <3@company.internal>\r\n"
        "\r\n"
        "Hi admin,\r\n\r\n"
        "A new personal access token was created for your account.\r\n\r\n"
        "Token: ghp_16C7e42F292c6912E7710c838347Ae178B4a\r\n\r\n"
        "If this wasn't you, revoke it immediately at github.com/settings/tokens.\r\n"
    ),
    (
        "Date: Thu, 09 Nov 2023 11:22:47 +0000\r\n"
        "From: IT Admin <admin@company.internal>\r\n"
        "To: team@company.internal\r\n"
        "Subject: VPN config attached\r\n"
        "Message-ID: <4@company.internal>\r\n"
        "\r\n"
        "VPN access details for new starters:\r\n\r\n"
        "  Host:     vpn.company.internal:1194\r\n"
        "  Protocol: UDP\r\n"
        "  Username: vpnadmin\r\n"
        "  Password: VpnP@ss2024\r\n\r\n"
        "Config file sent separately via secure channel.\r\n"
    ),
    (
        "Date: Fri, 10 Nov 2023 16:45:00 +0000\r\n"
        "From: SysAdmin <sysadmin@company.internal>\r\n"
        "To: admin@company.internal\r\n"
        "Subject: Root password\r\n"
        "Message-ID: <5@company.internal>\r\n"
        "\r\n"
        "New root password for prod servers:\r\n\r\n"
        "  r00tM3T00!\r\n\r\n"
        "Change after first login. Do NOT forward this email.\r\n"
    ),
    (
        "Date: Sat, 11 Nov 2023 03:12:04 +0000\r\n"
        "From: Backup System <backup@company.internal>\r\n"
        "To: admin@company.internal\r\n"
        "Subject: Backup job failed\r\n"
        "Message-ID: <6@company.internal>\r\n"
        "\r\n"
        "Nightly backup to 192.168.1.50:/mnt/nas FAILED at 03:11 UTC.\r\n\r\n"
        "Error: Authentication failed. Credentials in /etc/backup.conf may be stale.\r\n\r\n"
        "Last successful backup: 2023-11-10 03:11 UTC\r\n"
    ),
    (
        "Date: Sun, 12 Nov 2023 07:04:31 +0000\r\n"
        "From: Security Alerts <alerts@company.internal>\r\n"
        "To: admin@company.internal\r\n"
        "Subject: SSH brute-force alert\r\n"
        "Message-ID: <7@company.internal>\r\n"
        "\r\n"
        "47 failed SSH login attempts detected against prod-web-01.\r\n\r\n"
        "Source IPs: 185.220.101.34, 185.220.101.47, 185.220.101.52\r\n"
        "Target user: root\r\n"
        "Period: 2023-11-12 06:58 - 07:04 UTC\r\n\r\n"
        "All attempts blocked by fail2ban. No successful logins.\r\n"
    ),
    (
        "Date: Mon, 13 Nov 2023 10:11:55 +0000\r\n"
        "From: External Vendor <vendor@external.com>\r\n"
        "To: admin@company.internal\r\n"
        "Subject: RE: API integration\r\n"
        "Message-ID: <8@company.internal>\r\n"
        "\r\n"
        "Hi,\r\n\r\n"
        "Here is the live API key for the integration:\r\n\r\n"
        "  sk_live_9mK3xF2aP7qR1bN8cT4dW6vE0yU5hJ\r\n\r\n"
        "Keep this confidential. Let me know if you need the webhook secret.\r\n\r\n"
        "Best regards,\r\nVendor Support\r\n"
    ),
    (
        "Date: Tue, 14 Nov 2023 13:48:22 +0000\r\n"
        "From: Help Desk <helpdesk@company.internal>\r\n"
        "To: admin@company.internal\r\n"
        "Subject: Password reset request\r\n"
        "Message-ID: <9@company.internal>\r\n"
        "\r\n"
        "Hi,\r\n\r\n"
        "Could you reset my MFA? Current password is Winter2024! so you can verify it's me.\r\n\r\n"
        "Thanks\r\n"
    ),
    (
        "Date: Wed, 15 Nov 2023 00:01:00 +0000\r\n"
        "From: AWS Billing <noreply@aws.amazon.com>\r\n"
        "To: admin@company.internal\r\n"
        "Subject: Your AWS bill is ready\r\n"
        "Message-ID: <10@company.internal>\r\n"
        "\r\n"
        "Your AWS bill for October 2023 is $847.23.\r\n\r\n"
        "Top services:\r\n"
        "  EC2 (us-east-1):   $412.10\r\n"
        "  RDS (us-east-1):   $198.50\r\n"
        "  S3:                 $87.43\r\n"
        "  EC2 (eu-west-2):   $149.20\r\n\r\n"
        "Account ID: 123456789012\r\n"
    ),
]


# ── Spool-backed email loader ─────────────────────────────────────────────────
# POP3 stores each message as a single str (full RFC 822 text).  Seeded
# entries CONCATENATE onto ``_BAIT_EMAILS`` (never replace).  Both .eml
# and .json sources are accepted — JSON dicts are formatted into RFC
# 5322 on load.  Caching strategy matches the IMAP template.

_seed_cache: list[str] | None = None
_seed_cache_path_mtime: float = 0.0
_seed_cache_loaded_at: float = 0.0

_SEED_JSON_REQUIRED = ("from_addr", "to_addr", "subject", "body")


def _seed_dict_to_rfc822(entry: dict) -> str | None:
    """Format a JSON-supplied dict into a full RFC 5322 message string.

    Required keys: from_addr, to_addr, subject, body.  Optional: date,
    from_name.  Returns None for malformed entries (caller skips + logs).
    """
    if not isinstance(entry, dict):
        return None
    for key in _SEED_JSON_REQUIRED:
        if not isinstance(entry.get(key), str) or not entry[key]:
            return None
    from_addr = entry["from_addr"]
    from_name = str(entry.get("from_name") or from_addr.split("@", 1)[0])
    date = str(entry.get("date") or "")
    body = entry["body"]
    if "\r\n\r\n" in body or "\n\n" in body:
        return body  # already a full RFC 822 message
    return (
        f"Date: {date}\r\n"
        f"From: {from_name} <{from_addr}>\r\n"
        f"To: {entry['to_addr']}\r\n"
        f"Subject: {entry['subject']}\r\n"
        "\r\n"
        f"{body}"
    )


def _load_seed_json(path: Path) -> list[str]:
    """Load a JSON list of dicts → list of RFC 822 strings."""
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, ValueError) as exc:
        print(f"pop3: seed json {path} unreadable: {exc}", file=sys.stderr)
        return []
    if not isinstance(data, list):
        print(f"pop3: seed json {path} must be a list", file=sys.stderr)
        return []
    out: list[str] = []
    for i, entry in enumerate(data):
        formatted = _seed_dict_to_rfc822(entry)
        if formatted is None:
            print(f"pop3: seed json {path}[{i}] missing required keys", file=sys.stderr)
            continue
        out.append(formatted)
    return out


def _scan_seed(path: Path) -> list[str]:
    """Resolve *path* into RFC 822 strings (.eml direct, .json formatted)."""
    out: list[str] = []
    try:
        if path.is_dir():
            eml_paths = sorted(
                (p for p in path.rglob("*.eml") if p.is_file()),
                key=lambda p: p.stat().st_mtime,
            )
            for p in eml_paths:
                try:
                    out.append(p.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
            for jp in sorted(p for p in path.rglob("*.json") if p.is_file()):
                out.extend(_load_seed_json(jp))
        elif path.suffix.lower() == ".json" and path.is_file():
            out.extend(_load_seed_json(path))
        elif path.suffix.lower() == ".eml" and path.is_file():
            try:
                out.append(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
    except OSError:
        return []
    return out


def _get_emails() -> list[str]:
    """Return ``_BAIT_EMAILS`` concatenated with seed entries.

    Empty / missing seed → just ``_BAIT_EMAILS``.  Hardcoded baits keep
    indices 1..10; seeded messages start at 11.
    """
    global _seed_cache, _seed_cache_path_mtime, _seed_cache_loaded_at

    if not _EMAIL_SEED_PATH:
        return _BAIT_EMAILS

    seed_path = Path(_EMAIL_SEED_PATH)
    try:
        path_stat = seed_path.stat()
    except OSError:
        return _BAIT_EMAILS

    now = time.monotonic()
    fresh_enough = (
        _seed_cache is not None
        and (now - _seed_cache_loaded_at) < _SEED_RESCAN_INTERVAL
        and path_stat.st_mtime == _seed_cache_path_mtime
    )
    if fresh_enough:
        seed = _seed_cache or []
    else:
        seed = _scan_seed(seed_path)
        _seed_cache = seed
        _seed_cache_path_mtime = path_stat.st_mtime
        _seed_cache_loaded_at = now

    if not seed:
        return _BAIT_EMAILS
    return list(_BAIT_EMAILS) + seed


# ── Logging ───────────────────────────────────────────────────────────────────

def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


# ── Protocol ──────────────────────────────────────────────────────────────────

class POP3Protocol(asyncio.Protocol):
    _transport: asyncio.Transport | None = None
    _peer: tuple[str, int]

    def __init__(self):
        self._transport    = None
        self._peer         = ("?", 0)
        self._buf          = b""
        self._state        = "AUTHORIZATION"
        self._current_user: str | None = None
        self._deleted: set[int] = set()   # 0-based indices of DELE'd messages

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.Transport, transport)
        self._peer = self._transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])
        banner = POP3_BANNER if POP3_BANNER.endswith("\r\n") else POP3_BANNER + "\r\n"
        if not banner.startswith("+OK"):
            banner = "+OK " + banner
        self._transport.write(banner.encode())

    def data_received(self, data):
        self._buf += data
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            self._handle_line(line.decode(errors="replace").strip())

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")

    # ── Command dispatch ──────────────────────────────────────────────────────

    def _handle_line(self, line: str) -> None:
        assert self._transport is not None
        parts = line.split(None, 1)
        if not parts:
            return
        cmd  = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""

        _log("command", src=self._peer[0], cmd=cmd, state=self._state)

        # Always available
        if cmd == "CAPA":
            self._transport.write(
                b"+OK\r\nTOP\r\nUSER\r\nUIDL\r\nRESP-CODES\r\nAUTH-RESP-CODE\r\nSASL\r\n.\r\n"
            )
        elif cmd == "QUIT":
            self._transport.write(b"+OK Logging out.\r\n")
            self._transport.close()

        # AUTHORIZATION state
        elif cmd == "USER":
            self._cmd_user(args)
        elif cmd == "PASS":
            self._cmd_pass(args)

        # TRANSACTION state
        elif cmd == "STAT":
            self._cmd_stat()
        elif cmd == "LIST":
            self._cmd_list(args)
        elif cmd == "RETR":
            self._cmd_retr(args)
        elif cmd == "TOP":
            self._cmd_top(args)
        elif cmd == "UIDL":
            self._cmd_uidl(args)
        elif cmd == "DELE":
            self._cmd_dele(args)
        elif cmd == "RSET":
            self._cmd_rset()
        elif cmd == "NOOP":
            self._transport.write(b"+OK\r\n")

        else:
            self._transport.write(b"-ERR Command not recognized\r\n")

    # ── Command implementations ───────────────────────────────────────────────

    def _cmd_user(self, args: str) -> None:
        assert self._transport is not None
        if self._state != "AUTHORIZATION":
            self._transport.write(b"-ERR Already authenticated\r\n")
            return
        self._current_user = args.strip()
        self._transport.write(b"+OK User name accepted, password please\r\n")

    def _cmd_pass(self, args: str) -> None:
        assert self._transport is not None
        if self._state != "AUTHORIZATION":
            self._transport.write(b"-ERR Already authenticated\r\n")
            return
        if not self._current_user:
            self._transport.write(b"-ERR USER required first\r\n")
            return
        username = self._current_user
        password = args.strip()
        _enc = encode_secret(password)
        if VALID_USERS.get(username) == password:
            self._state = "TRANSACTION"
            _log("auth", src=self._peer[0], username=username, principal=username,
                 outcome="success", **_enc)
            self._transport.write(b"+OK Logged in.\r\n")
        else:
            _log("auth", src=self._peer[0], username=username, principal=username,
                 outcome="failure", severity=SEVERITY_WARNING, **_enc)
            self._current_user = None
            self._transport.write(b"-ERR Authentication failed.\r\n")

    def _require_transaction(self) -> bool:
        assert self._transport is not None
        if self._state != "TRANSACTION":
            self._transport.write(b"-ERR Not authenticated\r\n")
            return False
        return True

    def _active_messages(self) -> list[tuple[int, str]]:
        """Return [(1-based-num, body), ...] excluding DELE'd messages."""
        return [
            (i + 1, body)
            for i, body in enumerate(_get_emails())
            if i not in self._deleted
        ]

    def _cmd_stat(self) -> None:
        assert self._transport is not None
        if not self._require_transaction():
            return
        msgs = self._active_messages()
        total = sum(len(b.encode()) for _, b in msgs)
        self._transport.write(f"+OK {len(msgs)} {total}\r\n".encode())

    def _cmd_list(self, args: str) -> None:
        assert self._transport is not None
        if not self._require_transaction():
            return
        emails = _get_emails()
        if args:
            try:
                n = int(args)
                idx = n - 1
                if idx in self._deleted or not (0 <= idx < len(emails)):
                    self._transport.write(b"-ERR No such message\r\n")
                else:
                    size = len(emails[idx].encode())
                    self._transport.write(f"+OK {n} {size}\r\n".encode())
            except ValueError:
                self._transport.write(b"-ERR Invalid argument\r\n")
        else:
            msgs  = self._active_messages()
            total = sum(len(b.encode()) for _, b in msgs)
            self._transport.write(f"+OK {len(msgs)} messages ({total} octets)\r\n".encode())
            for n, body in msgs:
                self._transport.write(f"{n} {len(body.encode())}\r\n".encode())
            self._transport.write(b".\r\n")

    def _cmd_retr(self, args: str) -> None:
        assert self._transport is not None
        if not self._require_transaction():
            return
        try:
            n   = int(args)
            idx = n - 1
            emails = _get_emails()
            if idx in self._deleted or not (0 <= idx < len(emails)):
                self._transport.write(b"-ERR No such message\r\n")
                return
            body = emails[idx]
            raw  = body.encode()
            _log("retr", src=self._peer[0], message_num=n)
            self._transport.write(f"+OK {len(raw)} octets\r\n".encode())
            self._transport.write(raw)
            if not raw.endswith(b"\r\n"):
                self._transport.write(b"\r\n")
            self._transport.write(b".\r\n")
        except ValueError:
            self._transport.write(b"-ERR Invalid argument\r\n")

    def _cmd_top(self, args: str) -> None:
        assert self._transport is not None
        if not self._require_transaction():
            return
        try:
            parts     = args.split(None, 1)
            n         = int(parts[0])
            line_count = int(parts[1]) if len(parts) > 1 else 0
            idx = n - 1
            emails = _get_emails()
            if idx in self._deleted or not (0 <= idx < len(emails)):
                self._transport.write(b"-ERR No such message\r\n")
                return
            body    = emails[idx]
            sep     = "\r\n\r\n"
            if sep in body:
                headers, rest = body.split(sep, 1)
                headers += sep
            else:
                headers, rest = body, ""
            body_lines = rest.split("\r\n")[:line_count]
            result     = headers + "\r\n".join(body_lines)
            self._transport.write(b"+OK\r\n")
            self._transport.write(result.encode())
            if not result.endswith("\r\n"):
                self._transport.write(b"\r\n")
            self._transport.write(b".\r\n")
        except (ValueError, IndexError):
            self._transport.write(b"-ERR Invalid arguments\r\n")

    def _cmd_uidl(self, args: str) -> None:
        assert self._transport is not None
        if not self._require_transaction():
            return
        if args:
            try:
                n   = int(args)
                idx = n - 1
                if idx in self._deleted or not (0 <= idx < len(_get_emails())):
                    self._transport.write(b"-ERR No such message\r\n")
                else:
                    self._transport.write(f"+OK {n} msg-{n}\r\n".encode())
            except ValueError:
                self._transport.write(b"-ERR Invalid argument\r\n")
        else:
            self._transport.write(b"+OK\r\n")
            for n, _ in self._active_messages():
                self._transport.write(f"{n} msg-{n}\r\n".encode())
            self._transport.write(b".\r\n")

    def _cmd_dele(self, args: str) -> None:
        assert self._transport is not None
        if not self._require_transaction():
            return
        try:
            n   = int(args)
            idx = n - 1
            if idx in self._deleted or not (0 <= idx < len(_get_emails())):
                self._transport.write(b"-ERR No such message\r\n")
            else:
                self._deleted.add(idx)
                _log("delete", src=self._peer[0], message_num=n)
                self._transport.write(f"+OK Message {n} deleted\r\n".encode())
        except ValueError:
            self._transport.write(b"-ERR Invalid argument\r\n")

    def _cmd_rset(self) -> None:
        assert self._transport is not None
        if not self._require_transaction():
            return
        self._deleted.clear()
        self._transport.write(b"+OK\r\n")


async def main():
    _log("startup", msg=f"POP3 server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(POP3Protocol, "0.0.0.0", PORT)  # nosec B104
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
