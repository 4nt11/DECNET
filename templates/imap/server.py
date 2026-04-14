#!/usr/bin/env python3
"""
IMAP server (port 143).
Full IMAP4rev1 state machine with bait mailbox.

States: NOT_AUTHENTICATED → AUTHENTICATED → SELECTED

Credentials via IMAP_USERS env var ("user:pass,user2:pass2").
10 bait emails in INBOX containing AWS keys, DB passwords, tokens etc.
Banner advertises Dovecot so nmap fingerprints correctly.
"""

import asyncio
import os
from decnet_logging import SEVERITY_WARNING, syslog_line, write_syslog_file, forward_syslog

NODE_NAME   = os.environ.get("NODE_NAME", "mailserver")
SERVICE_NAME = "imap"
LOG_TARGET  = os.environ.get("LOG_TARGET", "")
PORT        = int(os.environ.get("PORT", "143"))
IMAP_BANNER = os.environ.get("IMAP_BANNER", "* OK Dovecot ready.\r\n")
_RAW_USERS  = os.environ.get("IMAP_USERS", "admin:admin123,root:toor,mail:mail,user:user")

VALID_USERS: dict[str, str] = {
    u: p for part in _RAW_USERS.split(",") if ":" in part for u, p in [part.split(":", 1)]
}

# DEBT-026: path to a JSON file with custom email definitions.
# When set, _BAIT_EMAILS should be replaced/extended from that file.
# Wiring (service_cfg["email_seed"] → compose_fragment → env var → here) is deferred.
_EMAIL_SEED_PATH = os.environ.get("IMAP_EMAIL_SEED", "")  # stub — currently unused

# ── Bait emails ───────────────────────────────────────────────────────────────
# All 10 live in INBOX. UID == sequence number.

_BAIT_EMAILS: list[dict] = [
    {
        "uid": 1, "flags": [r"\Seen"],
        "from_name": "DevOps Team", "from_addr": "devops@company.internal",
        "to_addr": "admin@company.internal",
        "subject": "AWS credentials rotation",
        "date": "Mon, 06 Nov 2023 09:12:33 +0000",
        "body": (
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
    },
    {
        "uid": 2, "flags": [r"\Seen"],
        "from_name": "Monitoring", "from_addr": "monitoring@company.internal",
        "to_addr": "admin@company.internal",
        "subject": "DB password changed",
        "date": "Tue, 07 Nov 2023 14:05:11 +0000",
        "body": (
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
    },
    {
        "uid": 3, "flags": [],
        "from_name": "GitHub", "from_addr": "noreply@github.com",
        "to_addr": "admin@company.internal",
        "subject": "Your personal access token",
        "date": "Wed, 08 Nov 2023 08:30:00 +0000",
        "body": (
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
    },
    {
        "uid": 4, "flags": [r"\Seen"],
        "from_name": "IT Admin", "from_addr": "admin@company.internal",
        "to_addr": "team@company.internal",
        "subject": "VPN config attached",
        "date": "Thu, 09 Nov 2023 11:22:47 +0000",
        "body": (
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
    },
    {
        "uid": 5, "flags": [],
        "from_name": "SysAdmin", "from_addr": "sysadmin@company.internal",
        "to_addr": "admin@company.internal",
        "subject": "Root password",
        "date": "Fri, 10 Nov 2023 16:45:00 +0000",
        "body": (
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
    },
    {
        "uid": 6, "flags": [r"\Seen"],
        "from_name": "Backup System", "from_addr": "backup@company.internal",
        "to_addr": "admin@company.internal",
        "subject": "Backup job failed",
        "date": "Sat, 11 Nov 2023 03:12:04 +0000",
        "body": (
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
    },
    {
        "uid": 7, "flags": [r"\Seen"],
        "from_name": "Security Alerts", "from_addr": "alerts@company.internal",
        "to_addr": "admin@company.internal",
        "subject": "SSH brute-force alert",
        "date": "Sun, 12 Nov 2023 07:04:31 +0000",
        "body": (
            "Date: Sun, 12 Nov 2023 07:04:31 +0000\r\n"
            "From: Security Alerts <alerts@company.internal>\r\n"
            "To: admin@company.internal\r\n"
            "Subject: SSH brute-force alert\r\n"
            "Message-ID: <7@company.internal>\r\n"
            "\r\n"
            "47 failed SSH login attempts detected against prod-web-01.\r\n\r\n"
            "Source IPs: 185.220.101.34, 185.220.101.47, 185.220.101.52\r\n"
            "Target user: root\r\n"
            "Period: 2023-11-12 06:58 – 07:04 UTC\r\n\r\n"
            "All attempts blocked by fail2ban. No successful logins.\r\n"
        ),
    },
    {
        "uid": 8, "flags": [r"\Seen"],
        "from_name": "External Vendor", "from_addr": "vendor@external.com",
        "to_addr": "admin@company.internal",
        "subject": "RE: API integration",
        "date": "Mon, 13 Nov 2023 10:11:55 +0000",
        "body": (
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
    },
    {
        "uid": 9, "flags": [],
        "from_name": "Help Desk", "from_addr": "helpdesk@company.internal",
        "to_addr": "admin@company.internal",
        "subject": "Password reset request",
        "date": "Tue, 14 Nov 2023 13:48:22 +0000",
        "body": (
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
    },
    {
        "uid": 10, "flags": [r"\Seen"],
        "from_name": "AWS Billing", "from_addr": "noreply@aws.amazon.com",
        "to_addr": "admin@company.internal",
        "subject": "Your AWS bill is ready",
        "date": "Wed, 15 Nov 2023 00:01:00 +0000",
        "body": (
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
    },
]

_MAILBOXES = ["INBOX", "Sent", "Drafts", "Archive"]

# ── Logging ───────────────────────────────────────────────────────────────────

def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)

# ── FETCH helpers ─────────────────────────────────────────────────────────────

def _parse_seq_range(range_str: str, total: int) -> list[int]:
    """Parse IMAP sequence set ('1', '1:3', '1:*', '*') → list of 1-based indices."""
    result = []
    for part in range_str.split(","):
        part = part.strip()
        if ":" in part:
            lo_s, hi_s = part.split(":", 1)
            lo = total if lo_s == "*" else int(lo_s)
            hi = total if hi_s == "*" else int(hi_s)
            result.extend(range(min(lo, hi), max(lo, hi) + 1))
        elif part == "*":
            result.append(total)
        else:
            result.append(int(part))
    return [n for n in result if 1 <= n <= total]


def _parse_fetch_items(items_str: str) -> list[str]:
    """Parse '(FLAGS ENVELOPE)' or 'BODY[]' → list of item name strings."""
    s = items_str.strip()
    if s.startswith("(") and s.endswith(")"):
        s = s[1:-1]
    tokens, i = [], 0
    while i < len(s):
        if s[i] == " ":
            i += 1
            continue
        j, depth = i, 0
        while j < len(s):
            if s[j] == "[":
                depth += 1
            elif s[j] == "]":
                depth -= 1
            elif s[j] == " " and depth == 0:
                break
            j += 1
        tokens.append(s[i:j].upper())
        i = j
    return tokens


def _envelope(msg: dict) -> str:
    """Build minimal RFC 3501 ENVELOPE tuple string."""
    def addr(name: str, email: str) -> str:
        parts = email.split("@", 1)
        user = parts[0]
        host = parts[1] if len(parts) > 1 else ""
        safe_name = name.replace('"', '\\"')
        return f'("{safe_name}" NIL "{user}" "{host}")'

    from_addr = addr(msg["from_name"], msg["from_addr"])
    to_addr   = addr("", msg["to_addr"])
    subject   = msg["subject"].replace('"', '\\"')
    return (
        f'("{msg["date"]}" "{subject}" '
        f'({from_addr}) ({from_addr}) ({from_addr}) '
        f'({to_addr}) NIL NIL NIL "<{msg["uid"]}@{NODE_NAME}>")'
    )


def _build_fetch_response(seq: int, msg: dict, items: list[str]) -> bytes:
    """Build the bytes for a single '* N FETCH (...)' response."""
    non_literal: list[str] = []
    literal_name: str | None = None
    literal_raw:  bytes | None = None

    for item in items:
        norm = item.upper()
        if norm == "FLAGS":
            flags = " ".join(msg["flags"]) if msg["flags"] else ""
            non_literal.append(f"FLAGS ({flags})")
        elif norm == "ENVELOPE":
            non_literal.append(f"ENVELOPE {_envelope(msg)}")
        elif norm == "RFC822.SIZE":
            non_literal.append(f"RFC822.SIZE {len(msg['body'].encode())}")
        elif norm in ("UID",):
            non_literal.append(f"UID {msg['uid']}")
        elif norm in ("BODY[]", "RFC822", "BODY[TEXT]", "BODY.PEEK[]"):
            literal_name = "BODY[]"
            literal_raw  = msg["body"].encode()
        elif norm in ("BODY[HEADER]", "BODY.PEEK[HEADER]"):
            header_part  = msg["body"].split("\r\n\r\n", 1)[0] + "\r\n\r\n"
            literal_name = "BODY[HEADER]"
            literal_raw  = header_part.encode()
        # unknown items silently ignored

    if literal_raw is not None:
        prefix_str = (" ".join(non_literal) + " ") if non_literal else ""
        header = f"* {seq} FETCH ({prefix_str}{literal_name} {{{len(literal_raw)}}}\r\n".encode()
        return header + literal_raw + b")\r\n"
    else:
        return f"* {seq} FETCH ({' '.join(non_literal)})\r\n".encode()


# ── Protocol ──────────────────────────────────────────────────────────────────

class IMAPProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport  = None
        self._peer       = ("?", 0)
        self._buf        = b""
        self._state      = "NOT_AUTHENTICATED"
        self._selected   = None   # mailbox name currently selected

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])
        banner = IMAP_BANNER if IMAP_BANNER.endswith("\r\n") else IMAP_BANNER + "\r\n"
        transport.write(banner.encode())

    def data_received(self, data):
        self._buf += data
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            self._handle_line(line.decode(errors="replace").strip())

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")

    # ── Command dispatch ──────────────────────────────────────────────────────

    def _handle_line(self, line: str) -> None:
        parts = line.split(None, 2)
        if not parts:
            return
        tag = parts[0]
        cmd = parts[1].upper() if len(parts) > 1 else ""
        args = parts[2] if len(parts) > 2 else ""

        _log("command", src=self._peer[0], cmd=cmd, state=self._state)

        # Commands valid in any state
        if cmd == "CAPABILITY":
            self._w(b"* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS"
                    b" ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN\r\n")
            self._w(f"{tag} OK CAPABILITY completed\r\n")

        elif cmd == "NOOP":
            self._w(f"{tag} OK\r\n")

        elif cmd == "LOGOUT":
            self._w(b"* BYE Logging out\r\n")
            self._w(f"{tag} OK LOGOUT completed\r\n")
            self._transport.close()

        # NOT_AUTHENTICATED only
        elif cmd == "LOGIN":
            self._cmd_login(tag, args)

        # AUTHENTICATED or SELECTED
        elif cmd in ("LIST", "LSUB"):
            self._cmd_list(tag, cmd)
        elif cmd == "STATUS":
            self._cmd_status(tag, args)
        elif cmd in ("SELECT", "EXAMINE"):
            self._cmd_select(tag, cmd, args)

        # SELECTED only
        elif cmd == "FETCH":
            self._cmd_fetch(tag, args, use_uid=False)
        elif cmd == "SEARCH":
            self._cmd_search(tag)
        elif cmd == "CLOSE":
            self._cmd_close(tag)

        # UID prefix — dispatch sub-command
        elif cmd == "UID":
            sub_parts = args.split(None, 1)
            sub_cmd  = sub_parts[0].upper() if sub_parts else ""
            sub_args = sub_parts[1] if len(sub_parts) > 1 else ""
            if sub_cmd == "FETCH":
                self._cmd_fetch(tag, sub_args, use_uid=True)
            elif sub_cmd == "SEARCH":
                self._cmd_search(tag, uid_mode=True)
            else:
                self._w(f"{tag} BAD Unknown UID sub-command\r\n")

        else:
            self._w(f"{tag} BAD Command not recognized or not supported\r\n")

    # ── Command implementations ───────────────────────────────────────────────

    def _cmd_login(self, tag: str, args: str) -> None:
        if self._state != "NOT_AUTHENTICATED":
            self._w(f"{tag} BAD Already authenticated\r\n")
            return
        parts    = args.split(None, 1)
        username = parts[0].strip('"') if parts else ""
        password = parts[1].strip('"') if len(parts) > 1 else ""
        if VALID_USERS.get(username) == password:
            self._state = "AUTHENTICATED"
            _log("auth", src=self._peer[0], username=username, password=password,
                 status="success")
            self._w(f"{tag} OK [CAPABILITY IMAP4rev1] Logged in\r\n")
        else:
            _log("auth", src=self._peer[0], username=username, password=password,
                 status="failed", severity=SEVERITY_WARNING)
            self._w(f"{tag} NO [AUTHENTICATIONFAILED] Authentication failed.\r\n")

    def _cmd_list(self, tag: str, cmd: str) -> None:
        if self._state == "NOT_AUTHENTICATED":
            self._w(f"{tag} BAD Not authenticated\r\n")
            return
        for box in _MAILBOXES:
            self._w(f'* {cmd} (\\HasNoChildren) "/" "{box}"\r\n')
        self._w(f"{tag} OK {cmd} completed\r\n")

    def _cmd_status(self, tag: str, args: str) -> None:
        if self._state == "NOT_AUTHENTICATED":
            self._w(f"{tag} BAD Not authenticated\r\n")
            return
        parts   = args.split(None, 1)
        mailbox = parts[0].strip('"') if parts else "INBOX"
        attr_str = parts[1].strip("()").upper() if len(parts) > 1 else "MESSAGES"

        counts = {"MESSAGES": 10, "RECENT": 0, "UNSEEN": 10} if mailbox == "INBOX" \
            else {"MESSAGES": 0, "RECENT": 0, "UNSEEN": 0}

        result_parts = []
        for attr in attr_str.split():
            if attr in counts:
                result_parts.append(f"{attr} {counts[attr]}")
        self._w(f"* STATUS {mailbox} ({' '.join(result_parts)})\r\n")
        self._w(f"{tag} OK STATUS completed\r\n")

    def _cmd_select(self, tag: str, cmd: str, args: str) -> None:
        if self._state == "NOT_AUTHENTICATED":
            self._w(f"{tag} BAD Not authenticated\r\n")
            return
        mailbox = args.strip('"')
        total   = len(_BAIT_EMAILS) if mailbox == "INBOX" else 0
        self._selected = mailbox
        self._state    = "SELECTED"
        self._w(f"* {total} EXISTS\r\n")
        self._w(b"* 0 RECENT\r\n")
        self._w(b"* OK [UNSEEN 1] Message 1 is first unseen\r\n")
        self._w(b"* OK [UIDVALIDITY 1712345678] UIDs valid\r\n")
        self._w(f"* OK [UIDNEXT {total + 1}] Predicted next UID\r\n")
        self._w(b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n")
        self._w(b"* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited\r\n")
        mode = "READ-ONLY" if cmd == "EXAMINE" else "READ-WRITE"
        self._w(f"{tag} OK [{mode}] {cmd} completed\r\n")

    def _cmd_fetch(self, tag: str, args: str, use_uid: bool) -> None:
        if self._state != "SELECTED":
            self._w(f"{tag} BAD Not in selected state\r\n")
            return
        parts     = args.split(None, 1)
        range_str = parts[0] if parts else "1:*"
        items_str = parts[1] if len(parts) > 1 else "FLAGS"

        total    = len(_BAIT_EMAILS)
        indices  = _parse_seq_range(range_str, total)
        items    = _parse_fetch_items(items_str)
        # Ensure UID is included when using UID FETCH
        if use_uid and "UID" not in items:
            items = ["UID"] + items

        for seq in indices:
            if 1 <= seq <= total:
                self._transport.write(_build_fetch_response(seq, _BAIT_EMAILS[seq - 1], items))
        self._w(f"{tag} OK FETCH completed\r\n")

    def _cmd_search(self, tag: str, uid_mode: bool = False) -> None:
        if self._state != "SELECTED":
            self._w(f"{tag} BAD Not in selected state\r\n")
            return
        nums = " ".join(str(i) for i in range(1, len(_BAIT_EMAILS) + 1))
        self._w(f"* SEARCH {nums}\r\n")
        self._w(f"{tag} OK SEARCH completed\r\n")

    def _cmd_close(self, tag: str) -> None:
        if self._state != "SELECTED":
            self._w(f"{tag} BAD Not in selected state\r\n")
            return
        self._state    = "AUTHENTICATED"
        self._selected = None
        self._w(f"{tag} OK CLOSE completed\r\n")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _w(self, data: str | bytes) -> None:
        if isinstance(data, str):
            data = data.encode()
        self._transport.write(data)


async def main():
    _log("startup", msg=f"IMAP server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(IMAPProtocol, "0.0.0.0", PORT)  # nosec B104
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
