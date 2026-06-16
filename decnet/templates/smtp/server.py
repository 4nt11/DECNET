#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
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
import binascii
import hashlib
import io
import json
import os
import random as _rand
import re
import time
import zipfile
from datetime import datetime, timezone
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message
from typing import cast

try:
    from lxml import html as _lxml_html
except Exception:  # pragma: no cover — defensive when lxml unavailable
    _lxml_html = None

import instance_seed as _seed
from syslog_bridge import (
    SEVERITY_WARNING,
    encode_secret,
    forward_syslog,
    syslog_line,
    write_syslog_file,
)

NODE_NAME   = os.environ.get("NODE_NAME", "mailserver")
SERVICE_NAME = os.environ.get("SMTP_SERVICE_NAME", "smtp")
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
# Body-URL extraction. Tight enough to skip stray text that happens to
# start with "http"; loose enough to catch IDN punycode, query strings,
# and the trailing-paren / trailing-period tokens that bare-URL regexes
# typically over-capture. Anchored on whitespace / quote / angle-bracket
# boundaries so URLs inside `<a href="...">` round-trip cleanly.
_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+")
# Authentication-Results parsing. We only care about the binary
# pass-or-not for dkim and spf — finer-grained verdicts (neutral /
# softfail / temperror) are evidence at best and the EmailLifter does
# not key on them.
_DKIM_PASS_RE = re.compile(r"\bdkim\s*=\s*pass\b", re.IGNORECASE)
_SPF_PASS_RE  = re.compile(r"\bspf\s*=\s*pass\b",  re.IGNORECASE)
# Base64 chunk detector. Mirrors the regex the EmailLifter uses
# (`decnet/ttp/impl/email_lifter.py:_BASE64_RE`) so the decky-side
# precompute and the lifter's fallback agree on chunk boundaries.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
# Token boundary for body simhash. Lower-cased and word-class only so
# whitespace mutations and punctuation flips don't fragment the token
# stream.
_SIMHASH_TOKEN_RE = re.compile(r"\w+", re.UNICODE)
# HTML-smuggling regex fallback, used when lxml is unavailable or fails
# to parse a malformed body. Combines the three structural signals into
# one OR-combined regex; FP rate is higher than the lxml path so it is
# only the second-pass safety net.
_HTML_SMUGGLE_RE = re.compile(
    r"<a\s+[^>]*\bdownload\b[^>]*>"
    r"|new\s+Blob\s*\("
    r"|new\s+Uint8Array\s*\("
    r"|window\.URL\.createObjectURL\s*\(",
    re.IGNORECASE,
)
# Magic-bytes for the encrypted-archive bool. Compared after stripping
# leading whitespace; first 8 bytes is enough for every format we
# recognise. ZIP / docx / xlsx round-trip via the central directory's
# encryption flag and aren't here.
_MAGIC_7Z   = b"7z\xBC\xAF\x27\x1C"
_MAGIC_RAR  = b"Rar!\x1A\x07"
_MAGIC_CFBF = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"


def _empty_summary() -> dict:
    return {
        "subject": "", "from_hdr": "", "to_hdr": "", "date_hdr": "",
        "message_id_hdr": "", "content_type": "",
        "return_path": "", "x_mailer": "",
        "dkim_signed": False, "spf_pass": False,
        "attachments": [], "urls": [],
        "body_simhash": "", "body_base64_bytes": 0,
        "html_smuggling": False,
    }


def _body_simhash(body_text: str) -> str:
    """Charikar 64-bit simhash over word tokens, hex-encoded.

    Inlined rather than pulling the ``simhash`` PyPI dep (which
    transitively brings numpy ~50 MB into a slim decky container) —
    the algorithm is ~15 lines and fully equivalent for this use.
    Token weighting is by frequency; per-token hash is md5[:8] for
    speed (this is a content fingerprint, not a security primitive).

    Returns a 16-hex-char string, or ``""`` on empty/no-token input
    (the lifter's ``_p_mass_phish`` predicate accepts str|int and
    rejects non-strings, so the empty case is "no signal" — exactly
    what we want when a multipart message has no usable text body).
    """
    tokens = _SIMHASH_TOKEN_RE.findall(body_text.lower()) if body_text else []
    if not tokens:
        return ""
    counts: dict[str, int] = {}
    for tok in tokens:
        counts[tok] = counts.get(tok, 0) + 1
    bits = [0] * 64
    for tok, weight in counts.items():
        h = int.from_bytes(
            hashlib.md5(tok.encode("utf-8", errors="replace")).digest()[:8],  # noqa: S324
            "big",
        )
        for i in range(64):
            if h & (1 << i):
                bits[i] += weight
            else:
                bits[i] -= weight
    out = 0
    for i in range(64):
        if bits[i] > 0:
            out |= (1 << i)
    return format(out, "016x")


def _body_base64_bytes(body_text: str) -> int:
    """Largest decoded base64 chunk's byte count in the body, or 0.

    Mirrors the EmailLifter's ``_p_encoded_payload`` fallback exactly:
    iterate ``_BASE64_RE`` matches, attempt strict decode, return the
    largest decoded length seen. Computed once decky-side so the
    lifter never has to scan body text — R0048 fires from this
    scalar alone.
    """
    if not body_text:
        return 0
    largest = 0
    for m in _BASE64_RE.finditer(body_text):
        chunk = m.group(0)
        try:
            decoded = base64.b64decode(chunk, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) > largest:
            largest = len(decoded)
    return largest


def _attachment_macro_indicator(payload: bytes, filename: str) -> bool:
    """True if the attachment is an OOXML container with a VBA macro
    stream (``vbaProject.bin``).

    Modern macro-bearing Office files (.docm / .xlsm / .pptm and
    .docx with injected macros) are zip containers carrying a
    ``word/vbaProject.bin`` (or analogous) entry. Catches ~95% of
    in-the-wild macro phishing. Legacy .xls (CFBF, not zip) is a
    follow-up — see DEBT entry.
    """
    if not payload or len(payload) < 4 or payload[:2] != b"PK":
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            for name in zf.namelist():
                if name.endswith("vbaProject.bin"):
                    return True
    except (zipfile.BadZipFile, OSError, ValueError):
        return False
    return False


def _attachment_encrypted(payload: bytes, filename: str) -> bool:
    """True if the attachment is an encrypted/password-protected
    archive or Office container.

    ZIP / OOXML: read the central directory's encryption bit
    (``flag_bits & 0x1`` on any entry).
    7z / RAR: file-magic match.
    Encrypted Office (XLSX-with-password): wrapped in a CFBF
    container (magic ``D0 CF 11 E0``) — catch on filename hint.
    """
    if not payload or len(payload) < 8:
        return False
    head = payload[:8]
    if head.startswith(_MAGIC_7Z) or head.startswith(_MAGIC_RAR):
        return True
    if head.startswith(_MAGIC_CFBF):
        # Naked CFBF without an Office filename is rare; treat any
        # CFBF as potentially encrypted Office for the bool flag.
        return True
    if payload[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        return True
        except (zipfile.BadZipFile, OSError, ValueError):
            return False
    return False


def _html_smuggling(msg: Message) -> bool:
    """True if any text/html part exhibits the HTML-smuggling shape.

    Structural lxml parse first: walk anchors and scripts, fire when
    an ``<a>`` carries a ``download`` attribute AND a sibling /
    near-ancestor ``<script>`` references one of the canonical
    blob-builder primitives (``new Blob(``, ``new Uint8Array(``,
    ``URL.createObjectURL(``). Real-world phish HTML is often
    malformed enough to break lxml; on parse failure we fall back
    to a regex pass that combines the same indicators in one body
    (higher FP rate, but catches the malformed cases lxml drops).
    """
    for part in msg.walk():
        if part.is_multipart():
            continue
        if (part.get_content_type() or "").lower() != "text/html":
            continue
        try:
            raw = part.get_payload(decode=True) or b""
            text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else ""
        except Exception:
            text = ""
        if not text:
            continue
        if _lxml_html is not None:
            try:
                tree = _lxml_html.fromstring(text)
            except Exception:
                tree = None
            if tree is not None:
                anchors_with_download = tree.xpath(
                    "//a[@download or @*[name()='download']]",
                )
                if anchors_with_download:
                    scripts = tree.xpath("//script")
                    blob_re = re.compile(
                        r"new\s+Blob\s*\("
                        r"|new\s+Uint8Array\s*\("
                        r"|URL\.createObjectURL\s*\(",
                        re.IGNORECASE,
                    )
                    for script in scripts:
                        script_text = (script.text or "") + (script.tail or "")
                        if blob_re.search(script_text):
                            return True
                # Fall through to regex if lxml found no smoking gun
                # — malformed HTML may have lost structure during
                # parse-and-serialize.
        if _HTML_SMUGGLE_RE.search(text):
            # Pair check: at least two distinct indicator classes
            # must hit so a stray ``<a download>`` link in a
            # legitimate "click to download our report" mail does
            # not fire on its own.
            anchor_hit = re.search(
                r"<a\s+[^>]*\bdownload\b", text, re.IGNORECASE,
            )
            blob_hit = re.search(
                r"new\s+Blob\s*\("
                r"|new\s+Uint8Array\s*\("
                r"|window\.URL\.createObjectURL\s*\(",
                text, re.IGNORECASE,
            )
            if anchor_hit and blob_hit:
                return True
    return False


def _extract_urls(msg: Message) -> list[str]:
    """Walk text/* parts and return the unique http(s) URLs found.

    Order is preserved (first-seen wins) so the lifter's IDN-punycode
    check and the SIEM evidence list are stable across runs. The walker
    intentionally skips non-text parts: HTML-smuggling decode of binary
    blobs is a heavyweight detector deferred to the EmailLifter follow-
    up DEBT entry, not in scope for the cheap projection.
    """
    seen: dict[str, None] = {}
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "").lower()
        if not ctype.startswith("text/"):
            continue
        try:
            raw = part.get_payload(decode=True) or b""
            text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else ""
        except Exception:
            text = ""
        for match in _URL_RE.findall(text):
            # Strip trailing punctuation that frequently rides on URLs in
            # natural-language bodies ("see https://x.com.").
            url = match.rstrip(".,;:!?")
            if url and url not in seen:
                seen[url] = None
    return list(seen.keys())


def _summarize_message(body: bytes, msg_id: str) -> dict:
    """Parse the DATA body and extract forensic metadata.

    Returns a dict with:
        subject, from_hdr, to_hdr, date_hdr, message_id_hdr,
        content_type, return_path, x_mailer, dkim_signed, spf_pass,
        attachments (list of {filename, content_type, size, sha256}),
        urls (list of http(s) URLs from text/* parts).

    Headers are RFC 2047 decoded. Attachment hashing uses the *decoded*
    payload so operators can match against VT / MalwareBazaar directly.
    `dkim_signed` / `spf_pass` are derived from any
    ``Authentication-Results:`` header line (multiple lines tolerated;
    a positive verdict on any line counts).
    """
    try:
        msg: Message = message_from_bytes(body)
    except Exception:
        return _empty_summary()

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
            _raw = part.get_payload(decode=True) or b""
            payload: bytes = _raw if isinstance(_raw, bytes) else b""
        except Exception:
            payload = b""
        decoded_filename = _decode_header(filename) or ""
        attachments.append({
            "filename": decoded_filename,
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
            "macro_indicator": _attachment_macro_indicator(payload, decoded_filename),
            "encrypted": _attachment_encrypted(payload, decoded_filename),
        })

    auth_results = " | ".join(
        v for v in msg.get_all("Authentication-Results") or [] if v
    )
    # Concatenate all text/* body parts for simhash + base64-bytes
    # computation. The simhash should be order-independent across
    # multipart alternatives (text/plain + text/html), so we treat
    # the union as one document — different attackers' templates
    # will diverge in word distribution regardless of the multipart
    # arrangement.
    body_text_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if not (part.get_content_type() or "").lower().startswith("text/"):
            continue
        try:
            raw = part.get_payload(decode=True) or b""
            text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else ""
        except Exception:
            text = ""
        if text:
            body_text_parts.append(text)
    body_text = "\n".join(body_text_parts)
    return {
        "subject": _decode_header(msg.get("Subject")),
        "from_hdr": _decode_header(msg.get("From")),
        "to_hdr": _decode_header(msg.get("To")),
        "date_hdr": _decode_header(msg.get("Date")),
        "message_id_hdr": _decode_header(msg.get("Message-ID")),
        "content_type": msg.get_content_type(),
        "return_path": _decode_header(msg.get("Return-Path")),
        "x_mailer": _decode_header(msg.get("X-Mailer")),
        "dkim_signed": bool(_DKIM_PASS_RE.search(auth_results)),
        "spf_pass": bool(_SPF_PASS_RE.search(auth_results)),
        "attachments": attachments,
        "urls": _extract_urls(msg),
        "body_simhash": _body_simhash(body_text),
        "body_base64_bytes": _body_base64_bytes(body_text),
        "html_smuggling": _html_smuggling(msg),
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
    _transport: asyncio.Transport | None = None
    _peer: tuple[str, int]

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

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.Transport, transport)
        self._peer = self._transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])
        self._transport.write(f"{_SMTP_BANNER}\r\n".encode())

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
        assert self._transport is not None
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
                        # Header-derived signals consumed by EmailLifter
                        # R0043 / R0044 / R0045. Truncated to bound the
                        # SD-value size; the lifter only needs presence
                        # + domain extraction.
                        return_path=summary["return_path"][:256],
                        x_mailer=summary["x_mailer"][:256],
                        dkim_signed=int(summary["dkim_signed"]),
                        spf_pass=int(summary["spf_pass"]),
                        attachment_count=len(summary["attachments"]),
                        # Full manifest (filename/sha256/size/content_type
                        # + macro_indicator/encrypted booleans) rides as
                        # a compact JSON blob — the SD-value escape in
                        # syslog_bridge handles the quotes and brackets.
                        # Per-attachment booleans are reduced to top-
                        # level flags by the master ingester at publish
                        # time.
                        attachments_json=json.dumps(summary["attachments"], separators=(",", ":")),
                        # URL list extracted from text/* body parts;
                        # capped at 64 entries to bound the syslog SD
                        # value. Spam kits with hundreds of unique URLs
                        # are rare and the cap is loud-friendly.
                        urls_json=json.dumps(summary["urls"][:64], separators=(",", ":")),
                        # Heavyweight Layer-2 body signals consumed by
                        # EmailLifter R0042 / R0046 / R0048. Booleans
                        # ride as 0/1 ints because syslog SD-values are
                        # strings; the ingester coerces back at publish
                        # time. body_simhash is a 16-hex-char string;
                        # body_base64_bytes is the largest decoded
                        # base64 chunk's byte count (0 if none).
                        body_simhash=summary["body_simhash"],
                        body_base64_bytes=summary["body_base64_bytes"],
                        html_smuggling=int(summary["html_smuggling"]),
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
            # Strip <…> wrappers around the address; everything after the
            # last @ is the domain. Empty when the attacker sent <> or a
            # malformed envelope; keeping value= for back-compat with any
            # log query that still reads it.
            _bare = addr.strip("<>").strip()
            _domain = _bare.rsplit("@", 1)[-1] if "@" in _bare else ""
            _log("mail_from", src=self._peer[0], value=addr,
                 mail_from=_bare, domain=_domain)
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
        assert self._transport is not None
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
        assert self._transport is not None
        _log("auth_attempt", src=self._peer[0],
             username=username, principal=username,
             severity=SEVERITY_WARNING, **encode_secret(password))
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
