#!/usr/bin/env python3
"""
Shared RFC 5424 syslog helper used by service containers.

Services call syslog_line() to format an RFC 5424 message, then
write_syslog_file() to emit it to stdout — the container runtime
captures it, and the host-side collector streams it into the log file.

RFC 5424 structure:
  <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ELEMENT] MSG

Facility: local0 (16). SD element ID uses PEN 55555.
"""

from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime, timezone
from typing import Any, Optional

# ─── Constants ────────────────────────────────────────────────────────────────

_FACILITY_LOCAL0 = 16
_SD_ID = "relay@55555"
_NILVALUE = "-"

SEVERITY_EMERG   = 0
SEVERITY_ALERT   = 1
SEVERITY_CRIT    = 2
SEVERITY_ERROR   = 3
SEVERITY_WARNING = 4
SEVERITY_NOTICE  = 5
SEVERITY_INFO    = 6
SEVERITY_DEBUG   = 7

_MAX_HOSTNAME = 255
_MAX_APPNAME  = 48
_MAX_MSGID    = 32

# ─── Formatter ────────────────────────────────────────────────────────────────

def _sd_escape(value: str) -> str:
    """Escape SD-PARAM-VALUE per RFC 5424 §6.3.3."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _sd_element(fields: dict[str, Any]) -> str:
    if not fields:
        return _NILVALUE
    params = " ".join(f'{k}="{_sd_escape(str(v))}"' for k, v in fields.items())
    return f"[{_SD_ID} {params}]"


def syslog_line(
    service: str,
    hostname: str,
    event_type: str,
    severity: int = SEVERITY_INFO,
    timestamp: datetime | None = None,
    msg: str | None = None,
    **fields: Any,
) -> str:
    """
    Return a single RFC 5424-compliant syslog line (no trailing newline).

    Args:
        service:    APP-NAME (e.g. "http", "mysql")
        hostname:   HOSTNAME (node name)
        event_type: MSGID    (e.g. "request", "login_attempt")
        severity:   Syslog severity integer (default: INFO=6)
        timestamp:  UTC datetime; defaults to now
        msg:        Optional free-text MSG
        **fields:   Encoded as structured data params
    """
    pri     = f"<{_FACILITY_LOCAL0 * 8 + severity}>"
    ts      = (timestamp or datetime.now(timezone.utc)).isoformat()
    host    = (hostname or _NILVALUE)[:_MAX_HOSTNAME]
    appname = (service  or _NILVALUE)[:_MAX_APPNAME]
    msgid   = (event_type or _NILVALUE)[:_MAX_MSGID]
    sd      = _sd_element(fields)
    message = f" {msg}" if msg else ""
    return f"{pri}1 {ts} {host} {appname} {_NILVALUE} {msgid} {sd}{message}"


def encode_secret(secret: str) -> dict[str, str]:
    """Standardized credential-secret encoding for the universal SD-block shape.

    Returns ``{'secret_printable': ..., 'secret_b64': ...}`` ready to spread
    into a :func:`syslog_line` / ``_log`` call::

        _log("auth_attempt", principal=user, **encode_secret(password))

    ``secret_printable`` mirrors auth-helper.c's sd_escape: bytes outside
    ``[0x20, 0x7f)`` collapse to ``'?'`` so the field is always parser-safe
    RFC 5424 ASCII. ``secret_b64`` preserves the *original* utf-8 bytes —
    NUL/0xff/control/non-utf8 sequences all survive losslessly, useful as
    a fingerprinting signal even when the printable form sanitizes them.

    The decnet web ingester's native-shape branch keys off ``secret_b64``
    being present, so any service emitter calling this helper lands its
    cred attempt directly in the :class:`Credential` table.
    """
    raw = secret.encode("utf-8", errors="replace")
    printable = "".join(chr(b) if 0x20 <= b < 0x7f else "?" for b in raw)
    return {
        "secret_printable": printable,
        "secret_b64": base64.b64encode(raw).decode("ascii"),
    }


_DIGEST_PARAM_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"|(\w+)\s*=\s*([^,\s]+)')


def classify_authorization(header_value: Optional[str]) -> Optional[dict[str, Any]]:
    """Parse an HTTP Authorization header value into Credential SD fields.

    Returns a dict with the universal cred shape ready to spread into a
    ``_log(...)`` call::

        auth = request.headers.get("Authorization")
        cred = classify_authorization(auth)
        if cred:
            _log("auth_attempt", **cred)

    Recognised schemes:
      * Basic — base64(user:pw); decoded → ``principal=user`` +
        ``secret_kind="plaintext"`` + ``encode_secret(pw)``.
      * Bearer / Token — opaque token; ``principal=None`` +
        ``secret_kind="http_bearer"`` + ``encode_secret(token)``.
      * Digest — ``principal=username`` from header +
        ``secret_kind="http_digest_md5"`` + ``encode_secret(response)``.

    Returns ``None`` for anything unrecognized (AWS4-HMAC-SHA256, NTLM,
    Negotiate, …) — callers can still log the raw header value in the
    ambient SD-block; we just don't know how to extract a hashable
    secret from it.
    """
    if not header_value or not isinstance(header_value, str):
        return None
    parts = header_value.strip().split(None, 1)
    if len(parts) < 2:
        return None
    scheme, rest = parts[0].lower(), parts[1].strip()

    if scheme == "basic":
        try:
            decoded = base64.b64decode(rest, validate=True).decode("utf-8", errors="replace")
        except (ValueError, binascii.Error):
            return None
        if ":" not in decoded:
            return None
        user, _, pw = decoded.partition(":")
        return {
            "principal": user,
            "secret_kind": "plaintext",
            **encode_secret(pw),
        }

    if scheme in ("bearer", "token"):
        return {
            "principal": None,
            "secret_kind": "http_bearer",
            **encode_secret(rest),
        }

    if scheme == "digest":
        params: dict[str, str] = {}
        for m in _DIGEST_PARAM_RE.finditer(rest):
            k = m.group(1) or m.group(3)
            v = m.group(2) if m.group(2) is not None else m.group(4)
            if k:
                params[k.lower()] = v
        response = params.get("response")
        if not response:
            return None
        return {
            "principal": params.get("username"),
            "secret_kind": "http_digest_md5",
            **encode_secret(response),
        }

    return None


_FORM_PRINCIPAL_KEYS = (
    "username", "user", "email", "login", "userid", "account",
    "log",        # wp-login.php
    "user_login", # WordPress alt
    "uname",      # phpMyAdmin
    "pma_username",
)
_FORM_SECRET_KEYS = (
    "password", "pass", "pwd", "passwd", "passwort", "mot_de_passe",
    "user_password",   # WordPress alt
    "pma_password",    # phpMyAdmin
)


def extract_form_credentials(
    body: Optional[str],
    content_type: Optional[str],
) -> Optional[dict[str, Any]]:
    """Parse an `application/x-www-form-urlencoded` body for credentials.

    Returns the universal cred SD shape ready to spread into a
    ``_log(...)`` call when both a principal-shaped key and a secret-
    shaped key are present in the body. Otherwise returns ``None``.

    Field-name detection is case-insensitive and covers the most common
    login-form variants (WordPress wp-login.php, phpMyAdmin, Joomla,
    etc.). Add more entries to ``_FORM_PRINCIPAL_KEYS`` /
    ``_FORM_SECRET_KEYS`` as new templates surface them.
    """
    if not body or not isinstance(content_type, str):
        return None
    if not content_type.lower().startswith("application/x-www-form-urlencoded"):
        return None

    fields: dict[str, str] = {}
    for pair in body.split("&"):
        if "=" not in pair:
            continue
        k, _, v = pair.partition("=")
        # urllib decode without importing urllib at module scope (the
        # template emitters are import-cost-sensitive). Inline the
        # tiny percent-decode + plus-decode.
        try:
            from urllib.parse import unquote_plus
            key = unquote_plus(k).lower()
            val = unquote_plus(v)
        except Exception:
            continue
        # First-wins so duplicate-key forms don't get clobbered.
        fields.setdefault(key, val)

    principal: Optional[str] = None
    for k in _FORM_PRINCIPAL_KEYS:
        if k in fields:
            principal = fields[k]
            break
    secret: Optional[str] = None
    for k in _FORM_SECRET_KEYS:
        if k in fields:
            secret = fields[k]
            break
    if secret is None:
        return None
    return {
        "principal": principal,
        "secret_kind": "plaintext",
        **encode_secret(secret),
    }


def write_syslog_file(line: str) -> None:
    """Emit a syslog line to stdout for container log capture."""
    print(line, flush=True)


def forward_syslog(line: str, log_target: str) -> None:
    """No-op stub. TCP forwarding is handled by rsyslog, not by service containers."""
    pass
