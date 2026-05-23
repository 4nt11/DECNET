# SPDX-License-Identifier: AGPL-3.0-or-later
"""SMTP probe-relay driver.

Forwards the attacker's first probe email via the master's real internet
connection. The smtp_relay decky runs on MACVLAN and has no gateway access;
the master (where this worker runs) does.

Called by the realism worker's smtp probe listener, not the main tick loop.
"""
from __future__ import annotations

import email
import smtplib
from pathlib import Path
from typing import Any

_ARTIFACTS_ROOT_DEFAULT = "/var/lib/decnet/artifacts"


def _ensure_from_header(body: bytes, mail_from: str) -> bytes:
    """Return body with a From: header added if one is absent."""
    try:
        msg = email.message_from_bytes(body)
    except Exception:
        return body
    if msg["From"]:
        return body
    # Prepend the header before the existing content.
    header_line = f"From: {mail_from}\r\n".encode()
    return header_line + body


def forward_probe(
    *,
    svc_cfg: dict[str, Any],
    stored_as: str,
    decky_name: str,
    mail_from: str,
    rcpt_to: list[str],
    artifacts_root: str = _ARTIFACTS_ROOT_DEFAULT,
) -> tuple[bool, str]:
    """Read the .eml from disk and forward it via the upstream relay.

    Returns (True, "") on success or (False, reason) on failure.
    Always safe to call in a thread — uses only blocking I/O.
    """
    upstream_host = (svc_cfg.get("upstream_host") or "").strip()
    if not upstream_host:
        return False, "upstream_host not configured"

    eml_path = Path(artifacts_root) / decky_name / "smtp" / stored_as
    try:
        body = eml_path.read_bytes()
    except OSError as exc:
        return False, f"cannot read eml: {exc}"

    if not rcpt_to:
        return False, "no recipients"

    upstream_port  = int(svc_cfg.get("upstream_port") or 25)
    upstream_user  = (svc_cfg.get("upstream_user") or "").strip()
    upstream_pass  = (svc_cfg.get("upstream_pass") or "").strip()
    envelope_from  = (svc_cfg.get("upstream_sender") or "").strip() or mail_from

    # Ensure the message has a From: header so mail clients show the attacker's
    # address rather than falling back to the envelope sender (upstream_sender).
    # Minimal relay-test scripts often omit headers entirely.
    body = _ensure_from_header(body, mail_from)

    try:
        with smtplib.SMTP(upstream_host, upstream_port, timeout=15) as conn:
            conn.ehlo()
            if conn.has_extn("STARTTLS"):
                conn.starttls()
                conn.ehlo()
            if upstream_user and upstream_pass:
                conn.login(upstream_user, upstream_pass)
            conn.sendmail(envelope_from, rcpt_to, body)
        return True, ""
    except Exception as exc:
        return False, str(exc)[:256]
