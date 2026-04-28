#!/usr/bin/env python3
"""Mock webhook receiver for local DECNET testing.

Listens on a local port, accepts POSTs from the `decnet webhook`
worker (or the `/api/v1/webhooks/{uuid}/test` admin endpoint), and
pretty-prints each delivery with HMAC verification status.

Usage:
    # Start a receiver on port 8765, skip HMAC verification (unverified badge)
    scripts/mock-webhook-receiver.py

    # Verify HMAC against a known secret — reads DECNET_MOCK_SECRET env or --secret
    scripts/mock-webhook-receiver.py --secret deadbeefdeadbeef

    # Bind a different port / host
    scripts/mock-webhook-receiver.py --host 0.0.0.0 --port 9000

    # Simulate SIEM downtime — return a failure status for every POST so the
    # worker's retry/backoff path can be exercised end-to-end.
    scripts/mock-webhook-receiver.py --fail 503

Once running, create a webhook in DECNET pointing at the URL printed on
startup (e.g. http://localhost:8765/). The receiver accepts any path
— it's a catch-all — so the URL path after the host is yours to pick.

Pure stdlib. No dependencies to install.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# ANSI colors — stripped when stdout isn't a TTY.
_ISATTY = sys.stdout.isatty()


def _c(code: str) -> str:
    return code if _ISATTY else ""


RESET = _c("\033[0m")
DIM = _c("\033[2m")
BOLD = _c("\033[1m")
GREEN = _c("\033[32m")
RED = _c("\033[31m")
YELLOW = _c("\033[33m")
CYAN = _c("\033[36m")
MAGENTA = _c("\033[35m")
GRAY = _c("\033[90m")


def _verify_hmac(secret: str, body: bytes, sig_header: str) -> bool:
    """Return True iff the received signature matches our recomputed HMAC."""
    if not sig_header.startswith("sha256="):
        return False
    received = sig_header[len("sha256="):]
    expected = hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(received, expected)


class WebhookHandler(BaseHTTPRequestHandler):
    # Class-level config injected by `main`.
    secret: str | None = None
    fail_status: int | None = None

    # Silence the default noisy per-request log line — we print our own.
    def log_message(self, format, *args):  # noqa: A002,N802 — BaseHTTPRequestHandler API
        return

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler API
        """Friendly health check so you can `curl http://localhost:8765/`."""
        body = (
            b"DECNET mock webhook receiver.\n"
            b"POST to any path to test delivery.\n"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802 — BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length) if length else b""

        sig = self.headers.get("X-DECNET-Signature", "")
        event_id = self.headers.get("X-DECNET-Event-Id", "—")
        topic = self.headers.get("X-DECNET-Event-Topic", "—")
        ts_hdr = self.headers.get("X-DECNET-Timestamp", "")

        # Signature verification
        if self.secret is None:
            sig_badge = f"{YELLOW}UNVERIFIED{RESET}"
        elif not sig:
            sig_badge = f"{RED}NO SIGNATURE{RESET}"
        elif _verify_hmac(self.secret, raw_body, sig):
            sig_badge = f"{GREEN}HMAC OK{RESET}"
        else:
            sig_badge = f"{RED}HMAC MISMATCH{RESET}"

        # Decode the body — print as JSON when possible, raw otherwise.
        try:
            payload = json.loads(raw_body.decode("utf-8") or "{}")
            body_text = json.dumps(payload, indent=2, sort_keys=True)
        except (ValueError, UnicodeDecodeError):
            body_text = raw_body.decode("utf-8", errors="replace")

        now = datetime.now().strftime("%H:%M:%S")
        print(
            f"{DIM}{now}{RESET} "
            f"{BOLD}{MAGENTA}[POST {self.path}]{RESET} "
            f"{sig_badge} "
            f"{CYAN}topic={topic}{RESET} "
            f"{GRAY}event_id={event_id}{RESET}"
            f"{(' ' + GRAY + 'ts=' + ts_hdr + RESET) if ts_hdr else ''}",
            flush=True,
        )
        for line in body_text.splitlines() or [""]:
            print(f"  {line}", flush=True)
        print("", flush=True)

        # Response — success by default; configurable for retry-path testing.
        if self.fail_status is not None:
            status = self.fail_status
            reason = f"mock failure (--fail {self.fail_status})"
        else:
            status = 200
            reason = "ok"
        resp = json.dumps({"received": True, "reason": reason}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Mock HTTP receiver for DECNET webhook testing.",
    )
    ap.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")
    ap.add_argument(
        "--secret",
        default=os.environ.get("DECNET_MOCK_SECRET"),
        help="Webhook secret — HMAC is verified against received body when provided. "
             "Falls back to $DECNET_MOCK_SECRET. Omit to skip verification.",
    )
    ap.add_argument(
        "--fail",
        type=int,
        metavar="STATUS",
        help="Return this HTTP status for every POST instead of 200. "
             "Useful for exercising the worker's retry backoff "
             "(try --fail 503 or --fail 429).",
    )
    args = ap.parse_args()

    WebhookHandler.secret = args.secret
    WebhookHandler.fail_status = args.fail

    verify_note = (
        f"{GREEN}HMAC verification ENABLED{RESET}"
        if args.secret
        else f"{YELLOW}HMAC verification OFF (pass --secret to enable){RESET}"
    )
    fail_note = (
        f"\n  {RED}RESPONSE MODE: failing every request with {args.fail}{RESET}"
        if args.fail is not None
        else ""
    )

    url = f"http://{args.host}:{args.port}/"
    banner = (
        f"\n{BOLD}{CYAN}DECNET mock webhook receiver{RESET}\n"
        f"  listening on {BOLD}{url}{RESET}\n"
        f"  {verify_note}{fail_note}\n"
        f"  POST to any path; GET / for a health reply.\n"
        f"  Ctrl-C to stop.\n"
    )
    print(banner, flush=True)

    server = ThreadingHTTPServer((args.host, args.port), WebhookHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{DIM}receiver stopped.{RESET}", flush=True)
        server.server_close()


if __name__ == "__main__":
    main()
