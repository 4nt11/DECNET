import asyncio
import contextlib
import ipaddress
import os
import json
import re
import time
from typing import Any, Optional
from pathlib import Path

from decnet.bus import topics as _topics
from decnet.bus.factory import get_bus
from decnet.bus.publish import publish_safely
from decnet.env import DECNET_BATCH_SIZE, DECNET_BATCH_MAX_WAIT_MS
from decnet.logging import get_logger
from decnet.telemetry import (
    traced as _traced,
    get_tracer as _get_tracer,
    extract_context as _extract_ctx,
    start_span_with_context as _start_span,
)
from decnet.web.db.repository import BaseRepository

logger = get_logger("api")

_INGEST_STATE_KEY = "ingest_worker_position"


async def log_ingestion_worker(repo: BaseRepository) -> None:
    """
    Background task that tails the DECNET_INGEST_LOG_FILE.json and
    inserts structured JSON logs into the SQLite repository.
    """
    _base_log_file: str | None = os.environ.get("DECNET_INGEST_LOG_FILE")
    if not _base_log_file:
        logger.warning("DECNET_INGEST_LOG_FILE not set. Log ingestion disabled.")
        return

    _json_log_path: Path = Path(_base_log_file).with_suffix(".json")

    _saved = await repo.get_state(_INGEST_STATE_KEY)
    _position: int = _saved.get("position", 0) if _saved else 0

    logger.info("ingest worker started path=%s position=%d", _json_log_path, _position)

    # Optional bus wiring — emit one system.log event per committed batch so
    # downstream consumers (dashboard heartbeats, federation forwarder) can
    # track DB-persisted progress without polling the state table.
    _bus = None
    try:
        _bus = get_bus(client_name="ingester")
        await _bus.connect()
    except Exception as _exc:
        logger.warning("ingester: bus unavailable, continuing without publish: %s", _exc)
        _bus = None

    try:
        await _run_loop(repo, _json_log_path, _position, _bus)
    finally:
        if _bus is not None:
            with contextlib.suppress(Exception):
                await _bus.close()


async def _run_loop(
    repo: BaseRepository,
    _json_log_path: Path,
    _position: int,
    _bus: Any,
) -> None:
    while True:
        try:
            if not _json_log_path.exists():
                await asyncio.sleep(2)
                continue

            _stat: os.stat_result = _json_log_path.stat()
            if _stat.st_size < _position:
                # File rotated or truncated
                _position = 0
                await repo.set_state(_INGEST_STATE_KEY, {"position": 0})

            if _stat.st_size == _position:
                # No new data
                await asyncio.sleep(1)
                continue

            # Accumulate parsed rows and the file offset they end at.  We
            # only advance _position after the batch is successfully
            # committed — if we get cancelled mid-flush, the next run
            # re-reads the un-committed lines rather than losing them.
            _batch: list[tuple[dict[str, Any], int]] = []
            _batch_started: float = time.monotonic()
            _max_wait_s: float = DECNET_BATCH_MAX_WAIT_MS / 1000.0

            with open(_json_log_path, "r", encoding="utf-8", errors="replace") as _f:
                _f.seek(_position)
                while True:
                    _line: str = _f.readline()
                    if not _line or not _line.endswith('\n'):
                        # EOF or partial line — flush what we have and stop
                        break

                    try:
                        _log_data: dict[str, Any] = json.loads(_line.strip())
                        # Collector injects trace context so the ingester span
                        # chains off the collector's — full event journey in Jaeger.
                        _parent_ctx = _extract_ctx(_log_data)
                        _tracer = _get_tracer("ingester")
                        with _start_span(_tracer, "ingester.process_record", context=_parent_ctx) as _span:
                            _span.set_attribute("decky", _log_data.get("decky", ""))
                            _span.set_attribute("service", _log_data.get("service", ""))
                            _span.set_attribute("event_type", _log_data.get("event_type", ""))
                            _span.set_attribute("attacker_ip", _log_data.get("attacker_ip", ""))
                            _sctx = getattr(_span, "get_span_context", None)
                            if _sctx:
                                _ctx = _sctx()
                                if _ctx and getattr(_ctx, "trace_id", 0):
                                    _log_data["trace_id"] = format(_ctx.trace_id, "032x")
                                    _log_data["span_id"] = format(_ctx.span_id, "016x")
                        _batch.append((_log_data, _f.tell()))
                    except json.JSONDecodeError:
                        logger.error("ingest: failed to decode JSON log line: %s", _line.strip())
                        # Skip past bad line so we don't loop forever on it.
                        _position = _f.tell()
                        continue

                    if len(_batch) >= DECNET_BATCH_SIZE or (
                        time.monotonic() - _batch_started >= _max_wait_s
                    ):
                        _flushed = len(_batch)
                        _position = await _flush_batch(repo, _batch, _position)
                        _batch.clear()
                        _batch_started = time.monotonic()
                        await _publish_batch(_bus, _flushed, _position)

            # Flush any remainder collected before EOF / partial-line break.
            if _batch:
                _flushed = len(_batch)
                _position = await _flush_batch(repo, _batch, _position)
                await _publish_batch(_bus, _flushed, _position)

        except Exception as _e:
            _err_str = str(_e).lower()
            if "no such table" in _err_str or "no active connection" in _err_str or "connection closed" in _err_str:
                logger.error("ingest: post-shutdown or fatal DB error: %s", _e)
                break  # Exit worker — DB is gone or uninitialized

            logger.error("ingest: error in worker: %s", _e)
            await asyncio.sleep(5)

        await asyncio.sleep(1)


async def _publish_batch(bus: Any, flushed: int, position: int) -> None:
    """Emit one ``system.log`` event summarising a committed batch.

    Fire-and-forget via :func:`publish_safely`; a dead bus never blocks the
    ingestion loop.  Zero-row flushes are suppressed so the topic stays
    meaningful.
    """
    if bus is None or flushed <= 0:
        return
    await publish_safely(
        bus,
        _topics.system(_topics.SYSTEM_LOG),
        {"component": "ingester", "flushed": flushed, "position": position},
        event_type="batch_committed",
    )


async def _flush_batch(
    repo: BaseRepository,
    batch: list[tuple[dict[str, Any], int]],
    current_position: int,
) -> int:
    """Commit a batch of log rows and return the new file position.

    If the enclosing task is being cancelled, bail out without touching
    the DB — the session factory may already be disposed during lifespan
    teardown, and awaiting it would stall the worker.  The un-flushed
    lines stay uncommitted; the next startup re-reads them from
    ``current_position``.
    """
    _task = asyncio.current_task()
    if _task is not None and _task.cancelling():
        raise asyncio.CancelledError()

    _entries = [_entry for _entry, _ in batch]
    _new_position = batch[-1][1]
    await repo.add_logs(_entries)
    for _entry in _entries:
        await _extract_bounty(repo, _entry)
    await repo.set_state(_INGEST_STATE_KEY, {"position": _new_position})
    return _new_position


@_traced("ingester.extract_bounty")
async def _extract_bounty(repo: BaseRepository, log_data: dict[str, Any]) -> None:
    """Detect and extract valuable artifacts (bounties) from log entries."""
    _fields = log_data.get("fields")
    if not isinstance(_fields, dict):
        return

    # 1. Credentials (User/Pass)
    _user = _fields.get("username")
    _pass = _fields.get("password")

    if _user and _pass:
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": log_data.get("service"),
            "attacker_ip": log_data.get("attacker_ip"),
            "bounty_type": "credential",
            "payload": {
                "username": _user,
                "password": _pass
            }
        })

    # 2. HTTP User-Agent fingerprint
    _h_raw = _fields.get("headers")
    if isinstance(_h_raw, dict):
        _headers = _h_raw
    elif isinstance(_h_raw, str):
        try:
            _parsed = json.loads(_h_raw)
            _headers = _parsed if isinstance(_parsed, dict) else {}
        except (json.JSONDecodeError, ValueError):
            _headers = {}
    else:
        _headers = {}
    _ua = _headers.get("User-Agent") or _headers.get("user-agent")
    if _ua:
        # Payload must be identity-only (no per-request method/path) —
        # add_bounty dedups on (attacker_ip, bounty_type, full payload
        # JSON), so including path here would create one row per URL
        # the scanner hits. Per-request context belongs in the logs
        # table, not the bounty table.
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": log_data.get("service"),
            "attacker_ip": log_data.get("attacker_ip"),
            "bounty_type": "fingerprint",
            "payload": {
                "fingerprint_type": "http_useragent",
                "value": _ua,
            }
        })

    # 2b. IP leak — the attacker's real IP accidentally forwarded in a
    # proxy-family header (X-Forwarded-For / Forwarded / X-Real-IP /
    # CDN variants). Left-most value differing from the TCP source is
    # a high-confidence attribution signal. DECNET_TRUSTED_PROXIES
    # opts specific source IPs out (legitimate reverse proxy in front
    # of DECNET).
    _leak = _detect_ip_leak(log_data, _headers)
    if _leak is not None:
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": log_data.get("service"),
            "attacker_ip": log_data.get("attacker_ip"),
            "bounty_type": "ip_leak",
            "payload": _leak,
        })

    # 2b.2 Spoofed source — attacker tried to pass a non-routable IP
    # (loopback / RFC1918 / link-local / reserved) in a proxy header.
    # Classic WAF-bypass: `X-Forwarded-For: 127.0.0.1` hoping an
    # upstream filter waves localhost through. Distinct bounty type
    # from ip_leak because the semantic is inverted — attack attempt,
    # not opsec failure.
    _spoof = _detect_spoofed_source(log_data, _headers)
    if _spoof is not None:
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": log_data.get("service"),
            "attacker_ip": log_data.get("attacker_ip"),
            "bounty_type": "fingerprint",
            "payload": _spoof,
        })

    # 2c. HTTP header quirks — order + casing fingerprint per request.
    # Real HTTP clients have distinctive header orderings and casing
    # patterns (curl vs python-requests vs Go-http-client vs nmap vs
    # browsers all differ). Attackers routinely spoof User-Agent but
    # forget to match the stack's native header order. Bounty dedup
    # collapses repeat fingerprints from the same attacker, so this
    # fires once per distinct hash per source.
    _quirks = _http_quirks_fingerprint(log_data, _headers)
    if _quirks is not None:
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": log_data.get("service"),
            "attacker_ip": log_data.get("attacker_ip"),
            "bounty_type": "fingerprint",
            "payload": _quirks,
        })

    # 3. VNC client version fingerprint
    _vnc_ver = _fields.get("client_version")
    if _vnc_ver and log_data.get("event_type") == "version":
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": log_data.get("service"),
            "attacker_ip": log_data.get("attacker_ip"),
            "bounty_type": "fingerprint",
            "payload": {
                "fingerprint_type": "vnc_client_version",
                "value": _vnc_ver,
            }
        })

    # 4. SSH client banner fingerprint (deferred — requires asyncssh server)
    # Fires on: service=ssh, event_type=client_banner, fields.client_banner

    # 5. JA3/JA3S TLS fingerprint from sniffer container
    _ja3 = _fields.get("ja3")
    if _ja3 and log_data.get("service") == "sniffer":
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": "sniffer",
            "attacker_ip": log_data.get("attacker_ip"),
            "bounty_type": "fingerprint",
            "payload": {
                "fingerprint_type": "ja3",
                "ja3": _ja3,
                "ja3s": _fields.get("ja3s"),
                "ja4": _fields.get("ja4"),
                "ja4s": _fields.get("ja4s"),
                "tls_version": _fields.get("tls_version"),
                "sni": _fields.get("sni") or None,
                "alpn": _fields.get("alpn") or None,
                "dst_port": _fields.get("dst_port"),
                "raw_ciphers": _fields.get("raw_ciphers"),
                "raw_extensions": _fields.get("raw_extensions"),
            },
        })

    # 6. JA4L latency fingerprint from sniffer
    _ja4l_rtt = _fields.get("ja4l_rtt_ms")
    if _ja4l_rtt and log_data.get("service") == "sniffer":
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": "sniffer",
            "attacker_ip": log_data.get("attacker_ip"),
            "bounty_type": "fingerprint",
            "payload": {
                "fingerprint_type": "ja4l",
                "rtt_ms": _ja4l_rtt,
                "client_ttl": _fields.get("ja4l_client_ttl"),
            },
        })

    # 7. TLS session resumption behavior
    _resumption = _fields.get("resumption")
    if _resumption and log_data.get("service") == "sniffer":
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": "sniffer",
            "attacker_ip": log_data.get("attacker_ip"),
            "bounty_type": "fingerprint",
            "payload": {
                "fingerprint_type": "tls_resumption",
                "mechanisms": _resumption,
            },
        })

    # 8. TLS certificate details (TLS 1.2 only — passive extraction)
    _subject_cn = _fields.get("subject_cn")
    if _subject_cn and log_data.get("service") == "sniffer":
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": "sniffer",
            "attacker_ip": log_data.get("attacker_ip"),
            "bounty_type": "fingerprint",
            "payload": {
                "fingerprint_type": "tls_certificate",
                "subject_cn": _subject_cn,
                "issuer": _fields.get("issuer"),
                "self_signed": _fields.get("self_signed"),
                "not_before": _fields.get("not_before"),
                "not_after": _fields.get("not_after"),
                "sans": _fields.get("sans"),
                "sni": _fields.get("sni") or None,
            },
        })

    # 9. JARM fingerprint from active prober
    _jarm = _fields.get("jarm_hash")
    if _jarm and log_data.get("service") == "prober":
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": "prober",
            "attacker_ip": _fields.get("target_ip", "Unknown"),
            "bounty_type": "fingerprint",
            "payload": {
                "fingerprint_type": "jarm",
                "hash": _jarm,
                "target_ip": _fields.get("target_ip"),
                "target_port": _fields.get("target_port"),
            },
        })

    # 10. HASSHServer fingerprint from active prober
    _hassh = _fields.get("hassh_server_hash")
    if _hassh and log_data.get("service") == "prober":
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": "prober",
            "attacker_ip": _fields.get("target_ip", "Unknown"),
            "bounty_type": "fingerprint",
            "payload": {
                "fingerprint_type": "hassh_server",
                "hash": _hassh,
                "target_ip": _fields.get("target_ip"),
                "target_port": _fields.get("target_port"),
                "ssh_banner": _fields.get("ssh_banner"),
                "kex_algorithms": _fields.get("kex_algorithms"),
                "encryption_s2c": _fields.get("encryption_s2c"),
                "mac_s2c": _fields.get("mac_s2c"),
                "compression_s2c": _fields.get("compression_s2c"),
            },
        })

    # 11. TCP/IP stack fingerprint from active prober
    _tcpfp = _fields.get("tcpfp_hash")
    if _tcpfp and log_data.get("service") == "prober":
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": "prober",
            "attacker_ip": _fields.get("target_ip", "Unknown"),
            "bounty_type": "fingerprint",
            "payload": {
                "fingerprint_type": "tcpfp",
                "hash": _tcpfp,
                "raw": _fields.get("tcpfp_raw"),
                "target_ip": _fields.get("target_ip"),
                "target_port": _fields.get("target_port"),
                "ttl": _fields.get("ttl"),
                "window_size": _fields.get("window_size"),
                "df_bit": _fields.get("df_bit"),
                "mss": _fields.get("mss"),
                "window_scale": _fields.get("window_scale"),
                "sack_ok": _fields.get("sack_ok"),
                "timestamp": _fields.get("timestamp"),
                "options_order": _fields.get("options_order"),
            },
        })


# ─── IP-leak detection (XFF / Forwarded / X-Real-IP / CDN variants) ──────────

# Proxy-family headers we inspect, in priority order. Forwarded (RFC 7239)
# is the "proper" way; X-Forwarded-For is de-facto; X-Real-IP and CDN
# variants are common nginx / CloudFlare conventions.
_PROXY_HEADERS = (
    "Forwarded",
    "X-Forwarded-For",
    "X-Real-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
)

# RFC 7239 `Forwarded: for=1.2.3.4` / `for="[2001:db8::1]:4711"`. The
# capture grabs the raw for= value up to the next pair/element
# delimiter (; or ,) or end-of-string; _parse_forwarded strips quotes
# / IPv6 brackets / port afterwards.
_FORWARDED_KV_RE = re.compile(
    r'for\s*=\s*"?([^",;]+?)"?(?=[;,]|$)',
    re.IGNORECASE,
)


def _get_trusted_proxies() -> list[ipaddress._BaseNetwork]:
    """Parse DECNET_TRUSTED_PROXIES once per process into network objects.

    Empty / unset → empty list (no opt-outs). Malformed entries are logged
    at WARNING and silently dropped — a typo in the env shouldn't brick
    the ingester.
    """
    raw = os.environ.get("DECNET_TRUSTED_PROXIES", "")
    out: list[ipaddress._BaseNetwork] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            # Accept both bare IPs ("1.2.3.4") and CIDRs ("10.0.0.0/8").
            if "/" in token:
                out.append(ipaddress.ip_network(token, strict=False))
            else:
                out.append(ipaddress.ip_network(f"{token}/32", strict=False))
        except (ValueError, TypeError) as exc:
            logger.warning("DECNET_TRUSTED_PROXIES: ignoring %r: %s", token, exc)
    return out


def _is_trusted_source(source_ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(source_ip)
    except (ValueError, TypeError):
        return False
    for net in _get_trusted_proxies():
        try:
            if addr in net:
                return True
        except (ValueError, TypeError):
            continue
    return False


def _lookup_header(headers: dict[str, Any], name: str) -> Optional[str]:
    """Case-insensitive header fetch; HTTP template logs headers as-received."""
    lowered = name.lower()
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == lowered:
            if isinstance(v, str) and v.strip():
                return v.strip()
    return None


def _parse_forwarded(value: str) -> Optional[str]:
    """Return the first `for=` IP from an RFC 7239 Forwarded header.

    Handles the quoted IPv6-bracket-port form (`for="[2001:db8::1]:4711"`)
    plus the bare IPv4 (`for=1.2.3.4`) and IPv4:port (`for=1.2.3.4:80`)
    variants. Returns None on any parse failure.
    """
    match = _FORWARDED_KV_RE.search(value)
    if not match:
        return None
    token = match.group(1).strip()
    if not token:
        return None
    # Strip IPv6 brackets (+ optional :port after them).
    if token.startswith("["):
        end = token.find("]")
        if end > 0:
            token = token[1:end]
    elif token.count(":") == 1:
        # IPv4:port. IPv6 bare literals have ≥2 colons so we leave those.
        token = token.split(":")[0]
    try:
        ipaddress.ip_address(token)
    except (ValueError, TypeError):
        return None
    return token


def _parse_xff_chain(value: str) -> Optional[str]:
    """Return the left-most parseable IP from an X-Forwarded-For chain."""
    for token in value.split(","):
        token = token.strip().strip('"').lstrip("[").rstrip("]")
        if not token:
            continue
        try:
            ipaddress.ip_address(token)
        except (ValueError, TypeError):
            continue
        return token
    return None


def _extract_claimed_ip(headers: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Walk the proxy-header priority list; return (claimed_ip, header_name)."""
    for header in _PROXY_HEADERS:
        raw = _lookup_header(headers, header)
        if raw is None:
            continue
        if header == "Forwarded":
            claimed = _parse_forwarded(raw)
        elif header == "X-Forwarded-For":
            claimed = _parse_xff_chain(raw)
        else:
            # Single-IP headers — may still carry port or IPv6 brackets.
            token = raw.strip().strip('"').lstrip("[").rstrip("]")
            try:
                ipaddress.ip_address(token)
                claimed = token
            except (ValueError, TypeError):
                claimed = None
        if claimed is not None:
            return claimed, header
    return None, None


def _categorize_claimed_ip(ip: str) -> str:
    """Return a category label for a claimed IP string.

    Public routable addresses are potential real-IP leaks. Anything
    else (loopback, private, link-local, multicast, reserved,
    unspecified) is almost certainly a forgery — XFF spoofing is the
    classic WAF-bypass / IP-allowlist trick. Callers branch on this:
    ``public`` → :data:`ip_leak` bounty, anything else →
    ``spoofed_source`` fingerprint bounty.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return "unparseable"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    if addr.is_private:
        return "private"
    return "public"


def _classify_proxy_header_claim(
    log_data: dict[str, Any], headers: dict[str, Any],
) -> Optional[tuple[str, dict[str, Any]]]:
    """Shared worker for the two XFF-family detectors.

    Returns ``(kind, payload)`` where ``kind`` is ``"leak"`` (public
    claim, real attribution leak) or ``"spoof"`` (non-routable claim,
    WAF-bypass attempt). Returns ``None`` for non-HTTP / trusted-proxy
    source / no proxy header / claim matches source / unparseable claim.
    """
    if log_data.get("service") != "http":
        return None
    if not isinstance(headers, dict) or not headers:
        return None
    source_ip = log_data.get("attacker_ip")
    if not isinstance(source_ip, str) or not source_ip:
        return None
    if _is_trusted_source(source_ip):
        return None

    claimed, header_name = _extract_claimed_ip(headers)
    if claimed is None or claimed == source_ip:
        return None

    category = _categorize_claimed_ip(claimed)
    if category == "unparseable":
        return None

    seen: dict[str, str] = {}
    for h in _PROXY_HEADERS:
        raw = _lookup_header(headers, h)
        if raw is not None:
            seen[h] = raw

    base = {
        "source_ip": source_ip,
        "claimed_ip": claimed,
        "source_header": header_name,
        "headers_seen": seen,
        "claim_category": category,
    }
    return ("leak" if category == "public" else "spoof"), base


def _detect_ip_leak(
    log_data: dict[str, Any], headers: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Return an ip_leak bounty payload iff a PUBLIC proxy-claim
    mismatch is present — an attacker whose misconfigured VPN / proxy
    forwarded their real routable IP in an XFF-family header. Returns
    ``None`` for spoofing attempts (loopback / private / link-local /
    etc.); those land as ``spoofed_source`` fingerprints instead.
    """
    result = _classify_proxy_header_claim(log_data, headers)
    if result is None or result[0] != "leak":
        return None
    payload = result[1]
    # Preserve the legacy field name so existing UI consumers
    # (AttackerDetail "LEAKED IPs" row, repo JSON decode) keep working.
    payload["real_ip_claim"] = payload.pop("claimed_ip")
    payload.pop("claim_category", None)  # always "public" for leaks
    return payload


def _detect_spoofed_source(
    log_data: dict[str, Any], headers: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Return a fingerprint payload iff a NON-ROUTABLE proxy-claim
    is present — the attacker tried to pass loopback / private /
    link-local / reserved / etc. in an XFF-family header.

    That's the classic IP-allowlist / WAF-bypass trick: ``curl -H
    'X-Forwarded-For: 127.0.0.1'`` hoping an upstream WAF sees
    "localhost" and waves them through. No leak of their real IP;
    they're telling us "I know what this header does."

    Caller wraps this in ``bounty_type="fingerprint"`` with
    ``fingerprint_type="spoofed_source"``.
    """
    result = _classify_proxy_header_claim(log_data, headers)
    if result is None or result[0] != "spoof":
        return None
    _, payload = result
    # Promote to fingerprint_type for the UI renderer dispatcher.
    return {
        "fingerprint_type": "spoofed_source",
        **payload,
    }


# ─── HTTP header quirks fingerprint ─────────────────────────────────────────

# Headers that vary with per-request content (payload-body size, cookies
# set by prior responses) and therefore aren't useful identity. Stripped
# before hashing so a tool's order fingerprint is stable across different
# targets/sessions.
_VOLATILE_HEADERS = frozenset({
    "content-length",
    "cookie",
    "authorization",
    "x-forwarded-for",   # carries attacker-dependent values
    "forwarded",
    "x-real-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "x-request-id",
    "x-correlation-id",
    "x-amzn-trace-id",
})


# Distinctive order signatures for common tools. The match is on the
# lowercased-name list MINUS the volatile set. A prefix match wins —
# many tools tack on "User-Agent / Accept-Encoding / Accept" in the
# same order regardless of method.
_TOOL_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    # curl sends: Host, User-Agent, Accept, <body-headers>.
    ("curl", ("host", "user-agent", "accept")),
    # python-requests: User-Agent, Accept-Encoding, Accept, Connection, Host.
    ("python-requests", ("host", "user-agent", "accept-encoding", "accept", "connection")),
    # Go-http-client: Host, User-Agent, Accept-Encoding.
    ("go-http-client", ("host", "user-agent", "accept-encoding")),
    # nmap http-enum / http-* scripts: short, Host+User-Agent ordering.
    ("nmap-nse", ("host", "user-agent")),
    # Nikto / Nuclei send distinctive Accept-Language preferences — treat
    # User-Agent check as the secondary signal elsewhere; order alone is
    # ambiguous here.
)


def _casing_category(name: str) -> str:
    """Classify a header-name casing pattern.

    Real HTTP clients and stacks pick one convention and stick to it:
    browsers send `Title-Case`; python-requests sends `Title-Case`;
    Go's stdlib canonicalises to `Title-Case`; curl sends literal
    `Title-Case`; nmap/masscan often send `lowercase`; custom scanners
    sometimes send `UPPERCASE`.
    """
    if not name:
        return "empty"
    if name == name.upper():
        return "upper"
    if name == name.lower():
        return "lower"
    # "Title-Case" test: each dash-separated token starts with an
    # uppercase; trailing chars (if any) must be lowercase. Single-
    # letter tokens like the `X` in `X-Forwarded-For` qualify when
    # uppercase — "".islower() is False in Python so the naive form
    # of this test misfires.
    parts = [p for p in name.split("-") if p]
    if parts and all(
        p[:1].isupper() and (len(p) == 1 or p[1:].islower())
        for p in parts
    ):
        return "title"
    return "mixed"


def _short_hash(value: str) -> str:
    """16-hex-char SHA-256 prefix — stable identity, short display."""
    import hashlib
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _guess_tool_from_order(lowered: list[str]) -> Optional[str]:
    """Return the first matching tool signature, or None."""
    for name, sig in _TOOL_SIGNATURES:
        if len(lowered) >= len(sig) and tuple(lowered[: len(sig)]) == sig:
            return name
    return None


def _http_quirks_fingerprint(
    log_data: dict[str, Any], headers: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Build an HTTP request-header quirks fingerprint.

    Captures the header-order hash, casing pattern, count, and a
    best-effort tool guess. Returns ``None`` for non-HTTP services or
    when no usable headers are present.  Bounty dedup will collapse
    repeat fingerprints from the same attacker.
    """
    if log_data.get("service") != "http":
        return None
    if not isinstance(headers, dict) or not headers:
        return None

    # Preserve insertion order (Python 3.7+ dict guarantee, and JSON
    # round-trip also preserves it). Drop volatile headers for the
    # identity hash but keep them in the display order list.
    names_full: list[str] = [k for k in headers.keys() if isinstance(k, str)]
    if not names_full:
        return None

    names_stable = [n for n in names_full if n.lower() not in _VOLATILE_HEADERS]
    lowered = [n.lower() for n in names_stable]

    order_hash = _short_hash("\n".join(lowered))
    casing_per_header = [_casing_category(n) for n in names_stable]
    casing_hash = _short_hash("\n".join(casing_per_header))

    # A single "dominant" casing category — useful for at-a-glance display.
    categories = set(casing_per_header)
    if not categories:
        dominant = "empty"
    elif len(categories) == 1:
        dominant = next(iter(categories))
    else:
        dominant = "mixed"

    # Identity-only payload — every field must be stable for two
    # requests from the same client stack. add_bounty dedups on the
    # full payload JSON, so a per-request-varying key (path, method,
    # header_count when Cookie presence varies) would spawn one row
    # per request. The hashes ARE the identity; per-request context
    # lives in the logs table.
    return {
        "fingerprint_type": "http_quirks",
        "order_hash": order_hash,
        "order": names_stable,
        "casing_hash": casing_hash,
        "casing_category": dominant,
        "stable_count": len(names_stable),
        "tool_guess": _guess_tool_from_order(lowered),
    }

