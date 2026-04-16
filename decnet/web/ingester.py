import asyncio
import os
import json
from typing import Any
from pathlib import Path

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

            with open(_json_log_path, "r", encoding="utf-8", errors="replace") as _f:
                _f.seek(_position)
                while True:
                    _line: str = _f.readline()
                    if not _line:
                        break # EOF reached

                    if not _line.endswith('\n'):
                        # Partial line read, don't process yet, don't advance position
                        break

                    try:
                        _log_data: dict[str, Any] = json.loads(_line.strip())
                        # Extract trace context injected by the collector.
                        # This makes the ingester span a child of the collector span,
                        # showing the full event journey in Jaeger.
                        _parent_ctx = _extract_ctx(_log_data)
                        _tracer = _get_tracer("ingester")
                        with _start_span(_tracer, "ingester.process_record", context=_parent_ctx) as _span:
                            _span.set_attribute("decky", _log_data.get("decky", ""))
                            _span.set_attribute("service", _log_data.get("service", ""))
                            _span.set_attribute("event_type", _log_data.get("event_type", ""))
                            _span.set_attribute("attacker_ip", _log_data.get("attacker_ip", ""))
                            logger.debug("ingest: record decky=%s event_type=%s", _log_data.get("decky"), _log_data.get("event_type"))
                            await repo.add_log(_log_data)
                            await _extract_bounty(repo, _log_data)
                    except json.JSONDecodeError:
                        logger.error("ingest: failed to decode JSON log line: %s", _line.strip())
                        continue

                    # Update position after successful line read
                    _position = _f.tell()

            await repo.set_state(_INGEST_STATE_KEY, {"position": _position})

        except Exception as _e:
            _err_str = str(_e).lower()
            if "no such table" in _err_str or "no active connection" in _err_str or "connection closed" in _err_str:
                logger.error("ingest: post-shutdown or fatal DB error: %s", _e)
                break  # Exit worker — DB is gone or uninitialized

            logger.error("ingest: error in worker: %s", _e)
            await asyncio.sleep(5)

        await asyncio.sleep(1)


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
        await repo.add_bounty({
            "decky": log_data.get("decky"),
            "service": log_data.get("service"),
            "attacker_ip": log_data.get("attacker_ip"),
            "bounty_type": "fingerprint",
            "payload": {
                "fingerprint_type": "http_useragent",
                "value": _ua,
                "method": _fields.get("method"),
                "path": _fields.get("path"),
            }
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
