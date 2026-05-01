"""Master-side syslog-over-TLS listener (RFC 5425).

Accepts mTLS-authenticated worker connections on TCP 6514, reads
octet-counted frames, parses each as an RFC 5424 line, and appends it to
the master's local ingest log files. The existing log_ingestion_worker
tails those files and inserts records into the master repo — worker
provenance is embedded in the parsed record's ``source_worker`` field.

Design:
* TLS is mandatory. No plaintext fallback. A peer without a CA-signed
  cert is rejected at the TLS handshake; nothing gets past the kernel.
* The listener never trusts the syslog HOSTNAME field for provenance —
  that's attacker-supplied from the decky. The authoritative source is
  the peer cert's CN, which the CA controlled at enrollment.
* Dropped connections are fine — the worker's forwarder holds the
  offset and resumes from the same byte on reconnect.
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import ssl
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from decnet.logging import get_logger
from decnet.swarm import pki
from decnet.swarm.log_forwarder import read_frame

log = get_logger("swarm.listener")


@dataclass(frozen=True)
class ListenerConfig:
    log_path: pathlib.Path          # master's RFC 5424 .log (forensic sink)
    json_path: pathlib.Path         # master's .json (ingester tails this)
    bind_host: str = "0.0.0.0"  # nosec B104 — listener must bind publicly
    bind_port: int = 6514
    ca_dir: pathlib.Path = pki.DEFAULT_CA_DIR


# --------------------------------------------------------- TLS context


def build_listener_ssl_context(ca_dir: pathlib.Path) -> ssl.SSLContext:
    """Server-side mTLS context: master presents its master cert; clients
    must present a cert signed by the DECNET CA."""
    master_dir = ca_dir / "master"
    ca_cert = master_dir / "ca.crt"
    cert = master_dir / "worker.crt"   # master re-uses the 'worker' bundle layout
    key = master_dir / "worker.key"
    for p in (ca_cert, cert, key):
        if not p.exists():
            raise RuntimeError(
                f"master identity missing at {master_dir} — call ensure_master_identity first"
            )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    ctx.load_verify_locations(cafile=str(ca_cert))
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


# ---------------------------------------------------------- helpers


def peer_cn(ssl_object: Optional[ssl.SSLObject]) -> str:
    """Extract the CN from the TLS peer certificate (worker provenance).

    Falls back to ``"unknown"`` on any parse error — we refuse to crash on
    malformed cert DNs and instead tag the message for later inspection.
    """
    if ssl_object is None:
        return "unknown"
    der = ssl_object.getpeercert(binary_form=True)
    if der is None:
        return "unknown"
    try:
        cert = x509.load_der_x509_certificate(der)
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(attrs[0].value) if attrs else "unknown"
    except Exception:  # nosec B110 — provenance is best-effort
        return "unknown"


def fingerprint_from_ssl(ssl_object: Optional[ssl.SSLObject]) -> Optional[str]:
    if ssl_object is None:
        return None
    der = ssl_object.getpeercert(binary_form=True)
    if der is None:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
        return pki.fingerprint(cert.public_bytes(serialization.Encoding.PEM))
    except Exception:
        return None


# --------------------------------------------------- per-connection handler


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    cfg: ListenerConfig,
) -> None:
    ssl_obj = writer.get_extra_info("ssl_object")
    cn = peer_cn(ssl_obj)
    peer = writer.get_extra_info("peername")
    log.info("listener accepted worker=%s peer=%s", cn, peer)

    # Lazy import to avoid a circular dep if the collector pulls in logger setup.
    from decnet.collector.worker import parse_rfc5424

    cfg.log_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.json_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(cfg.log_path, "a", encoding="utf-8") as lf, open(
            cfg.json_path, "a", encoding="utf-8"
        ) as jf:
            while True:
                try:
                    frame = await read_frame(reader)
                except asyncio.IncompleteReadError:
                    break
                except ValueError as exc:
                    log.warning("listener bad frame worker=%s err=%s", cn, exc)
                    break
                if frame is None:
                    break
                if not frame:
                    continue
                line = frame.decode("utf-8", errors="replace")
                lf.write(line + "\n")
                lf.flush()
                parsed = parse_rfc5424(line)
                if parsed is not None:
                    parsed["source_worker"] = cn
                    jf.write(json.dumps(parsed) + "\n")
                    jf.flush()
                else:
                    log.debug("listener malformed RFC5424 worker=%s snippet=%r", cn, line[:80])
    except Exception as exc:
        log.warning("listener connection error worker=%s err=%s", cn, exc)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # nosec B110 — socket cleanup is best-effort
            pass
        log.info("listener closed worker=%s", cn)


# ---------------------------------------------------------------- server


async def run_listener(
    cfg: ListenerConfig,
    *,
    stop_event: Optional[asyncio.Event] = None,
) -> None:
    ctx = build_listener_ssl_context(cfg.ca_dir)

    async def _client_cb(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await _handle_connection(reader, writer, cfg)

    server = await asyncio.start_server(
        _client_cb, host=cfg.bind_host, port=cfg.bind_port, ssl=ctx
    )
    sockets = server.sockets or ()
    log.info(
        "listener bound host=%s port=%d sockets=%d",
        cfg.bind_host, cfg.bind_port, len(sockets),
    )
    async with server:
        if stop_event is None:
            await server.serve_forever()
        else:
            serve_task = asyncio.create_task(server.serve_forever())
            await stop_event.wait()
            server.close()
            serve_task.cancel()
            try:
                await serve_task
            except (asyncio.CancelledError, Exception):  # nosec B110
                pass
