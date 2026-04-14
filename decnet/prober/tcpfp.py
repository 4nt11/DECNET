"""
TCP/IP stack fingerprinting via SYN-ACK analysis.

Sends a crafted TCP SYN packet to a target host:port, captures the
SYN-ACK response, and extracts OS/tool-identifying characteristics:
TTL, window size, DF bit, MSS, window scale, SACK support, timestamps,
and TCP options ordering.

Uses scapy for packet crafting and parsing. Requires root/CAP_NET_RAW.
"""

from __future__ import annotations

import hashlib
import random
from typing import Any

# Lazy-import scapy to avoid breaking non-root usage of HASSH/JARM.
# The actual import happens inside functions that need it.

# ─── TCP option short codes ─────────────────────────────────────────────────

_OPT_CODES: dict[str, str] = {
    "MSS": "M",
    "WScale": "W",
    "SAckOK": "S",
    "SAck": "S",
    "Timestamp": "T",
    "NOP": "N",
    "EOL": "E",
    "AltChkSum": "A",
    "AltChkSumOpt": "A",
    "UTO": "U",
}


# ─── Packet construction ───────────────────────────────────────────────────

def _send_syn(
    host: str,
    port: int,
    timeout: float,
) -> Any | None:
    """
    Craft a TCP SYN with common options and send it. Returns the
    SYN-ACK response packet or None on timeout/failure.
    """
    from scapy.all import IP, TCP, conf, sr1

    # Suppress scapy's noisy output
    conf.verb = 0

    src_port = random.randint(49152, 65535)

    pkt = (
        IP(dst=host)
        / TCP(
            sport=src_port,
            dport=port,
            flags="S",
            options=[
                ("MSS", 1460),
                ("NOP", None),
                ("WScale", 7),
                ("NOP", None),
                ("NOP", None),
                ("Timestamp", (0, 0)),
                ("SAckOK", b""),
                ("EOL", None),
            ],
        )
    )

    try:
        resp = sr1(pkt, timeout=timeout, verbose=0)
    except (OSError, PermissionError):
        return None

    if resp is None:
        return None

    # Verify it's a SYN-ACK (flags == 0x12)
    from scapy.all import TCP as TCPLayer
    if not resp.haslayer(TCPLayer):
        return None
    if resp[TCPLayer].flags != 0x12:  # SYN-ACK
        return None

    # Send RST to clean up half-open connection
    _send_rst(host, port, src_port, resp)

    return resp


def _send_rst(
    host: str,
    dport: int,
    sport: int,
    resp: Any,
) -> None:
    """Send RST to clean up the half-open connection."""
    try:
        from scapy.all import IP, TCP, send
        rst = (
            IP(dst=host)
            / TCP(
                sport=sport,
                dport=dport,
                flags="R",
                seq=resp.ack,
            )
        )
        send(rst, verbose=0)
    except Exception:
        pass  # Best-effort cleanup


# ─── Response parsing ───────────────────────────────────────────────────────

def _parse_synack(resp: Any) -> dict[str, Any]:
    """
    Extract fingerprint fields from a scapy SYN-ACK response packet.
    """
    from scapy.all import IP, TCP

    ip_layer = resp[IP]
    tcp_layer = resp[TCP]

    # IP fields
    ttl = ip_layer.ttl
    df_bit = 1 if (ip_layer.flags & 0x2) else 0  # DF = bit 1
    ip_id = ip_layer.id

    # TCP fields
    window_size = tcp_layer.window

    # Parse TCP options
    mss = 0
    window_scale = -1
    sack_ok = 0
    timestamp = 0
    options_order = _extract_options_order(tcp_layer.options)

    for opt_name, opt_value in tcp_layer.options:
        if opt_name == "MSS":
            mss = opt_value
        elif opt_name == "WScale":
            window_scale = opt_value
        elif opt_name in ("SAckOK", "SAck"):
            sack_ok = 1
        elif opt_name == "Timestamp":
            timestamp = 1

    return {
        "ttl": ttl,
        "window_size": window_size,
        "df_bit": df_bit,
        "ip_id": ip_id,
        "mss": mss,
        "window_scale": window_scale,
        "sack_ok": sack_ok,
        "timestamp": timestamp,
        "options_order": options_order,
    }


def _extract_options_order(options: list[tuple[str, Any]]) -> str:
    """
    Map scapy TCP option tuples to a short-code string.

    E.g. [("MSS", 1460), ("NOP", None), ("WScale", 7)] → "M,N,W"
    """
    codes = []
    for opt_name, _ in options:
        code = _OPT_CODES.get(opt_name, "?")
        codes.append(code)
    return ",".join(codes)


# ─── Fingerprint computation ───────────────────────────────────────────────

def _compute_fingerprint(fields: dict[str, Any]) -> tuple[str, str]:
    """
    Compute fingerprint raw string and SHA256 hash from parsed fields.

    Returns (raw_string, hash_hex_32).
    """
    raw = (
        f"{fields['ttl']}:{fields['window_size']}:{fields['df_bit']}:"
        f"{fields['mss']}:{fields['window_scale']}:{fields['sack_ok']}:"
        f"{fields['timestamp']}:{fields['options_order']}"
    )
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    return raw, h


# ─── Public API ─────────────────────────────────────────────────────────────

def tcp_fingerprint(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> dict[str, Any] | None:
    """
    Send a TCP SYN to host:port and fingerprint the SYN-ACK response.

    Returns a dict with the hash, raw fingerprint string, and individual
    fields, or None if no SYN-ACK was received.

    Requires root/CAP_NET_RAW.
    """
    resp = _send_syn(host, port, timeout)
    if resp is None:
        return None

    fields = _parse_synack(resp)
    raw, h = _compute_fingerprint(fields)

    return {
        "tcpfp_hash": h,
        "tcpfp_raw": raw,
        **fields,
    }
