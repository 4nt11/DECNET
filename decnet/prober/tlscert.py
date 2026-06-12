# SPDX-License-Identifier: AGPL-3.0-or-later
"""
TLS leaf-certificate capture from attacker-run servers.

Companion to ``decnet.prober.jarm``: JARM probes are crafted ClientHellos
that never complete a real handshake (raw byte parsing only), so the
peer certificate is never available from those sockets. This module does
a separate :func:`ssl.wrap_socket` against the same ``(host, port)``
solely to fetch and parse the leaf cert.

The cert is intentionally NOT verified — attacker-presented certs are
inherently untrusted, and rejecting self-signed ones would defeat the
whole point of the capture (most C2 infra runs self-signed certs).
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from decnet.telemetry import traced as _traced


def _cn_or_empty(name: x509.Name) -> str:
    """Return the first CN attribute as a plain string, or ``""``."""
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return ""
    return str(attrs[0].value)


def _iso_utc(dt: Any) -> str:
    """Cert validity timestamps as ``YYYY-MM-DDTHH:MM:SSZ``.

    ``cryptography`` exposes ``not_valid_before`` (deprecated, naive UTC)
    and ``not_valid_before_utc`` (timezone-aware) — prefer the latter
    when available so we always emit explicit-Z ISO strings.
    """
    return cast(str, dt.strftime("%Y-%m-%dT%H:%M:%SZ"))


def _extract_sans(cert: x509.Certificate) -> list[str]:
    """All DNS / IP SANs as a flat list of strings; empty when absent."""
    try:
        ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        return []
    sans: list[str] = []
    san: x509.SubjectAlternativeName = ext.value
    sans.extend(str(v) for v in san.get_values_for_type(x509.DNSName))
    sans.extend(str(v) for v in san.get_values_for_type(x509.IPAddress))
    return sans


@_traced("prober.tls_cert_parse")
def parse_leaf_cert(der: bytes) -> dict[str, Any] | None:
    """Parse a DER-encoded leaf cert into the prober's flat field shape.

    Returns ``None`` if parsing fails for any reason — the caller treats
    that the same as a connect failure.
    """
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception:
        return None

    try:
        subject_cn = _cn_or_empty(cert.subject)
        issuer = cert.issuer.rfc4514_string()
        issuer_cn = _cn_or_empty(cert.issuer)
        try:
            nb = cert.not_valid_before_utc
            na = cert.not_valid_after_utc
        except AttributeError:  # cryptography < 42
            nb = cert.not_valid_before
            na = cert.not_valid_after
        not_before = _iso_utc(nb)
        not_after = _iso_utc(na)
        self_signed = bool(subject_cn) and subject_cn == issuer_cn
        sans = _extract_sans(cert)
        cert_sha256 = hashlib.sha256(der).hexdigest()
    except Exception:
        return None

    return {
        "subject_cn": subject_cn,
        "issuer": issuer,
        "self_signed": self_signed,
        "not_before": not_before,
        "not_after": not_after,
        "sans": sans,
        "cert_sha256": cert_sha256,
    }


@_traced("prober.tls_cert_fetch")
def fetch_leaf_cert(
    host: str, port: int, timeout: float = 5.0
) -> dict[str, Any] | None:
    """Open a TLS connection and return the parsed leaf cert.

    Returns ``None`` on any connect / handshake / parse failure. Never
    raises — failures must collapse silently so the prober's outer loop
    can keep moving through targets.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Some attacker C2 servers gate on weak ciphers; don't constrain.
    ctx.set_ciphers("ALL:@SECLEVEL=0")

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=None) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, socket.timeout):
        return None
    except Exception:
        return None

    if not der:
        return None
    return parse_leaf_cert(der)
