"""DECNET SWARM PKI — self-managed X.509 CA for master↔worker mTLS.

Used by:
* the SWARM controller (master) to issue per-worker server+client certs at
  enrollment time,
* the agent (worker) to present its mTLS identity for both the control-plane
  HTTPS endpoint and the syslog-over-TLS (RFC 5425) log forwarder,
* the master-side syslog-TLS listener to authenticate inbound workers.

Storage layout (master):

    ~/.decnet/ca/
        ca.key                 (PEM, 0600 — the CA private key)
        ca.crt                 (PEM — self-signed root)
        workers/<worker-name>/
            client.crt         (issued, signed by CA)

Worker layout (delivered by /enroll response):

    ~/.decnet/agent/
        ca.crt                 (master's CA — trust anchor)
        worker.key             (worker's own private key)
        worker.crt             (signed by master CA — used for both TLS
                                server auth *and* syslog client auth)

The CA is a hard dependency only in swarm mode; unihost installs never
touch this module.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import os
import pathlib
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

DEFAULT_CA_DIR = pathlib.Path(os.path.expanduser("~/.decnet/ca"))
DEFAULT_AGENT_DIR = pathlib.Path(os.path.expanduser("~/.decnet/agent"))

CA_KEY_BITS = 4096
WORKER_KEY_BITS = 2048
CA_VALIDITY_DAYS = 3650      # 10 years — internal CA
WORKER_VALIDITY_DAYS = 825   # max permitted by modern TLS clients


@dataclass(frozen=True)
class CABundle:
    """The master's CA identity (key is secret, cert is published)."""

    key_pem: bytes
    cert_pem: bytes


@dataclass(frozen=True)
class IssuedCert:
    """A signed worker certificate + its private key, handed to the worker
    exactly once during enrollment.
    """

    key_pem: bytes
    cert_pem: bytes
    ca_cert_pem: bytes
    fingerprint_sha256: str  # hex, lowercase


# --------------------------------------------------------------------- CA ops


def _pem_private(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def generate_ca(common_name: str = "DECNET SWARM Root CA") -> CABundle:
    """Generate a fresh self-signed CA. Does not touch disk."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=CA_KEY_BITS)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DECNET"),
        ]
    )
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return CABundle(key_pem=_pem_private(key), cert_pem=_pem_cert(cert))


def save_ca(bundle: CABundle, ca_dir: pathlib.Path = DEFAULT_CA_DIR) -> None:
    ca_dir.mkdir(parents=True, exist_ok=True)
    # 0700 on the dir, 0600 on the key — defence against casual reads.
    os.chmod(ca_dir, 0o700)
    key_path = ca_dir / "ca.key"
    cert_path = ca_dir / "ca.crt"
    key_path.write_bytes(bundle.key_pem)
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(bundle.cert_pem)


def load_ca(ca_dir: pathlib.Path = DEFAULT_CA_DIR) -> CABundle:
    key_pem = (ca_dir / "ca.key").read_bytes()
    cert_pem = (ca_dir / "ca.crt").read_bytes()
    return CABundle(key_pem=key_pem, cert_pem=cert_pem)


def ensure_ca(ca_dir: pathlib.Path = DEFAULT_CA_DIR) -> CABundle:
    """Load the CA if present, otherwise generate and persist a new one."""
    if (ca_dir / "ca.key").exists() and (ca_dir / "ca.crt").exists():
        return load_ca(ca_dir)
    bundle = generate_ca()
    save_ca(bundle, ca_dir)
    return bundle


# --------------------------------------------------------------- cert issuance


def _parse_san(value: str) -> x509.GeneralName:
    """Parse a SAN entry as IP if possible, otherwise DNS."""
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        return x509.DNSName(value)


def issue_worker_cert(
    ca: CABundle,
    worker_name: str,
    sans: list[str],
    validity_days: int = WORKER_VALIDITY_DAYS,
) -> IssuedCert:
    """Sign a freshly-generated worker keypair.

    The cert is usable as BOTH a TLS server (agent's HTTPS endpoint) and a
    TLS client (syslog-over-TLS upstream to the master) — extended key usage
    covers both.  ``sans`` should include every address/name the master or
    workers will use to reach this worker — typically the worker's IP plus
    its hostname.
    """
    ca_key = serialization.load_pem_private_key(ca.key_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem)

    worker_key = rsa.generate_private_key(public_exponent=65537, key_size=WORKER_KEY_BITS)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, worker_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DECNET"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "swarm-worker"),
        ]
    )
    now = _dt.datetime.now(_dt.timezone.utc)
    san_entries: list[x509.GeneralName] = [_parse_san(s) for s in sans] if sans else []
    # Always include the worker-name as a DNS SAN so cert pinning by CN-as-DNS
    # works even when the operator forgets to pass an explicit SAN list.
    if not any(
        isinstance(e, x509.DNSName) and e.value == worker_name for e in san_entries
    ):
        san_entries.append(x509.DNSName(worker_name))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(worker_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1"),  # serverAuth
                    x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2"),  # clientAuth
                ]
            ),
            critical=True,
        )
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
    )
    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    cert_pem = _pem_cert(cert)
    fp = hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    return IssuedCert(
        key_pem=_pem_private(worker_key),
        cert_pem=cert_pem,
        ca_cert_pem=ca.cert_pem,
        fingerprint_sha256=fp,
    )


def write_worker_bundle(
    issued: IssuedCert,
    agent_dir: pathlib.Path = DEFAULT_AGENT_DIR,
) -> None:
    """Persist an issued bundle into the worker's agent directory."""
    agent_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(agent_dir, 0o700)
    (agent_dir / "ca.crt").write_bytes(issued.ca_cert_pem)
    (agent_dir / "worker.crt").write_bytes(issued.cert_pem)
    key_path = agent_dir / "worker.key"
    key_path.write_bytes(issued.key_pem)
    os.chmod(key_path, 0o600)


def load_worker_bundle(
    agent_dir: pathlib.Path = DEFAULT_AGENT_DIR,
) -> Optional[IssuedCert]:
    """Return the worker's bundle if enrolled; ``None`` otherwise."""
    ca = agent_dir / "ca.crt"
    crt = agent_dir / "worker.crt"
    key = agent_dir / "worker.key"
    if not (ca.exists() and crt.exists() and key.exists()):
        return None
    cert_pem = crt.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_pem)
    fp = hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    return IssuedCert(
        key_pem=key.read_bytes(),
        cert_pem=cert_pem,
        ca_cert_pem=ca.read_bytes(),
        fingerprint_sha256=fp,
    )


def fingerprint(cert_pem: bytes) -> str:
    """SHA-256 hex fingerprint of a cert (DER-encoded)."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
