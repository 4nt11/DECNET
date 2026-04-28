#!/usr/bin/env python3
"""
FTP server using Twisted's FTP server infrastructure.
Accepts any credentials, logs all commands and file requests,
forwards events as JSON to LOG_TARGET if set.
"""

import os
from pathlib import Path

from twisted.internet import defer, reactor
from twisted.protocols.ftp import FTP, FTPFactory, FTPAnonymousShell
from twisted.python.filepath import FilePath
from twisted.python import log as twisted_log

import instance_seed as _seed
from syslog_bridge import (
    encode_secret,
    forward_syslog,
    syslog_line,
    write_syslog_file,
)

NODE_NAME = os.environ.get("NODE_NAME", "ftpserver")
SERVICE_NAME   = "ftp"
LOG_TARGET = os.environ.get("LOG_TARGET", "")
PORT = int(os.environ.get("PORT", "21"))

# Per-instance daemon identity. Fleet-wide "vsFTPd 3.0.3" is an instant
# fingerprint of an unmaintained honeypot — real shops run a mix.
_FTP_BANNER_CHOICES = [
    "220 (vsFTPd 3.0.3)",
    "220 (vsFTPd 3.0.5)",
    "220 ProFTPD 1.3.7a Server ready.",
    "220 ProFTPD 1.3.6 Server ready.",
    "220 Pure-FTPd Service ready.",
]
BANNER = os.environ.get("FTP_BANNER") or _seed.pick(_FTP_BANNER_CHOICES)

# Accept approximately this fraction of logins. Real anon-accessible
# servers succeed often; credential-harvesting scanners hitting every
# possible user/pass pair should still see plausible failures.
_LOGIN_SUCCESS_RATE = float(os.environ.get("FTP_LOGIN_SUCCESS_RATE", "0.9"))

# Optional override — if set to "never", ALL logins fail (realistic for a
# server with anonymous disabled). Handy for producing server diversity
# across the fleet.
_LOGIN_MODE = os.environ.get("FTP_LOGIN_MODE", "").strip().lower()


def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


def _setup_bait_fs() -> str:
    """Generate a per-instance bait filesystem.

    No shared paths across deckies (/tmp/ftp_bait was identical on every
    host), no tell-tale 'super_secret_admin_pw' strings. Filenames, byte
    counts, and inline values are all derived from the per-decky seed, so
    two honeypots never serve byte-identical files yet each stays stable
    across restarts."""
    bait_dir = Path(f"/tmp/ftp-{_seed.instance_hex(6, 'ftp-bait-dir')}")
    bait_dir.mkdir(parents=True, exist_ok=True)

    company = _seed.pick(["acme", "contoso", "northwind", "initech", "globex", "hooli"])
    env = _seed.pick(["prod", "stage", "backup", "archive"])
    year = _seed.rng.randint(2022, 2024)
    month = _seed.rng.randint(1, 12)

    # Realistic-looking rotating backups. Sizes vary per instance.
    for idx in range(_seed.rng.randint(2, 5)):
        tag = f"{year}{month:02d}{_seed.rng.randint(1, 28):02d}"
        size = _seed.rng.randint(2048, 32768)
        (bait_dir / f"{company}-{env}-{tag}.tar.gz").write_bytes(
            b"\x1f\x8b\x08\x00" + _seed.random_bytes(size - 4, f"tar-{idx}")
        )

    # A plausible README that looks like legacy ops notes, NOT a credential
    # dump. No "password = ..." strings — those are a dead giveaway.
    (bait_dir / "README.txt").write_text(
        f"{company} {env} drop area\n"
        f"Rotation: keep last 14, nightly rsync from db{_seed.rng.randint(1,9)}.{env}\n"
        f"Contact: ops-{env}@{company}.internal\n"
    )
    (bait_dir / ".htaccess").write_text("Options -Indexes\n")

    return str(bait_dir)


_BAIT_PATH = _setup_bait_fs()


class ServerFTP(FTP):
    def connectionMade(self):
        peer = self.transport.getPeer()
        _log("connection", src_ip=peer.host, src_port=peer.port)
        super().connectionMade()

    def ftp_USER(self, username):
        self._server_user = username
        _log("user", username=username)
        return super().ftp_USER(username)

    def ftp_PASS(self, password):
        _u = getattr(self, "_server_user", "?")
        _log("auth_attempt", username=_u, principal=_u, **encode_secret(password))
        # Decide whether this attempt succeeds. Unseeded randomness so
        # scanners can't predict which creds will "work".
        import random as _rand
        if _LOGIN_MODE == "never":
            accept = False
        elif _LOGIN_MODE == "always":
            accept = True
        else:
            accept = _rand.random() < _LOGIN_SUCCESS_RATE
        if not accept:
            return defer.succeed((530, "Login incorrect."))
        self.state = self.AUTHED
        self._user = getattr(self, "_server_user", "anonymous")
        self.shell = FTPAnonymousShell(FilePath(_BAIT_PATH))
        return defer.succeed((230, "Login successful."))

    def ftp_RETR(self, path):
        _log("download_attempt", path=path)
        return super().ftp_RETR(path)

    def connectionLost(self, reason):
        peer = self.transport.getPeer()
        _log("disconnect", src_ip=peer.host, src_port=peer.port)
        super().connectionLost(reason)


class ServerFTPFactory(FTPFactory):
    protocol = ServerFTP
    welcomeMessage = BANNER

if __name__ == "__main__":
    twisted_log.startLoggingWithObserver(lambda e: None, setStdout=False)
    _log("startup", msg=f"FTP server starting as {NODE_NAME} on port {PORT}")
    reactor.listenTCP(PORT, ServerFTPFactory())
    reactor.run()
