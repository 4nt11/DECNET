"""Fake SSH private key with the callback host in the comment.

OpenSSH private keys carry a free-form comment field — typically
``user@host`` — that's preserved across rounds of ``ssh-keygen -p``.
We embed the canary host as the ``user@host`` so an attacker who
imports the key into their own keyring or runs ``ssh-keygen -lf`` on
it sees a hostname they may then try to reach.

The key bytes themselves are syntactically valid (PEM envelope, base64
body) but cryptographically junk — the body is a deterministic SHA-256
hash of the slug repeated to the right length.  We don't ship a real
RSA/Ed25519 key because (a) we don't want a real private key sitting
on disk pretending to be valuable, and (b) the attacker ``cat``-ing
the file or running ``ssh -i`` will trigger the callback regardless
of cryptographic validity.

The DNS-callback variant uses ``<slug>.canary.<dns_zone>`` as the
hostname so a bare ``ssh-keygen -lf`` on the file resolves a unique
subdomain even if the attacker never hits HTTP.
"""
from __future__ import annotations

import base64
import hashlib

from decnet.canary.base import CanaryArtifact, CanaryContext, CanaryGenerator


def _fake_key_body(seed: str) -> str:
    # Real OpenSSH keys are several hundred base64 chars; we make a
    # plausible-looking 24-line block from a SHA-256-derived stream.
    h = hashlib.sha256(seed.encode()).digest()
    long_stream = (h * 32)[:768]  # 768 bytes → ~1024 base64 chars
    encoded = base64.b64encode(long_stream).decode()
    # Wrap at 70 chars per line — same shape ``ssh-keygen`` produces.
    return "\n".join(encoded[i:i + 70] for i in range(0, len(encoded), 70))


class SSHKeyGenerator(CanaryGenerator):
    name = "ssh_key"

    def generate(self, ctx: CanaryContext) -> CanaryArtifact:
        slug = ctx.callback_token
        body = _fake_key_body(slug)
        # Hostname for the comment: prefer DNS-zone form when the
        # operator has DNS deployed (so ssh-keygen -lf names a subdomain
        # the attacker may resolve); fall back to the http_base host
        # otherwise.
        if ctx.dns_zone:
            host_comment = f"deploy@{slug}.{ctx.dns_zone}"
        else:
            from urllib.parse import urlparse
            host = urlparse(ctx.http_base).hostname or "deploy.local"
            host_comment = f"deploy@{host}"
        content = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{body}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
            f"# {host_comment}\n"
        )
        return CanaryArtifact(
            path="",
            content=content.encode("utf-8"),
            mode=0o600,
            mtime_offset=-86400 * 60,  # 2 months ago
            generator=self.name,
            notes=[f"comment line embeds {host_comment}"],
        )
