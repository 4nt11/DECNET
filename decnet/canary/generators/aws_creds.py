"""Fake ``~/.aws/credentials`` block (passive bait).

This is the **passive** variant — no callback wiring.  An attacker
who exfils these keys can't trip a detection unless we run a real
AWS account with a deny-all CloudTrail listener (post-v1).  The
realism is the point: the file looks like a routinely used credentials
file, so the rest of the decky's persona feels lived-in.

If the operator picks ``kind="aws_passive"`` we accept that no slug
will be embedded.  If they pick ``kind="http"`` or ``kind="dns"`` for
this generator, the API will reject the combination with a 400 — AWS
keys have no plausible field where a URL or hostname survives a
``grep -E '[A-Z0-9]{20}'`` smell test.
"""
from __future__ import annotations

import hashlib
from secrets import token_urlsafe

from decnet.canary.base import CanaryArtifact, CanaryContext, CanaryGenerator


# Stable AWS-style key body derived from the slug.  Keeping the
# generator deterministic (per-slug) means re-seeding produces the
# same bytes — the planter is naturally idempotent and an operator
# who runs ``decnet canary verify`` can re-derive the expected file
# without touching the DB.

def _fake_access_key(seed: str) -> str:
    # AWS access keys are 20 chars, uppercase alphanum, AKIA prefix.
    body = hashlib.sha256(seed.encode()).hexdigest().upper()
    return "AKIA" + body[:16]


def _fake_secret_key(seed: str) -> str:
    # AWS secret keys are 40 chars, mixed-case base64-ish.  We use
    # base64-safe characters from token_urlsafe seeded by a SHA-256
    # of the seed so the output is stable per slug.
    h = hashlib.sha256(("secret:" + seed).encode()).digest()
    # Reuse token_urlsafe for the alphabet but pad to 40 chars from
    # the deterministic bytes so we don't depend on os.urandom.
    import base64
    return base64.b64encode(h)[:40].decode()


class AWSCredsGenerator(CanaryGenerator):
    name = "aws_creds"

    def generate(self, ctx: CanaryContext) -> CanaryArtifact:
        seed = ctx.callback_token
        access = _fake_access_key(seed)
        secret = _fake_secret_key(seed)
        body = (
            "[default]\n"
            f"aws_access_key_id = {access}\n"
            f"aws_secret_access_key = {secret}\n"
            "region = us-east-1\n"
            "\n"
            "[prod]\n"
            f"aws_access_key_id = {_fake_access_key('prod-' + seed)}\n"
            f"aws_secret_access_key = {_fake_secret_key('prod-' + seed)}\n"
            "region = us-west-2\n"
        )
        return CanaryArtifact(
            path="",  # caller (planter) fills this from CanaryToken.placement_path
            content=body.encode("utf-8"),
            mode=0o600,
            mtime_offset=-86400 * 14,  # 2 weeks ago — looks lived-in
            generator=self.name,
            notes=[
                "fake AWS keys; no callback embedded — passive bait only",
                f"derived deterministically from slug={seed}",
            ],
        )


# Re-exported so the slug helper is reusable from the
# instrumenters/passthrough module without an internal import path.
__all__ = ["AWSCredsGenerator", "_fake_access_key", "_fake_secret_key"]


# Imports at the bottom keep the public dataclasses on top — pylint
# doesn't run on this repo, but tests do, and putting ``token_urlsafe``
# in a public symbol confuses readers.  Suppress the unused warning by
# referencing it once.
_ = token_urlsafe
