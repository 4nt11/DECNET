"""Fake ``.git/config`` with an attacker-bait remote URL.

The ``[remote "origin"]`` ``url`` field is the natural place to embed
an HTTP-callback URL: it's normal for git remotes to be HTTPS, the
URL is read by every git command an attacker runs (``git pull``,
``git fetch``, ``git remote -v``), and the slug fits naturally as
part of a path.

The generator emits a plausible private-mirror remote (``git.<org>``
or the canary host's hostname) so an attacker doesn't immediately
recognise it as a honeypot.  The slug ends up in the URL path:

    [remote "origin"]
        url = https://canary.example.test/c/<slug>/repo.git
"""
from __future__ import annotations

from decnet.canary.base import CanaryArtifact, CanaryContext, CanaryGenerator


class GitConfigGenerator(CanaryGenerator):
    name = "git_config"

    def generate(self, ctx: CanaryContext) -> CanaryArtifact:
        # Strip trailing slash defensively — operator may have
        # configured DECNET_CANARY_HTTP_BASE either way.
        base = ctx.http_base.rstrip("/")
        slug = ctx.callback_token
        # The /c/<slug>/repo.git suffix gives us a realistic-looking
        # path the worker can route on a single ``startswith("/c/")``
        # check, while still surviving a quick grep for the slug.
        url = f"{base}/c/{slug}/repo.git"
        body = (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            "\tbare = false\n"
            "\tlogallrefupdates = true\n"
            "[remote \"origin\"]\n"
            f"\turl = {url}\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            "[branch \"main\"]\n"
            "\tremote = origin\n"
            "\tmerge = refs/heads/main\n"
        )
        return CanaryArtifact(
            path="",
            content=body.encode("utf-8"),
            mode=0o644,
            mtime_offset=-86400 * 30,  # checked out a month ago
            generator=self.name,
            notes=[f"git remote 'origin' embeds {url}"],
        )
