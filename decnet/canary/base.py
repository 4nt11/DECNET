"""Canary generator / instrumenter ABCs and the artifact dataclass.

Two flavors of producer share the same return shape:

* :class:`CanaryGenerator` synthesises a fake artifact from scratch
  (e.g. a plausible ``~/.aws/credentials`` block, a ``.git/config``
  pointing at an attacker-bait remote URL).  Operators don't supply
  any input.

* :class:`CanaryInstrumenter` mutates an operator-uploaded blob to
  embed the callback (HTTP slug + DNS host).  The original blob bytes
  are passed in; the instrumenter returns the mutated version.

Both return a :class:`CanaryArtifact` — the planter doesn't care
which path produced it.  Same dataclass keeps the planter's
docker-exec injector trivial.

ABCs intentionally do not include I/O — generators and instrumenters
are pure functions of (slug, host, blob?).  All filesystem work
happens in :mod:`decnet.canary.planter` and :mod:`decnet.canary.storage`.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CanaryContext:
    """Inputs every generator/instrumenter needs to embed a working callback.

    ``callback_token`` is the unique slug; it appears verbatim in HTTP
    URLs (``https://<host>/c/<callback_token>``) and as the leftmost
    DNS label (``<callback_token>.canary.<dns_zone>``) so a single
    slug resolves to a single :class:`CanaryToken` row regardless of
    which path the attacker tripped.

    ``http_base`` and ``dns_zone`` come from the canary worker's
    public-facing config (``DECNET_CANARY_HTTP_BASE``,
    ``DECNET_CANARY_DNS_ZONE``).  When DNS isn't deployed,
    ``dns_zone`` is empty and instrumenters that only have a DNS
    surface (e.g. an artifact whose only realistic embed point is a
    hostname) raise.
    """

    callback_token: str
    http_base: str  # e.g. "https://canary.example.test" — no trailing slash
    dns_zone: str = ""  # e.g. "canary.example.test"; "" disables DNS embeds
    persona: str = "linux"  # "linux" | "windows" — drives default username, path style


@dataclass
class CanaryArtifact:
    """Bytes-and-placement bundle produced by a generator/instrumenter."""

    path: str
    """Absolute path inside the target container."""

    content: bytes
    """Final bytes that hit the decky filesystem.

    Always raw bytes — the planter base64-encodes for the wire so
    binary blobs (DOCX/PNG/PDF) survive ``docker exec sh -c`` safely.
    """

    mode: int = 0o600
    """Unix file mode.  Defaults to ``0600`` because most realistic
    canary placements (``~/.aws/credentials``, ``.env``, ``id_rsa``)
    are operator-only.  Honeydocs in user docs folders should pass
    ``0o644``.
    """

    mtime_offset: int = 0
    """Seconds relative to *now* for the planted file's mtime.

    Negative values backdate the file so it doesn't look like it
    appeared the moment the decky was deployed.  ``-86400 * 90`` (90
    days ago) is a common choice for ``honeydoc`` artifacts; ``0``
    means "stamp it now," which is fine for ``aws_creds``-like files
    that would plausibly be touched recently.
    """

    instrumenter: Optional[str] = None
    """Identifier of the instrumenter that produced this artifact (for
    upload-driven tokens).  Mirrored into ``CanaryToken.instrumenter``.
    Mutually exclusive with :attr:`generator`.
    """

    generator: Optional[str] = None
    """Identifier of the generator that produced this artifact (for
    synthesised tokens).  Mirrored into ``CanaryToken.generator``.
    Mutually exclusive with :attr:`instrumenter`.
    """

    notes: list[str] = field(default_factory=list)
    """Human-readable notes about the embedding (e.g. "DOCX: injected
    1×1 remote image at relsId rId99").  Surfaced in the API
    ``preview`` response so the operator sees what we did before
    planting.  Never leaked to the attacker-facing surface.
    """

    fingerprint_nonce: Optional[str] = None
    """Per-mint HMAC nonce for fingerprint canaries; ``None`` for everything
    else.  Cultivator reads this and persists it on ``CanaryToken.fingerprint_nonce``
    so the worker can validate incoming ``?k=`` params.
    """


class CanaryGenerator(ABC):
    """Produces a fake artifact from scratch."""

    name: str  #: short tag — matches ``CanaryToken.generator``

    @abstractmethod
    def generate(self, ctx: CanaryContext) -> CanaryArtifact:
        """Synthesise the artifact.

        MUST NOT do I/O.  MUST be deterministic for the same
        ``(callback_token, http_base, dns_zone, persona)`` so re-seeding
        from :attr:`CanaryToken.secret_seed` produces byte-identical
        output and the planter is naturally idempotent.
        """


class CanaryInstrumenter(ABC):
    """Mutates an operator-uploaded blob to embed a callback."""

    name: str  #: short tag — matches ``CanaryToken.instrumenter``

    #: MIME prefixes this instrumenter handles.  The factory uses these
    #: to dispatch by sniffed content-type.  Sub-string match against
    #: the prefix list (e.g. ``("application/pdf",)`` or
    #: ``("text/",)``).
    mime_prefixes: tuple[str, ...] = ()

    @abstractmethod
    def instrument(
        self, blob: bytes, ctx: CanaryContext, *, target_path: str,
    ) -> CanaryArtifact:
        """Return the mutated bytes with the callback embedded.

        MUST raise :class:`InstrumenterRejectedError` when the blob
        can't be safely mutated (corrupt zip, encrypted PDF, etc.) so
        the API can surface a 400 with the specific reason rather than
        silently shipping the original bytes.
        """


class InstrumenterRejectedError(ValueError):
    """Raised when an instrumenter can't safely mutate the input."""
