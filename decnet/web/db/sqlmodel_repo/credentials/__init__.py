"""Credential capture + credential-reuse correlation.

Capture (per-attempt rows) lives in ``_core.py``; the reuse correlator
(grouping rows that share a secret triple) lives in ``reuse.py``.
``CredentialsMixin`` composes the two.
"""
from __future__ import annotations

from decnet.web.db.sqlmodel_repo.credentials._core import CredentialsCoreMixin
from decnet.web.db.sqlmodel_repo.credentials.reuse import CredentialReuseMixin


class CredentialsMixin(
    CredentialReuseMixin,
    CredentialsCoreMixin,
):
    """Composed credentials mixin — see submixins for the actual methods."""


__all__ = ["CredentialsMixin"]
