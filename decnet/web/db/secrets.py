# SPDX-License-Identifier: AGPL-3.0-or-later
"""Symmetric encryption helper for operator secrets stored in the DB.

``DECNET_SECRET_KEY`` must be a URL-safe base64-encoded 32-byte Fernet key
(generate once with ``python -m decnet.web.db.secrets``).  The env var is
read lazily — at the call site of ``encrypt_secret``/``decrypt_secret`` —
so processes that never touch encrypted columns start up without it.

Fail-closed: a missing or malformed key raises ``RuntimeError`` before any
plaintext is encrypted or any ciphertext is decrypted.
"""
from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken


def _load_key() -> bytes:
    key = os.environ.get("DECNET_SECRET_KEY", "")
    if not key:
        raise RuntimeError(
            "DECNET_SECRET_KEY is not set — cannot encrypt/decrypt secrets. "
            "Generate a key with: python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )
    return key.encode()


def encrypt_secret(plaintext: str) -> str:
    """Return a Fernet ciphertext token for *plaintext*."""
    return Fernet(_load_key()).encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a Fernet ciphertext token; raises ``InvalidToken`` if tampered."""
    try:
        return Fernet(_load_key()).decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        raise


if __name__ == "__main__":
    print(Fernet.generate_key().decode())
