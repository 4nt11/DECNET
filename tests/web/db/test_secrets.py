"""Tests for decnet.web.db.secrets — Fernet encrypt/decrypt helper."""
from __future__ import annotations

import pytest
from cryptography.fernet import Fernet, InvalidToken

from decnet.web.db import secrets as _mod


@pytest.fixture()
def fernet_key(monkeypatch) -> str:
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("DECNET_SECRET_KEY", key)
    return key


def test_round_trip(fernet_key):
    plaintext = "sk-supersecret-api-key-12345"
    ct = _mod.encrypt_secret(plaintext)
    assert ct != plaintext
    assert _mod.decrypt_secret(ct) == plaintext


def test_different_plaintexts_produce_different_ciphertexts(fernet_key):
    ct1 = _mod.encrypt_secret("alpha")
    ct2 = _mod.encrypt_secret("beta")
    assert ct1 != ct2


def test_nondeterministic_encryption(fernet_key):
    ct1 = _mod.encrypt_secret("same")
    ct2 = _mod.encrypt_secret("same")
    assert ct1 != ct2  # Fernet uses a random IV per call


def test_tampered_ciphertext_raises(fernet_key):
    ct = _mod.encrypt_secret("secret")
    tampered = ct[:-4] + "XXXX"
    with pytest.raises(InvalidToken):
        _mod.decrypt_secret(tampered)


def test_missing_key_raises_on_encrypt(monkeypatch):
    monkeypatch.delenv("DECNET_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="DECNET_SECRET_KEY"):
        _mod.encrypt_secret("anything")


def test_missing_key_raises_on_decrypt(monkeypatch):
    monkeypatch.delenv("DECNET_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="DECNET_SECRET_KEY"):
        _mod.decrypt_secret("gAAAAABanything")
