"""
Unit tests for decnet.web.db.mysql.database.build_mysql_url / resolve_url.

No MySQL server is required — these are pure URL-construction tests.
"""
import pytest

from decnet.web.db.mysql.database import build_mysql_url, resolve_url


def test_build_url_defaults(monkeypatch):
    for v in ("DECNET_DB_HOST", "DECNET_DB_PORT", "DECNET_DB_NAME",
              "DECNET_DB_USER", "DECNET_DB_PASSWORD", "DECNET_DB_URL"):
        monkeypatch.delenv(v, raising=False)
    # PYTEST_* is set by pytest itself, so empty password is allowed here.
    url = build_mysql_url()
    assert url == "mysql+aiomysql://decnet:@localhost:3306/decnet"


def test_build_url_from_env(monkeypatch):
    monkeypatch.setenv("DECNET_DB_HOST", "db.internal")
    monkeypatch.setenv("DECNET_DB_PORT", "3307")
    monkeypatch.setenv("DECNET_DB_NAME", "decnet_prod")
    monkeypatch.setenv("DECNET_DB_USER", "svc_decnet")
    monkeypatch.setenv("DECNET_DB_PASSWORD", "hunter2")
    url = build_mysql_url()
    assert url == "mysql+aiomysql://svc_decnet:hunter2@db.internal:3307/decnet_prod"


def test_build_url_percent_encodes_password(monkeypatch):
    """Passwords with @ : / # etc must not break URL parsing."""
    monkeypatch.setenv("DECNET_DB_PASSWORD", "p@ss:word/!#")
    url = build_mysql_url(user="u", host="h", port=3306, database="d")
    # @ → %40, : → %3A, / → %2F, # → %23, ! → %21
    assert "p%40ss%3Aword%2F%21%23" in url
    assert url.startswith("mysql+aiomysql://u:")
    assert url.endswith("@h:3306/d")


def test_build_url_component_args_override_env(monkeypatch):
    monkeypatch.setenv("DECNET_DB_HOST", "ignored")
    monkeypatch.setenv("DECNET_DB_PASSWORD", "env-pw")
    url = build_mysql_url(host="arg.host", user="arg-user", password="arg-pw",
                          port=9999, database="arg-db")
    assert url == "mysql+aiomysql://arg-user:arg-pw@arg.host:9999/arg-db"


def test_resolve_url_prefers_explicit_arg(monkeypatch):
    monkeypatch.setenv("DECNET_DB_URL", "mysql+aiomysql://env-url/x")
    assert resolve_url("mysql+aiomysql://explicit/y") == "mysql+aiomysql://explicit/y"


def test_resolve_url_uses_env_url_before_components(monkeypatch):
    monkeypatch.setenv("DECNET_DB_URL", "mysql+aiomysql://env-user:env-pw@env-host/env-db")
    monkeypatch.setenv("DECNET_DB_HOST", "ignored.host")
    assert resolve_url() == "mysql+aiomysql://env-user:env-pw@env-host/env-db"


def test_resolve_url_falls_back_to_components(monkeypatch):
    monkeypatch.delenv("DECNET_DB_URL", raising=False)
    monkeypatch.setenv("DECNET_DB_HOST", "fallback.host")
    monkeypatch.setenv("DECNET_DB_PASSWORD", "pw")
    url = resolve_url()
    assert "fallback.host" in url
    assert url.startswith("mysql+aiomysql://")


def test_build_url_requires_password_outside_pytest(monkeypatch):
    """Without a password and not in a pytest run, construction must fail loudly."""
    for v in ("DECNET_DB_URL", "DECNET_DB_PASSWORD"):
        monkeypatch.delenv(v, raising=False)
    # Strip every PYTEST_* env var so the safety check trips.
    import os
    for k in list(os.environ):
        if k.startswith("PYTEST"):
            monkeypatch.delenv(k, raising=False)
    with pytest.raises(ValueError, match="DECNET_DB_PASSWORD is not set"):
        build_mysql_url()
