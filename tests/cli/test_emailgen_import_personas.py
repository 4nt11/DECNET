"""``decnet emailgen import-personas`` CLI command."""
from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from decnet.cli import app
from decnet.orchestrator.emailgen import global_pool


@pytest.fixture(autouse=True)
def _reset_pool():
    global_pool.reset_cache()
    yield
    global_pool.reset_cache()


_TWO = [
    {
        "name": "John Smith",
        "email": "john@corp.com",
        "role": "COO",
        "tone": "formal",
        "mannerisms": ["uses 'Best regards'"],
    },
    {
        "name": "Sarah Johnson",
        "email": "sarah@corp.com",
        "role": "PM",
        "tone": "direct",
        "mannerisms": ["uses bullets"],
    },
]


def test_import_personas_writes_canonical_file(tmp_path, monkeypatch):
    src = tmp_path / "src.json"
    src.write_text(json.dumps(_TWO))
    dest = tmp_path / "global_pool.json"
    monkeypatch.setenv("DECNET_EMAILGEN_PERSONAS", str(dest))

    result = CliRunner().invoke(
        app, ["emailgen", "import-personas", str(src)]
    )
    assert result.exit_code == 0, result.stdout
    assert dest.exists()
    written = json.loads(dest.read_text())
    assert {p["email"] for p in written} == {"john@corp.com", "sarah@corp.com"}


def test_import_personas_explicit_output_overrides_env(tmp_path, monkeypatch):
    src = tmp_path / "src.json"
    src.write_text(json.dumps(_TWO))
    env_dest = tmp_path / "env.json"
    explicit = tmp_path / "explicit.json"
    monkeypatch.setenv("DECNET_EMAILGEN_PERSONAS", str(env_dest))

    result = CliRunner().invoke(
        app,
        ["emailgen", "import-personas", str(src), "--output", str(explicit)],
    )
    assert result.exit_code == 0, result.stdout
    assert explicit.exists()
    assert not env_dest.exists()


def test_import_personas_rejects_invalid_json(tmp_path):
    src = tmp_path / "src.json"
    src.write_text("{not valid")
    result = CliRunner().invoke(
        app, ["emailgen", "import-personas", str(src)]
    )
    assert result.exit_code != 0
    assert "Invalid JSON" in result.stdout


def test_import_personas_rejects_non_list(tmp_path, monkeypatch):
    src = tmp_path / "src.json"
    src.write_text(json.dumps({"not": "a list"}))
    monkeypatch.setenv("DECNET_EMAILGEN_PERSONAS", str(tmp_path / "out.json"))
    result = CliRunner().invoke(
        app, ["emailgen", "import-personas", str(src)]
    )
    assert result.exit_code != 0
    assert "list" in result.stdout.lower()


def test_import_personas_rejects_all_invalid_entries(tmp_path, monkeypatch):
    src = tmp_path / "src.json"
    src.write_text(json.dumps([
        {"name": "broken", "email": "no-at-symbol"},
    ]))
    monkeypatch.setenv("DECNET_EMAILGEN_PERSONAS", str(tmp_path / "out.json"))
    result = CliRunner().invoke(
        app, ["emailgen", "import-personas", str(src)]
    )
    assert result.exit_code != 0
    assert "No valid personas" in result.stdout


def test_import_personas_warns_on_single_persona(tmp_path, monkeypatch):
    src = tmp_path / "src.json"
    src.write_text(json.dumps(_TWO[:1]))
    dest = tmp_path / "out.json"
    monkeypatch.setenv("DECNET_EMAILGEN_PERSONAS", str(dest))
    result = CliRunner().invoke(
        app, ["emailgen", "import-personas", str(src)]
    )
    assert result.exit_code == 0, result.stdout
    assert "Warning" in result.stdout
    assert dest.exists()


def test_imported_personas_load_via_global_pool(tmp_path, monkeypatch):
    src = tmp_path / "src.json"
    src.write_text(json.dumps(_TWO))
    dest = tmp_path / "out.json"
    monkeypatch.setenv("DECNET_EMAILGEN_PERSONAS", str(dest))

    result = CliRunner().invoke(
        app, ["emailgen", "import-personas", str(src)]
    )
    assert result.exit_code == 0, result.stdout

    personas = global_pool.load()
    assert len(personas) == 2
    assert {p.email for p in personas} == {"john@corp.com", "sarah@corp.com"}
