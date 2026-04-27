"""Coverage for the persona-aware path resolver + placement validator."""
from __future__ import annotations

import pytest

from decnet.canary.paths import (
    DEFAULT_LINUX_USER,
    DEFAULT_WINDOWS_USER,
    default_path_for,
    default_user,
    normalize_placement,
)


def test_default_user_dispatch() -> None:
    assert default_user("linux") == DEFAULT_LINUX_USER
    assert default_user("windows") == DEFAULT_WINDOWS_USER
    # Unknown personas fall through to Linux — better to plant than fail.
    assert default_user("aix") == DEFAULT_LINUX_USER


@pytest.mark.parametrize(
    "generator, persona, expected_substr",
    [
        ("aws_creds", "linux", "/home/admin/.aws/credentials"),
        ("aws_creds", "windows", "/home/Administrator/.aws/credentials"),
        ("env_file", "linux", "/home/admin/.env"),
        ("env_file", "windows", "/home/Administrator/Desktop/prod.env"),
        ("git_config", "linux", "/home/admin/.git/config"),
        ("ssh_key", "linux", "/home/admin/.ssh/id_rsa"),
        ("honeydoc", "linux", "/home/admin/Documents/quarterly_report.docx"),
    ],
)
def test_default_path_for_known_generators(
    generator: str, persona: str, expected_substr: str,
) -> None:
    assert default_path_for(generator, persona) == expected_substr


def test_default_path_for_unknown_generator_falls_through() -> None:
    # Unknown generator — defensive /tmp drop. The API rejects unknowns
    # upstream, but the resolver shouldn't crash if one slips through.
    assert default_path_for("bogus") == "/tmp/bogus.canary"


def test_normalize_placement_accepts_clean_paths() -> None:
    assert normalize_placement("/home/admin/.env") == "/home/admin/.env"
    assert normalize_placement("/var/lib/x") == "/var/lib/x"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "relative/path",
        "./still-relative",
        "/path/with\x00nul",
        "/path/with\nnewline",
        "/path/with\rcr",
        "/path/../escape",
        "/trailing/..",
    ],
)
def test_normalize_placement_rejects_bad(bad: str) -> None:
    with pytest.raises(ValueError):
        normalize_placement(bad)
