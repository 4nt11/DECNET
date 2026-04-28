"""Body templates produce realistic, non-empty output per content class."""
from __future__ import annotations

import secrets

import pytest

from decnet.realism.bodies import make_body
from decnet.realism.taxonomy import ContentClass


_INERT_CLASSES = (
    ContentClass.NOTE,
    ContentClass.TODO,
    ContentClass.DRAFT,
    ContentClass.SCRIPT,
    ContentClass.LOG_CRON,
    ContentClass.LOG_DAEMON,
    ContentClass.CACHE_TMP,
)


@pytest.mark.parametrize("cls", _INERT_CLASSES)
def test_body_is_nonempty(cls: ContentClass) -> None:
    body = make_body(cls, "admin", rand=secrets.SystemRandom())
    assert isinstance(body, str)
    assert body.strip()


def test_todo_body_uses_checkbox_markdown() -> None:
    body = make_body(ContentClass.TODO, "admin")
    # Each line should look like a markdown checkbox; we don't pin the
    # exact distribution because the % checked is randomised.
    for line in body.strip().splitlines():
        assert line.startswith("- [")


def test_script_body_starts_with_shebang() -> None:
    seen_shebangs: set[str] = set()
    rng = secrets.SystemRandom()
    for _ in range(20):
        body = make_body(ContentClass.SCRIPT, "admin", rand=rng)
        assert body.startswith("#!")
        seen_shebangs.add(body.splitlines()[0])
    # We should pick from at least two interpreter shebangs across 20
    # trials; if not, the template list collapsed.
    assert len(seen_shebangs) >= 2


def test_log_cron_body_has_cron_syslog_shape() -> None:
    body = make_body(ContentClass.LOG_CRON, "admin", rand=secrets.SystemRandom())
    for line in body.strip().splitlines():
        assert "CRON[" in line
        assert "CMD (" in line


@pytest.mark.parametrize(
    "cls",
    [c for c in ContentClass if c.value.startswith("canary_")],
)
def test_canary_classes_raise_in_bodies(cls: ContentClass) -> None:
    with pytest.raises(NotImplementedError, match="canary"):
        make_body(cls, "admin")


def test_email_class_raises_in_bodies() -> None:
    with pytest.raises(NotImplementedError, match="email"):
        make_body(ContentClass.EMAIL, "admin")
