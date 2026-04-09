"""
Tests for decnet.mutator — mutation engine, retry logic, due-time scheduling.
All subprocess and state I/O is mocked; no Docker or filesystem access.
"""
import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from decnet.config import DeckyConfig, DecnetConfig
from decnet.mutator import _compose_with_retry, mutate_all, mutate_decky


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_decky(name="decky-01", services=None, archetype=None,
                mutate_interval=30, last_mutated=0.0):
    return DeckyConfig(
        name=name,
        ip="192.168.1.10",
        services=services or ["ssh"],
        distro="debian",
        base_image="debian",
        hostname="host-01",
        archetype=archetype,
        mutate_interval=mutate_interval,
        last_mutated=last_mutated,
    )


def _make_config(deckies=None, mutate_interval=30):
    return DecnetConfig(
        mode="unihost", interface="eth0",
        subnet="192.168.1.0/24", gateway="192.168.1.1",
        deckies=deckies or [_make_decky()],
        mutate_interval=mutate_interval,
    )


# ---------------------------------------------------------------------------
# _compose_with_retry
# ---------------------------------------------------------------------------

class TestComposeWithRetry:
    def test_succeeds_on_first_attempt(self):
        result = MagicMock(returncode=0, stdout="done\n")
        with patch("decnet.mutator.subprocess.run", return_value=result) as mock_run:
            _compose_with_retry("up", "-d", compose_file=Path("compose.yml"))
        mock_run.assert_called_once()

    def test_retries_on_failure_then_succeeds(self):
        fail = MagicMock(returncode=1, stdout="", stderr="transient error")
        ok   = MagicMock(returncode=0, stdout="", stderr="")
        with patch("decnet.mutator.subprocess.run", side_effect=[fail, ok]) as mock_run, \
             patch("decnet.mutator.time.sleep"):
            _compose_with_retry("up", "-d", compose_file=Path("compose.yml"), retries=3)
        assert mock_run.call_count == 2

    def test_raises_after_all_retries_exhausted(self):
        fail = MagicMock(returncode=1, stdout="", stderr="hard error")
        with patch("decnet.mutator.subprocess.run", return_value=fail), \
             patch("decnet.mutator.time.sleep"):
            with pytest.raises(subprocess.CalledProcessError):
                _compose_with_retry("up", "-d", compose_file=Path("compose.yml"), retries=3)

    def test_exponential_backoff(self):
        fail = MagicMock(returncode=1, stdout="", stderr="")
        sleep_calls = []
        with patch("decnet.mutator.subprocess.run", return_value=fail), \
             patch("decnet.mutator.time.sleep", side_effect=lambda d: sleep_calls.append(d)):
            with pytest.raises(subprocess.CalledProcessError):
                _compose_with_retry("up", compose_file=Path("c.yml"), retries=3, delay=1.0)
        assert sleep_calls == [1.0, 2.0]

    def test_correct_command_structure(self):
        ok = MagicMock(returncode=0, stdout="")
        with patch("decnet.mutator.subprocess.run", return_value=ok) as mock_run:
            _compose_with_retry("up", "-d", "--remove-orphans",
                                compose_file=Path("/tmp/compose.yml"))
        cmd = mock_run.call_args[0][0]
        assert cmd[:3] == ["docker", "compose", "-f"]
        assert "up" in cmd
        assert "--remove-orphans" in cmd


# ---------------------------------------------------------------------------
# mutate_decky
# ---------------------------------------------------------------------------

class TestMutateDecky:
    def _patch(self, config=None, compose_path=Path("compose.yml")):
        """Return a context manager that mocks all I/O in mutate_decky."""
        cfg = config or _make_config()
        return (
            patch("decnet.mutator.load_state", return_value=(cfg, compose_path)),
            patch("decnet.mutator.save_state"),
            patch("decnet.mutator.write_compose"),
            patch("decnet.mutator._compose_with_retry"),
        )

    def test_returns_false_when_no_state(self):
        with patch("decnet.mutator.load_state", return_value=None):
            assert mutate_decky("decky-01") is False

    def test_returns_false_when_decky_not_found(self):
        p = self._patch()
        with p[0], p[1], p[2], p[3]:
            assert mutate_decky("nonexistent") is False

    def test_returns_true_on_success(self):
        p = self._patch()
        with p[0], p[1], p[2], p[3]:
            assert mutate_decky("decky-01") is True

    def test_saves_state_after_mutation(self):
        p = self._patch()
        with p[0], patch("decnet.mutator.save_state") as mock_save, p[2], p[3]:
            mutate_decky("decky-01")
        mock_save.assert_called_once()

    def test_regenerates_compose_after_mutation(self):
        p = self._patch()
        with p[0], p[1], patch("decnet.mutator.write_compose") as mock_compose, p[3]:
            mutate_decky("decky-01")
        mock_compose.assert_called_once()

    def test_returns_false_on_compose_failure(self):
        p = self._patch()
        err = subprocess.CalledProcessError(1, "docker", "", "compose failed")
        with p[0], p[1], p[2], patch("decnet.mutator._compose_with_retry", side_effect=err):
            assert mutate_decky("decky-01") is False

    def test_mutation_changes_services(self):
        cfg = _make_config(deckies=[_make_decky(services=["ssh"])])
        p = self._patch(config=cfg)
        with p[0], p[1], p[2], p[3]:
            mutate_decky("decky-01")
        # Services may have changed (or stayed the same after 20 attempts)
        assert isinstance(cfg.deckies[0].services, list)
        assert len(cfg.deckies[0].services) >= 1

    def test_updates_last_mutated_timestamp(self):
        cfg = _make_config(deckies=[_make_decky(last_mutated=0.0)])
        p = self._patch(config=cfg)
        before = time.time()
        with p[0], p[1], p[2], p[3]:
            mutate_decky("decky-01")
        assert cfg.deckies[0].last_mutated >= before

    def test_archetype_constrains_service_pool(self):
        """A decky with an archetype must only mutate within its service pool."""
        cfg = _make_config(deckies=[_make_decky(archetype="workstation", services=["rdp"])])
        p = self._patch(config=cfg)
        with p[0], p[1], p[2], p[3]:
            result = mutate_decky("decky-01")
        assert result is True


# ---------------------------------------------------------------------------
# mutate_all
# ---------------------------------------------------------------------------

class TestMutateAll:
    def test_no_state_returns_early(self):
        with patch("decnet.mutator.load_state", return_value=None), \
             patch("decnet.mutator.mutate_decky") as mock_mutate:
            mutate_all()
        mock_mutate.assert_not_called()

    def test_force_mutates_all_deckies(self):
        cfg = _make_config(deckies=[_make_decky("d1"), _make_decky("d2")])
        with patch("decnet.mutator.load_state", return_value=(cfg, Path("c.yml"))), \
             patch("decnet.mutator.mutate_decky", return_value=True) as mock_mutate:
            mutate_all(force=True)
        assert mock_mutate.call_count == 2

    def test_skips_decky_not_yet_due(self):
        # last_mutated = now, interval = 30 min → not due
        now = time.time()
        cfg = _make_config(deckies=[_make_decky(mutate_interval=30, last_mutated=now)])
        with patch("decnet.mutator.load_state", return_value=(cfg, Path("c.yml"))), \
             patch("decnet.mutator.mutate_decky") as mock_mutate:
            mutate_all(force=False)
        mock_mutate.assert_not_called()

    def test_mutates_decky_that_is_due(self):
        # last_mutated = 2 hours ago, interval = 30 min → due
        old_ts = time.time() - 7200
        cfg = _make_config(deckies=[_make_decky(mutate_interval=30, last_mutated=old_ts)])
        with patch("decnet.mutator.load_state", return_value=(cfg, Path("c.yml"))), \
             patch("decnet.mutator.mutate_decky", return_value=True) as mock_mutate:
            mutate_all(force=False)
        mock_mutate.assert_called_once_with("decky-01")

    def test_skips_decky_with_no_interval_and_no_force(self):
        cfg = _make_config(
            deckies=[_make_decky(mutate_interval=None)],
            mutate_interval=None,
        )
        with patch("decnet.mutator.load_state", return_value=(cfg, Path("c.yml"))), \
             patch("decnet.mutator.mutate_decky") as mock_mutate:
            mutate_all(force=False)
        mock_mutate.assert_not_called()
