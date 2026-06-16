# SPDX-License-Identifier: AGPL-3.0-or-later
"""``motor.digraph_simhash`` — keystroke-rhythm biometric.

Builds typed input streams (single-char ``"i"`` events at a fixed
inter-key gap) and asserts the LSH property: same typist → Hamming-close,
different cadence → far apart, pastes excluded, thin sessions silent.
"""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent
from decnet.util.simhash import from_bytes8, hamming64

# A realistic multi-command session: plenty of distinct digraphs, > 20 samples.
_PHRASE = "ls -la /etc; cat /etc/passwd; whoami; uname -a; netstat -tlnp\r"


def _typed(phrase: str, dt: float, *, start: float = 0.0) -> list[AsciinemaEvent]:
    events: list[AsciinemaEvent] = []
    t = start
    for ch in phrase:
        events.append((t, "i", ch))
        t += dt
    return events


def _digraph_obs(events: list[AsciinemaEvent], sid: str):
    out = list(extract_session(events, sid=sid))
    obs = [o for o in out if o.primitive == "motor.digraph_simhash"]
    return obs


def _hash_int(obs) -> int:
    return from_bytes8(bytes.fromhex(obs.value))


def test_emits_one_observation_for_a_normal_session() -> None:
    obs = _digraph_obs(_typed(_PHRASE, 0.12), "dg-basic")
    assert len(obs) == 1
    assert len(obs[0].value) == 16  # 64-bit hex
    assert 0.0 < obs[0].confidence <= 0.95


def test_same_typist_identical_timing_is_identical() -> None:
    a = _digraph_obs(_typed(_PHRASE, 0.12), "dg-a")[0]
    b = _digraph_obs(_typed(_PHRASE, 0.12), "dg-b")[0]
    # Identical text + timing → identical fingerprint (0 Hamming).
    assert hamming64(_hash_int(a), _hash_int(b)) == 0


def test_different_cadence_separates() -> None:
    fast = _digraph_obs(_typed(_PHRASE, 0.05), "dg-fast")[0]
    slow = _digraph_obs(_typed(_PHRASE, 0.45), "dg-slow")[0]
    # Same vocabulary, very different flight-time buckets → the hashes diverge.
    assert hamming64(_hash_int(fast), _hash_int(slow)) > 0


def test_pastes_do_not_form_digraphs() -> None:
    # A session made of large paste events (len >= 4) carries no single-char
    # keystrokes, so no digraphs and no observation.
    events: list[AsciinemaEvent] = [
        (float(i), "i", "sudo apt-get update") for i in range(10)
    ]
    assert _digraph_obs(events, "dg-paste") == []


def test_thin_session_is_silent() -> None:
    # Below MIN_DIGRAPHS_FOR_SIMHASH / MIN_DIGRAPH_SAMPLES → no emission.
    assert _digraph_obs(_typed("ls\r", 0.1), "dg-thin") == []
