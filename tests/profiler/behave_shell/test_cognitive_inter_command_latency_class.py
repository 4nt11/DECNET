"""Step 5: ``cognitive.inter_command_latency_class``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _command_stream(starts: list[float]) -> list[AsciinemaEvent]:
    """Build an input stream that yields commands at the given start times."""
    events: list[AsciinemaEvent] = []
    for s in starts:
        events.append((s, "i", "x"))
        events.append((s + 0.05, "i", "\r"))
    return events


def test_no_commands_means_no_observation() -> None:
    out = list(extract_session([], sid="lat-empty"))
    assert [o for o in out if o.primitive == "cognitive.inter_command_latency_class"] == []


def test_single_command_no_iat_no_observation() -> None:
    out = list(extract_session(_command_stream([0.0]), sid="lat-1"))
    assert [o for o in out if o.primitive == "cognitive.inter_command_latency_class"] == []


def test_instant_bucket() -> None:
    # IATs of 0.1s — well under 0.30 cap
    starts = [i * 0.15 for i in range(6)]
    out = list(extract_session(_command_stream(starts), sid="lat-instant"))
    assert _of(out, "cognitive.inter_command_latency_class").value == "instant"


def test_typing_speed_bucket() -> None:
    # IATs around 1.0s
    starts = [i * 1.0 for i in range(6)]
    out = list(extract_session(_command_stream(starts), sid="lat-typing"))
    assert _of(out, "cognitive.inter_command_latency_class").value == "typing_speed"


def test_deliberate_bucket() -> None:
    # IATs around 1.85s — above typing (1.5), under deliberate cap (2.0)
    starts = [i * 1.9 for i in range(6)]
    out = list(extract_session(_command_stream(starts), sid="lat-deliberate"))
    assert _of(out, "cognitive.inter_command_latency_class").value == "deliberate"


def test_llm_lightweight_bucket() -> None:
    # IATs around 5s — within 2-8s band
    starts = [i * 5.05 for i in range(6)]
    out = list(extract_session(_command_stream(starts), sid="lat-lwt"))
    assert _of(out, "cognitive.inter_command_latency_class").value == "llm_lightweight"


def test_llm_heavyweight_bucket() -> None:
    # IATs around 15s — within 8-30s band; matches Claude Opus empirical
    starts = [i * 15.05 for i in range(6)]
    out = list(extract_session(_command_stream(starts), sid="lat-hvy"))
    assert _of(out, "cognitive.inter_command_latency_class").value == "llm_heavyweight"


def test_long_bucket() -> None:
    # IATs > 30s
    starts = [i * 60.0 for i in range(6)]
    out = list(extract_session(_command_stream(starts), sid="lat-long"))
    assert _of(out, "cognitive.inter_command_latency_class").value == "long"


def test_low_sample_count_reduces_confidence() -> None:
    # 2 commands → 1 IAT; below the floor
    short = list(extract_session(_command_stream([0.0, 1.0]), sid="lat-low"))
    full = list(extract_session(_command_stream([i * 1.0 for i in range(6)]), sid="lat-full"))
    s = _of(short, "cognitive.inter_command_latency_class")
    f = _of(full, "cognitive.inter_command_latency_class")
    assert s.confidence < f.confidence
