"""W.2 smoke: BEHAVE library pins are install-time importable.

Three asserts protect the pyproject.toml pin from a broken wheel /
missing install / drift in the BEHAVE-side public API. CI catches
these before they make it onto a running master.
"""
from __future__ import annotations


def test_envelope_imports_cleanly() -> None:
    from decnet_behave_core.spec.envelope import Observation, Window
    # construction smoke — registry-agnostic envelope
    obs = Observation(
        primitive="motor.input_modality",
        value="typed",
        confidence=0.9,
        window=Window(start_ts=0.0, end_ts=1.0),
        source="test",
    )
    assert obs.primitive == "motor.input_modality"
    assert obs.v >= 1


def test_registry_imports_and_is_non_empty() -> None:
    from decnet_behave_shell.spec.primitives import PRIMITIVE_REGISTRY
    assert len(PRIMITIVE_REGISTRY) > 0
    # spot-check a primitive every Tier-A engine emits
    assert "motor.input_modality" in PRIMITIVE_REGISTRY


def test_event_adapter_topic_shape() -> None:
    from decnet_behave_shell.spec.event_adapter import event_topic_for
    assert (
        event_topic_for("motor.input_modality")
        == "attacker.observation.motor.input_modality"
    )


def test_to_event_payload_excludes_envelope_meta_fields() -> None:
    """The adapter excludes id/ts/v from payload (they ride at the
    DECNET Event envelope level). The profiler worker re-merges them
    in per BEHAVE-INTEGRATION.md §339-366."""
    from decnet_behave_core.spec.envelope import Observation, Window
    from decnet_behave_shell.spec.event_adapter import to_event_payload
    obs = Observation(
        primitive="motor.input_modality",
        value="typed",
        confidence=0.9,
        window=Window(start_ts=0.0, end_ts=1.0),
        source="test",
    )
    payload = to_event_payload(obs)
    for excluded in ("id", "ts", "v"):
        assert excluded not in payload, (
            f"event_adapter.to_event_payload leaked {excluded!r} into "
            f"the payload body — DECNET re-merges these explicitly"
        )
