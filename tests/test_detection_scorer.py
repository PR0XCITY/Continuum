"""Tests for continuum.detection.scorer.

Uses a small fake model (not a real fitted CadenceModel) so debounce
and new-device logic can be tested with exact, controlled scores
instead of depending on what scikit-learn happens to produce.
"""

from __future__ import annotations

import pytest
from tools.simulate_attacks import generate_human

from continuum.common.schemas import FeatureWindow
from continuum.detection.features import NANOS_PER_SECOND
from continuum.detection.scorer import (
    DEFAULT_NEW_DEVICE_GRACE_PERIOD_SECONDS,
    DEFAULT_NEW_DEVICE_THRESHOLD_MULTIPLIER,
    Scorer,
)

BASELINE_DEVICE_ID = "baseline-device"
NEW_DEVICE_ID = "new-device"


class _FakeModel:
    def __init__(self, threshold: float = 1.0, baseline_device_id: str = BASELINE_DEVICE_ID):
        self.threshold = threshold
        self.baseline_device_id = baseline_device_id
        self.version = "fake-v1"
        self._next_score = 0.0

    def set_next_score(self, score: float) -> None:
        self._next_score = score

    def score_one(self, features: dict) -> float:  # noqa: ARG002
        return self._next_score


def _window(device_id: str, window_start_seconds: float) -> FeatureWindow:
    return FeatureWindow(
        device_id=device_id,
        window_start_ns=int(window_start_seconds * NANOS_PER_SECOND),
        n_events=30,
        features={"flight_mean_ms": 100.0},
    )


def test_single_flagged_window_is_suspicious_not_blocked():
    model = _FakeModel(threshold=1.0)
    scorer = Scorer(model)
    model.set_next_score(2.0)

    result = scorer.score_window(_window(BASELINE_DEVICE_ID, 0.0))

    assert result.verdict == "suspicious"
    assert result.anomaly_score == 2.0
    assert result.threshold == 1.0


def test_normal_window_below_threshold():
    model = _FakeModel(threshold=1.0)
    scorer = Scorer(model)
    model.set_next_score(0.5)

    result = scorer.score_window(_window(BASELINE_DEVICE_ID, 0.0))

    assert result.verdict == "normal"


def test_two_flagged_windows_within_debounce_window_escalate_to_blocked():
    model = _FakeModel(threshold=1.0)
    scorer = Scorer(model, debounce_suspicious_count=2, debounce_seconds=3.0)
    model.set_next_score(2.0)

    first = scorer.score_window(_window(BASELINE_DEVICE_ID, 0.0))
    second = scorer.score_window(_window(BASELINE_DEVICE_ID, 1.0))

    assert first.verdict == "suspicious"
    assert second.verdict == "blocked"


def test_flagged_windows_outside_the_debounce_window_do_not_combine():
    model = _FakeModel(threshold=1.0)
    scorer = Scorer(model, debounce_suspicious_count=2, debounce_seconds=3.0)
    model.set_next_score(2.0)

    first = scorer.score_window(_window(BASELINE_DEVICE_ID, 0.0))
    second = scorer.score_window(_window(BASELINE_DEVICE_ID, 10.0))

    assert first.verdict == "suspicious"
    assert second.verdict == "suspicious"  # the first flag aged out


def test_a_fast_typists_single_odd_window_does_not_trigger_a_block():
    model = _FakeModel(threshold=1.0)
    scorer = Scorer(model, debounce_suspicious_count=2, debounce_seconds=3.0)

    model.set_next_score(0.2)
    scorer.score_window(_window(BASELINE_DEVICE_ID, 0.0))
    model.set_next_score(2.0)
    odd = scorer.score_window(_window(BASELINE_DEVICE_ID, 0.5))
    model.set_next_score(0.2)
    after = scorer.score_window(_window(BASELINE_DEVICE_ID, 1.0))

    assert odd.verdict == "suspicious"
    assert after.verdict == "normal"


def test_new_device_gets_a_stricter_threshold_during_its_grace_period():
    model = _FakeModel(threshold=1.0)
    scorer = Scorer(model)

    # Between the stricter (0.5) and full (1.0) threshold.
    borderline_score = (DEFAULT_NEW_DEVICE_THRESHOLD_MULTIPLIER + 1.0) / 2.0
    model.set_next_score(borderline_score)

    baseline_result = scorer.score_window(_window(BASELINE_DEVICE_ID, 0.0))
    new_device_result = scorer.score_window(_window(NEW_DEVICE_ID, 0.0))

    assert baseline_result.verdict == "normal"
    assert new_device_result.verdict == "suspicious"
    assert new_device_result.threshold == model.threshold * DEFAULT_NEW_DEVICE_THRESHOLD_MULTIPLIER


def test_new_device_reverts_to_the_full_threshold_after_the_grace_period():
    model = _FakeModel(threshold=1.0)
    scorer = Scorer(model)
    borderline_score = (DEFAULT_NEW_DEVICE_THRESHOLD_MULTIPLIER + 1.0) / 2.0

    model.set_next_score(0.0)
    scorer.score_window(_window(NEW_DEVICE_ID, 0.0))  # establishes first_seen

    model.set_next_score(borderline_score)
    after_grace_period = scorer.score_window(
        _window(NEW_DEVICE_ID, DEFAULT_NEW_DEVICE_GRACE_PERIOD_SECONDS + 10.0)
    )

    assert after_grace_period.verdict == "normal"
    assert after_grace_period.threshold == model.threshold


def test_score_events_windows_and_scores_a_whole_stream():
    model = _FakeModel(threshold=1.0)
    scorer = Scorer(model)
    model.set_next_score(0.1)

    events = generate_human(BASELINE_DEVICE_ID, 80, seed=1)
    results = scorer.score_events(events, BASELINE_DEVICE_ID)

    assert len(results) > 0
    assert all(result.device_id == BASELINE_DEVICE_ID for result in results)
    assert all(result.verdict == "normal" for result in results)


def test_reset_device_clears_debounce_history():
    model = _FakeModel(threshold=1.0)
    scorer = Scorer(model, debounce_suspicious_count=2, debounce_seconds=3.0)
    model.set_next_score(2.0)

    scorer.score_window(_window(BASELINE_DEVICE_ID, 0.0))
    scorer.reset_device(BASELINE_DEVICE_ID)
    after_reset = scorer.score_window(_window(BASELINE_DEVICE_ID, 0.5))

    assert after_reset.verdict == "suspicious"  # not "blocked": history was cleared


def test_invalid_configuration_is_rejected():
    model = _FakeModel()
    with pytest.raises(ValueError):
        Scorer(model, debounce_suspicious_count=0)
    with pytest.raises(ValueError):
        Scorer(model, new_device_threshold_multiplier=1.5)


def test_sensitivity_five_is_the_calibrated_threshold():
    from continuum.detection.scorer import threshold_offset_for_sensitivity

    assert threshold_offset_for_sensitivity(5) == 0.0


def test_higher_sensitivity_lowers_the_threshold():
    from continuum.detection.scorer import threshold_offset_for_sensitivity

    offsets = [threshold_offset_for_sensitivity(s) for s in range(1, 11)]
    assert offsets == sorted(offsets, reverse=True)
    assert offsets[-1] < 0 < offsets[0]


@pytest.mark.parametrize("sensitivity", [0, 11])
def test_out_of_range_sensitivity_is_rejected(sensitivity):
    from continuum.detection.scorer import threshold_offset_for_sensitivity

    with pytest.raises(ValueError):
        threshold_offset_for_sensitivity(sensitivity)


def test_threshold_offset_shifts_the_effective_threshold():
    model = _FakeModel(threshold=1.0)
    scorer = Scorer(model, threshold_offset=-0.25)
    model.set_next_score(0.9)

    result = scorer.score_window(_window(BASELINE_DEVICE_ID, 0.0))

    assert scorer.base_threshold == pytest.approx(0.75)
    assert result.threshold == pytest.approx(0.75)
    assert result.verdict == "suspicious"
