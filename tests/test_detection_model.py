"""Tests for continuum.detection.model."""

from __future__ import annotations

import numpy as np
import pytest
from tools.simulate_attacks import generate_burst_injection, generate_human

from continuum.detection.baseline import feature_windows_to_matrix
from continuum.detection.features import FEATURE_NAMES, iter_feature_windows
from continuum.detection.model import (
    DEFAULT_TARGET_FALSE_POSITIVE_RATE,
    MIN_BASELINE_WINDOWS_TO_FIT,
    CadenceModel,
    fit_and_calibrate,
    model_path,
)

DEVICE_ID = "device-under-test"
BASELINE_DEVICE_ID = "baseline-device"


def _baseline_windows(n_streams: int = 15, n_presses: int = 80):
    windows = []
    for seed in range(n_streams):
        events = generate_human(DEVICE_ID, n_presses, seed=seed)
        windows.extend(iter_feature_windows(events, DEVICE_ID))
    return windows


def test_fit_and_calibrate_rejects_too_few_windows():
    tiny_matrix = np.zeros((MIN_BASELINE_WINDOWS_TO_FIT - 1, len(FEATURE_NAMES)))
    with pytest.raises(ValueError):
        fit_and_calibrate(
            tiny_matrix, feature_names=FEATURE_NAMES, baseline_device_id=BASELINE_DEVICE_ID
        )


@pytest.mark.parametrize("model_type", ["isolation_forest", "one_class_svm"])
def test_fit_and_calibrate_produces_a_usable_model(model_type):
    windows = _baseline_windows()
    matrix = feature_windows_to_matrix(windows, FEATURE_NAMES)

    model = fit_and_calibrate(
        matrix,
        feature_names=FEATURE_NAMES,
        baseline_device_id=BASELINE_DEVICE_ID,
        model_type=model_type,
    )

    assert model.model_type == model_type
    assert model.baseline_device_id == BASELINE_DEVICE_ID
    assert model.feature_names == list(FEATURE_NAMES)
    assert isinstance(model.threshold, float)


def test_calibration_holds_roughly_to_the_target_false_positive_rate():
    # A larger, independent sample of human windows: fit on one set,
    # check the empirical FPR on a completely different one.
    fit_windows = _baseline_windows(n_streams=20, n_presses=80)
    fit_matrix = feature_windows_to_matrix(fit_windows, FEATURE_NAMES)

    model = fit_and_calibrate(
        fit_matrix,
        feature_names=FEATURE_NAMES,
        baseline_device_id=BASELINE_DEVICE_ID,
        target_false_positive_rate=DEFAULT_TARGET_FALSE_POSITIVE_RATE,
    )

    held_out_windows = []
    for seed in range(100, 130):
        events = generate_human(DEVICE_ID, 80, seed=seed)
        held_out_windows.extend(iter_feature_windows(events, DEVICE_ID))
    held_out_matrix = feature_windows_to_matrix(held_out_windows, FEATURE_NAMES)

    scores = model.score(held_out_matrix)
    empirical_fpr = float(np.mean(scores > model.threshold))

    # Calibration targets 1%; an independent sample should land in the
    # same ballpark, not exactly on it.
    assert empirical_fpr < 0.15


def test_burst_injection_scores_higher_than_human():
    fit_windows = _baseline_windows()
    fit_matrix = feature_windows_to_matrix(fit_windows, FEATURE_NAMES)
    model = fit_and_calibrate(
        fit_matrix, feature_names=FEATURE_NAMES, baseline_device_id=BASELINE_DEVICE_ID
    )

    human_events = generate_human(DEVICE_ID, 80, seed=999)
    human_windows = list(iter_feature_windows(human_events, DEVICE_ID))
    burst_events = generate_burst_injection(DEVICE_ID, 80, seed=999)
    burst_windows = list(iter_feature_windows(burst_events, DEVICE_ID))

    human_scores = model.score(feature_windows_to_matrix(human_windows, FEATURE_NAMES))
    burst_scores = model.score(feature_windows_to_matrix(burst_windows, FEATURE_NAMES))

    assert burst_scores.mean() > human_scores.mean()


def test_save_and_load_roundtrip(tmp_path):
    windows = _baseline_windows()
    matrix = feature_windows_to_matrix(windows, FEATURE_NAMES)
    model = fit_and_calibrate(
        matrix, feature_names=FEATURE_NAMES, baseline_device_id=BASELINE_DEVICE_ID
    )

    path = tmp_path / "model.joblib"
    model.save(path)
    loaded = CadenceModel.load(path)

    assert loaded.model_type == model.model_type
    assert loaded.threshold == pytest.approx(model.threshold)
    assert loaded.feature_names == model.feature_names
    assert loaded.baseline_device_id == model.baseline_device_id
    assert loaded.version == model.version

    sample_features = windows[0].features
    assert loaded.score_one(sample_features) == pytest.approx(model.score_one(sample_features))


def test_model_path_uses_the_user_name(tmp_path):
    path = model_path("alice", model_dir=tmp_path)
    assert path == tmp_path / "alice.joblib"
