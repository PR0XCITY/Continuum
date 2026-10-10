"""Tests for continuum.detection.baseline."""

from __future__ import annotations

from datetime import UTC, datetime

import numpy as np
import pytest
from tools.simulators import human_like_events

from continuum.detection.baseline import (
    MIN_RECOMMENDED_WINDOWS,
    Baseline,
    append_feature_windows,
    baseline_path,
    build_quality_report,
    load_baseline,
    load_feature_matrix_and_scaler,
    save_baseline,
)
from continuum.detection.features import DEFAULT_WINDOW_SIZE, FEATURE_NAMES, iter_feature_windows

DEVICE_ID = "device-under-test"


def _some_windows(n_presses: int, *, rng=None):
    events = human_like_events(DEVICE_ID, n_presses=n_presses, rng=rng)
    return list(iter_feature_windows(events, DEVICE_ID))


def test_baseline_path_uses_the_user_name(tmp_path):
    path = baseline_path("alice", baseline_dir=tmp_path)
    assert path == tmp_path / "alice.npz"


def test_baseline_path_sanitises_unsafe_characters(tmp_path):
    path = baseline_path(" bob/the builder ", baseline_dir=tmp_path)
    assert path.parent == tmp_path
    assert path.name.endswith(".npz")
    assert "/" not in path.name


def test_save_and_load_baseline_roundtrip(tmp_path):
    windows = _some_windows(DEFAULT_WINDOW_SIZE * 2)
    baseline = Baseline(
        user="alice",
        device_id=DEVICE_ID,
        feature_names=list(FEATURE_NAMES),
        features=np.array([[w.features[name] for name in FEATURE_NAMES] for w in windows]),
        captured_at=[datetime.now(UTC) for _ in windows],
    )
    path = tmp_path / "alice.npz"
    save_baseline(path, baseline)

    loaded = load_baseline(path)

    assert loaded.user == "alice"
    assert loaded.device_id == DEVICE_ID
    assert loaded.feature_names == list(FEATURE_NAMES)
    assert loaded.n_windows == len(windows)
    assert np.allclose(loaded.features, baseline.features)


def test_load_baseline_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_baseline(tmp_path / "does-not-exist.npz")


def test_append_feature_windows_creates_a_new_baseline(tmp_path):
    windows = _some_windows(DEFAULT_WINDOW_SIZE)
    path = tmp_path / "alice.npz"

    baseline = append_feature_windows(path, user="alice", device_id=DEVICE_ID, windows=windows)

    assert path.exists()
    assert baseline.n_windows == len(windows)


def test_append_feature_windows_accumulates_across_sittings(tmp_path):
    path = tmp_path / "alice.npz"
    first_sitting = _some_windows(DEFAULT_WINDOW_SIZE, rng=np.random.default_rng(1))
    second_sitting = _some_windows(DEFAULT_WINDOW_SIZE * 2, rng=np.random.default_rng(2))

    append_feature_windows(path, user="alice", device_id=DEVICE_ID, windows=first_sitting)
    baseline = append_feature_windows(
        path, user="alice", device_id=DEVICE_ID, windows=second_sitting
    )

    assert baseline.n_windows == len(first_sitting) + len(second_sitting)

    reloaded = load_baseline(path)
    assert reloaded.n_windows == baseline.n_windows
    # First sitting's rows come before the second sitting's.
    first_row_count = len(first_sitting)
    assert np.allclose(
        reloaded.features[:first_row_count],
        np.array([[w.features[name] for name in FEATURE_NAMES] for w in first_sitting]),
    )


def test_append_feature_windows_rejects_a_different_user(tmp_path):
    path = tmp_path / "alice.npz"
    windows = _some_windows(DEFAULT_WINDOW_SIZE)
    append_feature_windows(path, user="alice", device_id=DEVICE_ID, windows=windows)

    with pytest.raises(ValueError, match="user"):
        append_feature_windows(path, user="bob", device_id=DEVICE_ID, windows=windows)


def test_append_feature_windows_rejects_a_different_device(tmp_path):
    path = tmp_path / "alice.npz"
    windows = _some_windows(DEFAULT_WINDOW_SIZE)
    append_feature_windows(path, user="alice", device_id=DEVICE_ID, windows=windows)

    with pytest.raises(ValueError, match="device"):
        append_feature_windows(
            path, user="alice", device_id="a-different-keyboard", windows=windows
        )


def test_load_feature_matrix_and_scaler_normalises_to_zero_mean_unit_variance(tmp_path):
    windows = _some_windows(DEFAULT_WINDOW_SIZE * 10)
    path = tmp_path / "alice.npz"
    append_feature_windows(path, user="alice", device_id=DEVICE_ID, windows=windows)

    matrix, scaler = load_feature_matrix_and_scaler(path)
    scaled = scaler.transform(matrix)

    assert matrix.shape == (len(windows), len(FEATURE_NAMES))
    assert np.allclose(scaled.mean(axis=0), 0.0, atol=1e-6)
    # Columns with zero variance in the source data (for human-like
    # synthetic events, burst_score is always 0) scale to a constant 0,
    # not unit variance; StandardScaler sets scale_ to 1.0 for those to
    # avoid dividing by zero, so check the real pre-scaling variance.
    nonzero_variance = scaler.var_ > 1e-12
    assert np.allclose(scaled.std(axis=0)[nonzero_variance], 1.0, atol=1e-6)


def test_quality_report_warns_below_the_recommended_window_count(tmp_path):
    windows = _some_windows(DEFAULT_WINDOW_SIZE)  # just one window
    path = tmp_path / "alice.npz"
    baseline = append_feature_windows(path, user="alice", device_id=DEVICE_ID, windows=windows)

    report = build_quality_report(baseline)

    assert f"Windows: {baseline.n_windows}" in report
    assert "WARNING" in report
    assert str(MIN_RECOMMENDED_WINDOWS) in report


def test_quality_report_has_no_warning_at_the_recommended_window_count():
    # Enough presses to produce at least MIN_RECOMMENDED_WINDOWS windows
    # at the default window size and step.
    n_presses = DEFAULT_WINDOW_SIZE + MIN_RECOMMENDED_WINDOWS * 10
    windows = _some_windows(n_presses)
    assert len(windows) >= MIN_RECOMMENDED_WINDOWS

    baseline = Baseline(
        user="alice",
        device_id=DEVICE_ID,
        feature_names=list(FEATURE_NAMES),
        features=np.array([[w.features[name] for name in FEATURE_NAMES] for w in windows]),
        captured_at=[datetime.now(UTC) for _ in windows],
    )

    report = build_quality_report(baseline)

    assert "WARNING" not in report
