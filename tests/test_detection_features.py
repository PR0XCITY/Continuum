"""Tests for continuum.detection.features.

Uses synthetic event streams from tools/simulators.py: human-like
(lognormal flight intervals around 150 ms) and injection-like (constant
5 ms). Covers that the two cadences separate clearly on the computed
features, plus the windowing edge cases: too few events, pauses
splitting a window, and repeat events being ignored.
"""

from __future__ import annotations

import numpy as np
import pytest
from tools.simulators import human_like_events, injection_like_events

from continuum.common.schemas import KeyEvent
from continuum.detection.features import (
    DEFAULT_PAUSE_SPLIT_SECONDS,
    DEFAULT_WINDOW_SIZE,
    DEFAULT_WINDOW_STEP,
    FEATURE_NAMES,
    NANOS_PER_SECOND,
    iter_feature_windows,
)

DEVICE_ID = "device-under-test"


def _make_event(
    timestamp_ns: int, event_type: str, press_id: int, is_repeat: bool = False
) -> KeyEvent:
    return KeyEvent(
        device_id=DEVICE_ID,
        timestamp_ns=timestamp_ns,
        event_type=event_type,
        press_id=press_id,
        is_repeat=is_repeat,
    )


# --- human vs injection cadence separation ----------------------------------


def test_human_and_injection_cadence_separate_clearly():
    rng = np.random.default_rng(seed=42)
    human_events = human_like_events(DEVICE_ID, n_presses=200, rng=rng)
    injection_events = injection_like_events(DEVICE_ID, n_presses=200)

    [human_window, *_] = iter_feature_windows(human_events, DEVICE_ID)
    [injection_window, *_] = iter_feature_windows(injection_events, DEVICE_ID)

    human = human_window.features
    injection = injection_window.features

    # Flight interval scale: human centred near 150ms, injection near 5ms.
    assert 50.0 < human["flight_mean_ms"] < 400.0
    assert injection["flight_mean_ms"] == pytest.approx(5.0, abs=0.5)

    # Variance-derived features: injection is machine-constant, so these
    # collapse to their degenerate values; human typing does not.
    assert human["flight_cv"] > injection["flight_cv"]
    assert injection["flight_cv"] == pytest.approx(0.0, abs=1e-6)

    assert human["interval_entropy"] > injection["interval_entropy"]
    assert injection["interval_entropy"] == pytest.approx(0.0, abs=1e-6)

    assert human["regularity_ratio"] < injection["regularity_ratio"]
    assert injection["regularity_ratio"] == pytest.approx(1.0, abs=1e-6)

    assert injection["autocorr_lag1"] == pytest.approx(1.0, abs=1e-6)
    assert abs(human["autocorr_lag1"] - 1.0) > 0.05

    # Burst: injection intervals (5ms) are all under the 15ms threshold,
    # human intervals (median 150ms) mostly are not.
    assert injection["burst_score"] == pytest.approx(1.0, abs=1e-6)
    assert human["burst_score"] < 0.2


def test_feature_window_has_every_declared_feature_and_plain_floats():
    events = human_like_events(DEVICE_ID, n_presses=DEFAULT_WINDOW_SIZE)
    [window] = iter_feature_windows(events, DEVICE_ID)

    assert set(window.features) == set(FEATURE_NAMES)
    assert len(FEATURE_NAMES) == 17
    for value in window.features.values():
        assert type(value) is float


# --- dwell time -------------------------------------------------------------


def test_dwell_time_statistics_match_known_values():
    # Three presses with exact dwell times of 50, 60 and 70 ms, spaced
    # 200ms apart so there is no overlap.
    events = [
        _make_event(0, "down", 1),
        _make_event(50_000_000, "up", 1),
        _make_event(200_000_000, "down", 2),
        _make_event(260_000_000, "up", 2),
        _make_event(400_000_000, "down", 3),
        _make_event(470_000_000, "up", 3),
    ]
    [window] = iter_feature_windows(events, DEVICE_ID, window_size=3, window_step=1)

    assert window.features["dwell_mean_ms"] == pytest.approx(60.0)
    assert window.features["dwell_min_ms"] == pytest.approx(50.0)
    assert window.features["dwell_max_ms"] == pytest.approx(70.0)


# --- rollover ----------------------------------------------------------------


def test_rollover_ratio_detects_overlapping_presses():
    # Press 2 goes down before press 1 comes up: a rollover.
    events = [
        _make_event(0, "down", 1),
        _make_event(100_000_000, "down", 2),  # press 2 down before press 1 up
        _make_event(120_000_000, "up", 1),
        _make_event(220_000_000, "up", 2),
        _make_event(300_000_000, "down", 3),
        _make_event(350_000_000, "up", 3),
    ]
    [window] = iter_feature_windows(events, DEVICE_ID, window_size=3, window_step=1)

    assert window.features["rollover_ratio"] > 0.0


def test_rollover_ratio_is_zero_without_overlap():
    events = [
        _make_event(0, "down", 1),
        _make_event(50_000_000, "up", 1),
        _make_event(200_000_000, "down", 2),
        _make_event(250_000_000, "up", 2),
        _make_event(400_000_000, "down", 3),
        _make_event(450_000_000, "up", 3),
    ]
    [window] = iter_feature_windows(events, DEVICE_ID, window_size=3, window_step=1)

    assert window.features["rollover_ratio"] == 0.0


# --- windowing edge cases ----------------------------------------------------


def test_no_window_when_fewer_events_than_window_size():
    events = human_like_events(DEVICE_ID, n_presses=DEFAULT_WINDOW_SIZE - 1)
    windows = list(iter_feature_windows(events, DEVICE_ID))

    assert windows == []


def test_sliding_window_emits_at_every_step_once_full():
    events = human_like_events(DEVICE_ID, n_presses=DEFAULT_WINDOW_SIZE + DEFAULT_WINDOW_STEP)
    windows = list(iter_feature_windows(events, DEVICE_ID))

    assert len(windows) == 2
    assert windows[0].n_events == DEFAULT_WINDOW_SIZE
    assert windows[1].n_events == DEFAULT_WINDOW_SIZE


def test_sliding_window_does_not_emit_before_the_next_step():
    events = human_like_events(DEVICE_ID, n_presses=DEFAULT_WINDOW_SIZE + DEFAULT_WINDOW_STEP - 1)
    windows = list(iter_feature_windows(events, DEVICE_ID))

    assert len(windows) == 1


def test_long_pause_splits_the_window_and_drops_a_short_run():
    first_run = human_like_events(DEVICE_ID, n_presses=DEFAULT_WINDOW_SIZE - 1)
    pause_ns = int((DEFAULT_PAUSE_SPLIT_SECONDS + 1.0) * NANOS_PER_SECOND)
    last_down_ns = first_run[-2].timestamp_ns  # last press's down event
    second_run = human_like_events(
        DEVICE_ID,
        n_presses=DEFAULT_WINDOW_SIZE - 1,
        start_timestamp_ns=last_down_ns + pause_ns,
    )
    # Re-number press ids in the second run so they do not collide.
    second_run = [
        event.model_copy(update={"press_id": event.press_id + 10_000}) for event in second_run
    ]

    windows = list(iter_feature_windows(first_run + second_run, DEVICE_ID))

    # Neither run alone reaches window_size, and the pause must prevent
    # them from being combined into one window.
    assert windows == []


def test_long_pause_starts_a_fresh_run_that_can_still_fill_a_window():
    first_run = human_like_events(DEVICE_ID, n_presses=5)
    pause_ns = int((DEFAULT_PAUSE_SPLIT_SECONDS + 1.0) * NANOS_PER_SECOND)
    last_down_ns = first_run[-2].timestamp_ns
    second_run = human_like_events(
        DEVICE_ID,
        n_presses=DEFAULT_WINDOW_SIZE,
        start_timestamp_ns=last_down_ns + pause_ns,
    )
    second_run = [
        event.model_copy(update={"press_id": event.press_id + 10_000}) for event in second_run
    ]

    windows = list(iter_feature_windows(first_run + second_run, DEVICE_ID))

    assert len(windows) == 1
    # The window must be built only from the second run, starting after
    # the pause, not blended with the first run.
    assert windows[0].window_start_ns == second_run[0].timestamp_ns


# --- repeat events are ignored ----------------------------------------------


def test_repeat_down_events_do_not_count_or_affect_timing():
    # Three real presses, evenly spaced 100ms apart, with a storm of
    # auto-repeat downs for press 2 injected in between.
    events = [
        _make_event(0, "down", 1),
        _make_event(10_000_000, "up", 1),
        _make_event(100_000_000, "down", 2),
        _make_event(105_000_000, "down", 2, is_repeat=True),
        _make_event(110_000_000, "down", 2, is_repeat=True),
        _make_event(115_000_000, "down", 2, is_repeat=True),
        _make_event(150_000_000, "up", 2),
        _make_event(200_000_000, "down", 3),
        _make_event(210_000_000, "up", 3),
    ]

    [window] = iter_feature_windows(events, DEVICE_ID, window_size=3, window_step=1)

    assert window.n_events == 3
    assert window.features["flight_mean_ms"] == pytest.approx(100.0)
    assert window.features["flight_std_ms"] == pytest.approx(0.0, abs=1e-6)


def test_other_devices_events_are_ignored():
    other_device_events = [
        KeyEvent(
            device_id="some-other-device",
            timestamp_ns=i,
            event_type="down",
            press_id=i,
            is_repeat=False,
        )
        for i in range(100)
    ]
    windows = list(iter_feature_windows(other_device_events, DEVICE_ID))

    assert windows == []
