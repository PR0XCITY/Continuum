"""Tests for tools/simulate_attacks.py: reproducibility and basic shape."""

from __future__ import annotations

import numpy as np
import pytest
from tools.simulate_attacks import (
    ATTACK_TYPES,
    generate,
    generate_burst_injection,
    generate_human,
    generate_hybrid,
    generate_randomized_injection,
    generate_slowed_injection,
)

from continuum.detection.features import iter_feature_windows

DEVICE_ID = "device-under-test"

_FIXED_LENGTH_GENERATORS = [
    generate_human,
    generate_burst_injection,
    generate_slowed_injection,
    generate_randomized_injection,
]


@pytest.mark.parametrize("generator", _FIXED_LENGTH_GENERATORS)
def test_same_seed_is_reproducible(generator):
    first = generator(DEVICE_ID, 50, seed=7)
    second = generator(DEVICE_ID, 50, seed=7)

    assert [e.model_dump() for e in first] == [e.model_dump() for e in second]


@pytest.mark.parametrize("generator", _FIXED_LENGTH_GENERATORS)
def test_different_seeds_differ(generator):
    first = generator(DEVICE_ID, 50, seed=7)
    second = generator(DEVICE_ID, 50, seed=8)

    assert [e.model_dump() for e in first] != [e.model_dump() for e in second]


@pytest.mark.parametrize("generator", _FIXED_LENGTH_GENERATORS)
def test_produces_the_requested_number_of_presses(generator):
    events = generator(DEVICE_ID, 40, seed=1)
    down_events = [e for e in events if e.event_type == "down"]
    up_events = [e for e in events if e.event_type == "up"]

    assert len(down_events) == 40
    assert len(up_events) == 40


def test_burst_injection_intervals_are_in_range():
    events = generate_burst_injection(DEVICE_ID, 100, seed=3)
    [window] = iter_feature_windows(events, DEVICE_ID, window_size=100, window_step=1)

    assert window.features["flight_max_ms"] < 15.0
    assert window.features["flight_cv"] < 0.5


def test_slowed_injection_is_constant_but_human_speed():
    events = generate_slowed_injection(DEVICE_ID, 100, seed=3)
    [window] = iter_feature_windows(events, DEVICE_ID, window_size=100, window_step=1)

    assert 80.0 <= window.features["flight_mean_ms"] <= 200.0
    assert window.features["flight_cv"] == pytest.approx(0.0, abs=1e-6)


def test_randomized_injection_has_variance_unlike_slowed_injection():
    events = generate_randomized_injection(DEVICE_ID, 100, seed=3)
    [window] = iter_feature_windows(events, DEVICE_ID, window_size=100, window_step=1)

    assert window.features["flight_cv"] > 0.01


def test_hybrid_contains_a_fast_segment_between_two_human_segments():
    events = generate_hybrid(DEVICE_ID, seed=5, n_human_before=60, n_burst=40, n_human_after=60)
    down_timestamps = sorted(e.timestamp_ns for e in events if e.event_type == "down")

    assert len(down_timestamps) == 160
    before_intervals = np.diff(down_timestamps[:60]) / 1_000_000
    burst_intervals = np.diff(down_timestamps[60:100]) / 1_000_000

    assert burst_intervals.mean() < 15.0
    assert before_intervals.mean() > burst_intervals.mean() * 3


def test_generate_dispatches_by_attack_type():
    for attack_type in ATTACK_TYPES:
        events = generate(attack_type, DEVICE_ID, 10, seed=1)
        assert len(events) > 0


def test_generate_rejects_unknown_attack_type():
    with pytest.raises(ValueError):
        generate("not_a_real_type", DEVICE_ID, 10, seed=1)
