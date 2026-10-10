"""Synthetic KeyEvent stream generator.

Responsibility: produce synthetic KeyEvent records, at configurable
cadence profiles (human typing versus machine-speed injection), so
detection can be developed and tested without real hardware or an
elevated session. Like everything upstream of it, this only ever deals
in timestamps, down/up pairs and press ids; there is no key identity to
generate because the real KeyEvent schema has nowhere to put one.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np

from continuum.common.schemas import KeyEvent

NANOS_PER_MS = 1_000_000

DEFAULT_HUMAN_MEDIAN_INTERVAL_MS = 150.0
DEFAULT_HUMAN_INTERVAL_SIGMA = 0.35
DEFAULT_HUMAN_DWELL_MEAN_MS = 90.0
DEFAULT_HUMAN_DWELL_SIGMA_MS = 20.0
DEFAULT_HUMAN_MIN_DWELL_MS = 10.0

DEFAULT_INJECTION_INTERVAL_MS = 5.0
DEFAULT_INJECTION_DWELL_MS = 2.0


def _events_from_intervals(
    device_id: str,
    intervals_ms: Sequence[float],
    dwell_ms: Sequence[float],
    start_timestamp_ns: int,
) -> list[KeyEvent]:
    n_presses = len(dwell_ms)
    events: list[KeyEvent] = []
    timestamp_ns = start_timestamp_ns

    for press_id in range(n_presses):
        down_ns = timestamp_ns
        up_ns = down_ns + int(dwell_ms[press_id] * NANOS_PER_MS)
        events.append(
            KeyEvent(
                device_id=device_id,
                timestamp_ns=down_ns,
                event_type="down",
                press_id=press_id,
                is_repeat=False,
            )
        )
        events.append(
            KeyEvent(
                device_id=device_id,
                timestamp_ns=up_ns,
                event_type="up",
                press_id=press_id,
                is_repeat=False,
            )
        )
        if press_id < len(intervals_ms):
            timestamp_ns = down_ns + int(intervals_ms[press_id] * NANOS_PER_MS)

    return events


def human_like_events(
    device_id: str,
    n_presses: int,
    *,
    median_interval_ms: float = DEFAULT_HUMAN_MEDIAN_INTERVAL_MS,
    sigma: float = DEFAULT_HUMAN_INTERVAL_SIGMA,
    dwell_mean_ms: float = DEFAULT_HUMAN_DWELL_MEAN_MS,
    dwell_sigma_ms: float = DEFAULT_HUMAN_DWELL_SIGMA_MS,
    start_timestamp_ns: int = 0,
    rng: np.random.Generator | None = None,
) -> list[KeyEvent]:
    """Synthetic human-like typing: lognormal flight intervals.

    Intervals are drawn from a lognormal distribution with the given
    median, which is what real inter-key timing tends to look like:
    mostly clustered around a typical speed with an occasional long
    pause, never negative, and right-skewed.
    """
    rng = rng if rng is not None else np.random.default_rng()
    n_intervals = max(n_presses - 1, 0)
    intervals_ms = rng.lognormal(mean=np.log(median_interval_ms), sigma=sigma, size=n_intervals)
    dwell_ms = np.clip(
        rng.normal(dwell_mean_ms, dwell_sigma_ms, size=n_presses),
        DEFAULT_HUMAN_MIN_DWELL_MS,
        None,
    )
    return _events_from_intervals(device_id, intervals_ms, dwell_ms, start_timestamp_ns)


def injection_like_events(
    device_id: str,
    n_presses: int,
    *,
    interval_ms: float = DEFAULT_INJECTION_INTERVAL_MS,
    dwell_ms: float = DEFAULT_INJECTION_DWELL_MS,
    start_timestamp_ns: int = 0,
) -> list[KeyEvent]:
    """Synthetic HID-injection typing: constant, machine-speed intervals.

    Keystroke-injection tools play back a fixed script at a fixed rate;
    there is no human variance, so every interval and every dwell time
    here is identical.
    """
    n_intervals = max(n_presses - 1, 0)
    intervals_ms = np.full(n_intervals, interval_ms, dtype=float)
    dwell_values_ms = np.full(n_presses, dwell_ms, dtype=float)
    return _events_from_intervals(device_id, intervals_ms, dwell_values_ms, start_timestamp_ns)
