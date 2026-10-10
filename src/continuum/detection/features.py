"""Feature extraction from windows of keystroke timing events.

Responsibility: convert a chronological stream of KeyEvent records for one
device into a sequence of FeatureWindow objects describing typing cadence.
Operates purely on timestamps, event types, press ids and the is_repeat
flag; never touches key identity because none is available this far from
capture, and there is no field here that could hold it.

Windowing rules:
    - Only non-repeat key-down events count as a "press" for window
      sizing; a key-up is used only to compute the dwell time of the
      press it closes, and is_repeat down events (OS auto-repeat) are
      ignored entirely, for both sizing and timing.
    - A window covers DEFAULT_WINDOW_SIZE presses and a new one is
      emitted every DEFAULT_WINDOW_STEP presses (a sliding window with
      a hop), so windows overlap.
    - A gap between two consecutive presses longer than
      DEFAULT_PAUSE_SPLIT_SECONDS ends the current run of presses; a
      window is only ever built from presses within one such run, never
      across a pause.
    - A run that never reaches DEFAULT_WINDOW_SIZE presses, whether
      because of a pause or because the input stream ends, never
      produces a window.

Feature families, all computed over one window's presses:
    flight_*       Inter-key interval statistics (down to next down).
    dwell_*        Dwell time statistics (down to its own up), over
                   presses whose up event was observed.
    rollover_ratio Fraction of presses whose down happened before the
                   previous press's up (keys briefly held together).
    burst_score    Fraction of flight intervals under 15 ms.
    interval_entropy
                   Shannon entropy, in bits, of the flight intervals
                   binned into ENTROPY_BINS buckets.
    autocorr_lag1  Lag-1 autocorrelation of the flight intervals; 1.0 by
                   convention when every interval is identical (zero
                   variance is the most regular case there is).
    regularity_ratio
                   Fraction of flight intervals within
                   REGULARITY_TOLERANCE of the window's median interval.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

import numpy as np

from continuum.common.schemas import FeatureWindow, KeyEvent

NANOS_PER_MS = 1_000_000
NANOS_PER_SECOND = 1_000_000_000

DEFAULT_WINDOW_SIZE = 30
DEFAULT_WINDOW_STEP = 10
DEFAULT_PAUSE_SPLIT_SECONDS = 2.0

BURST_THRESHOLD_MS = 15.0
REGULARITY_TOLERANCE = 0.05
ENTROPY_BINS = 10

FEATURE_NAMES: tuple[str, ...] = (
    "flight_mean_ms",
    "flight_median_ms",
    "flight_std_ms",
    "flight_min_ms",
    "flight_max_ms",
    "flight_p10_ms",
    "flight_p90_ms",
    "flight_cv",
    "dwell_mean_ms",
    "dwell_std_ms",
    "dwell_min_ms",
    "dwell_max_ms",
    "rollover_ratio",
    "burst_score",
    "interval_entropy",
    "autocorr_lag1",
    "regularity_ratio",
)


@dataclass
class _Press:
    """One key-down paired with its key-up, if seen. No key identity."""

    press_id: int
    down_ns: int
    up_ns: int | None = None


def _build_presses(events: Sequence[KeyEvent]) -> list[_Press]:
    """Turn a chronological event stream into presses, ignoring repeats."""
    presses: list[_Press] = []
    by_press_id: dict[int, _Press] = {}

    for event in events:
        if event.event_type == "down":
            if event.is_repeat:
                continue
            press = _Press(press_id=event.press_id, down_ns=event.timestamp_ns)
            presses.append(press)
            by_press_id[event.press_id] = press
        else:
            press = by_press_id.get(event.press_id)
            if press is not None and press.up_ns is None:
                press.up_ns = event.timestamp_ns

    return presses


def iter_feature_windows(
    events: Sequence[KeyEvent],
    device_id: str,
    *,
    window_size: int = DEFAULT_WINDOW_SIZE,
    window_step: int = DEFAULT_WINDOW_STEP,
    pause_split_seconds: float = DEFAULT_PAUSE_SPLIT_SECONDS,
) -> Iterator[FeatureWindow]:
    """Yield FeatureWindow objects for one device from a chronological stream.

    events may contain other devices' events too; only device_id's are
    used. Events must already be in chronological order.
    """
    if window_size < 2:
        raise ValueError("window_size must be at least 2 to compute an interval")
    if window_step < 1:
        raise ValueError("window_step must be at least 1")

    pause_split_ns = int(pause_split_seconds * NANOS_PER_SECOND)
    device_events = [event for event in events if event.device_id == device_id]
    presses = _build_presses(device_events)

    window: deque[_Press] = deque(maxlen=window_size)
    run_length = 0
    last_down_ns: int | None = None

    for press in presses:
        if last_down_ns is not None and (press.down_ns - last_down_ns) > pause_split_ns:
            window.clear()
            run_length = 0
        last_down_ns = press.down_ns

        window.append(press)
        run_length += 1

        if run_length >= window_size and (run_length - window_size) % window_step == 0:
            yield _build_feature_window(device_id, list(window))


def _coefficient_of_variation(values: np.ndarray) -> float:
    mean = float(values.mean())
    if abs(mean) <= 1e-12:
        return 0.0
    return float(values.std() / mean)


def _burst_score(values_ms: np.ndarray) -> float:
    if values_ms.size == 0:
        return 0.0
    return float(np.mean(values_ms < BURST_THRESHOLD_MS))


def _shannon_entropy(values: np.ndarray) -> float:
    if values.size == 0:
        return 0.0
    value_range = float(values.max() - values.min())
    if value_range <= 1e-9:
        return 0.0
    counts, _ = np.histogram(values, bins=ENTROPY_BINS)
    probabilities = counts[counts > 0] / counts.sum()
    return float(-np.sum(probabilities * np.log2(probabilities)))


def _autocorrelation_lag1(values: np.ndarray) -> float:
    if values.size < 2:
        return 0.0
    deviations = values - values.mean()
    denominator = float(np.sum(deviations**2))
    if denominator <= 1e-12:
        # Zero variance: every interval is identical, the most regular a
        # series can be, so autocorrelation is defined as 1.0 rather than
        # the undefined 0/0.
        return 1.0
    numerator = float(np.sum(deviations[:-1] * deviations[1:]))
    return numerator / denominator


def _regularity_ratio(values: np.ndarray) -> float:
    if values.size == 0:
        return 0.0
    median = float(np.median(values))
    if abs(median) <= 1e-12:
        return 1.0
    close = np.abs(values - median) <= (REGULARITY_TOLERANCE * median)
    return float(np.mean(close))


def _build_feature_window(device_id: str, presses: list[_Press]) -> FeatureWindow:
    flight_ms = np.array(
        [
            (presses[i].down_ns - presses[i - 1].down_ns) / NANOS_PER_MS
            for i in range(1, len(presses))
        ],
        dtype=float,
    )
    dwell_ms = np.array(
        [(p.up_ns - p.down_ns) / NANOS_PER_MS for p in presses if p.up_ns is not None],
        dtype=float,
    )

    rollover_hits = 0
    rollover_total = 0
    for i in range(1, len(presses)):
        previous_up_ns = presses[i - 1].up_ns
        if previous_up_ns is None:
            continue
        rollover_total += 1
        if presses[i].down_ns < previous_up_ns:
            rollover_hits += 1
    rollover_ratio = (rollover_hits / rollover_total) if rollover_total else 0.0

    features = {
        "flight_mean_ms": float(flight_ms.mean()),
        "flight_median_ms": float(np.median(flight_ms)),
        "flight_std_ms": float(flight_ms.std()),
        "flight_min_ms": float(flight_ms.min()),
        "flight_max_ms": float(flight_ms.max()),
        "flight_p10_ms": float(np.percentile(flight_ms, 10)),
        "flight_p90_ms": float(np.percentile(flight_ms, 90)),
        "flight_cv": _coefficient_of_variation(flight_ms),
        "dwell_mean_ms": float(dwell_ms.mean()) if dwell_ms.size else 0.0,
        "dwell_std_ms": float(dwell_ms.std()) if dwell_ms.size else 0.0,
        "dwell_min_ms": float(dwell_ms.min()) if dwell_ms.size else 0.0,
        "dwell_max_ms": float(dwell_ms.max()) if dwell_ms.size else 0.0,
        "rollover_ratio": float(rollover_ratio),
        "burst_score": _burst_score(flight_ms),
        "interval_entropy": _shannon_entropy(flight_ms),
        "autocorr_lag1": _autocorrelation_lag1(flight_ms),
        "regularity_ratio": _regularity_ratio(flight_ms),
    }

    return FeatureWindow(
        device_id=device_id,
        window_start_ns=presses[0].down_ns,
        n_events=len(presses),
        features=features,
    )
