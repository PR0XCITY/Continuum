"""Named, labelled synthetic cadence profiles for evaluating detection.

Responsibility: generate reproducible KeyEvent streams for five labelled
scenarios, built on the generic primitives in tools/simulators.py:

    human               Lognormal flight intervals at a random typing
                         speed between 40 and 120 wpm, realistic dwell
                         variance, and occasional short hesitations.
    burst_injection      Near-constant 1 to 10 ms intervals: a HID
                         injection tool playing its script back as fast
                         as the target will accept it.
    slowed_injection     Constant intervals in the 80 to 200 ms range,
                         deliberately tuned to look like a plausible
                         human typing speed. The absolute speed is
                         human; the complete lack of natural variance
                         is not.
    randomized_injection Intervals drawn from a uniform or Gaussian
                         distribution (chosen per stream) around a
                         human-plausible mean and spread, with random
                         jitter: an evasion attempt against variance
                         based detection.
    hybrid               A normal human typing session with a short
                         burst_injection-speed segment spliced into the
                         middle, then a return to human typing.

Every generator takes a seed and returns the same stream for the same
seed; nothing here ever has access to which key was pressed, because
KeyEvent has nowhere to put that.
"""

from __future__ import annotations

from typing import Literal

import numpy as np

from continuum.common.schemas import KeyEvent
from tools.simulators import (
    DEFAULT_HUMAN_DWELL_MEAN_MS,
    DEFAULT_HUMAN_DWELL_SIGMA_MS,
    DEFAULT_HUMAN_MIN_DWELL_MS,
    _events_from_intervals,
    injection_like_events,
)

ATTACK_TYPES: tuple[str, ...] = (
    "human",
    "burst_injection",
    "slowed_injection",
    "randomized_injection",
    "hybrid",
)

DEFAULT_WPM_RANGE = (40.0, 120.0)
AVERAGE_CHARS_PER_WORD = 5.0
HUMAN_INTERVAL_SIGMA = 0.35

DEFAULT_PAUSE_PROBABILITY = 0.05
DEFAULT_PAUSE_MULTIPLIER_RANGE = (3.0, 10.0)

DEFAULT_BURST_INTERVAL_RANGE_MS = (1.0, 10.0)
DEFAULT_BURST_DWELL_MS = 2.0

DEFAULT_SLOWED_INTERVAL_RANGE_MS = (80.0, 200.0)
DEFAULT_SLOWED_DWELL_MS = 60.0

DEFAULT_RANDOMIZED_MEAN_RANGE_MS = (80.0, 200.0)
DEFAULT_RANDOMIZED_STD_RANGE_MS = (20.0, 60.0)
DEFAULT_RANDOMIZED_MIN_INTERVAL_MS = 1.0

DEFAULT_HYBRID_N_HUMAN_BEFORE = 60
DEFAULT_HYBRID_N_BURST = 15
DEFAULT_HYBRID_N_HUMAN_AFTER = 60

_SEGMENT_GAP_NS = 50_000_000


def wpm_to_median_interval_ms(wpm: float) -> float:
    """Rough conversion from typing speed to a median inter-key interval.

    Uses the standard convention of one "word" being 5 characters.
    """
    return 60_000.0 / (wpm * AVERAGE_CHARS_PER_WORD)


def _apply_occasional_pauses(
    intervals_ms: np.ndarray,
    rng: np.random.Generator,
    *,
    pause_probability: float,
    pause_multiplier_range: tuple[float, float],
) -> np.ndarray:
    if intervals_ms.size == 0:
        return intervals_ms
    pause_mask = rng.random(intervals_ms.size) < pause_probability
    multipliers = rng.uniform(
        pause_multiplier_range[0], pause_multiplier_range[1], intervals_ms.size
    )
    return np.where(pause_mask, intervals_ms * multipliers, intervals_ms)


def generate_human(
    device_id: str,
    n_presses: int,
    *,
    seed: int,
    wpm_range: tuple[float, float] = DEFAULT_WPM_RANGE,
    pause_probability: float = DEFAULT_PAUSE_PROBABILITY,
    pause_multiplier_range: tuple[float, float] = DEFAULT_PAUSE_MULTIPLIER_RANGE,
    start_timestamp_ns: int = 0,
) -> list[KeyEvent]:
    """Human-like typing at a random speed between wpm_range, with pauses."""
    rng = np.random.default_rng(seed)
    wpm = rng.uniform(*wpm_range)
    median_interval_ms = wpm_to_median_interval_ms(wpm)

    n_intervals = max(n_presses - 1, 0)
    intervals_ms = rng.lognormal(
        mean=np.log(median_interval_ms), sigma=HUMAN_INTERVAL_SIGMA, size=n_intervals
    )
    intervals_ms = _apply_occasional_pauses(
        intervals_ms,
        rng,
        pause_probability=pause_probability,
        pause_multiplier_range=pause_multiplier_range,
    )
    dwell_ms = np.clip(
        rng.normal(DEFAULT_HUMAN_DWELL_MEAN_MS, DEFAULT_HUMAN_DWELL_SIGMA_MS, size=n_presses),
        DEFAULT_HUMAN_MIN_DWELL_MS,
        None,
    )
    return _events_from_intervals(device_id, intervals_ms, dwell_ms, start_timestamp_ns)


def generate_burst_injection(
    device_id: str,
    n_presses: int,
    *,
    seed: int,
    interval_range_ms: tuple[float, float] = DEFAULT_BURST_INTERVAL_RANGE_MS,
    dwell_ms: float = DEFAULT_BURST_DWELL_MS,
    start_timestamp_ns: int = 0,
) -> list[KeyEvent]:
    """Near-constant 1 to 10 ms intervals, with a touch of USB-level jitter."""
    rng = np.random.default_rng(seed)
    base_interval_ms = rng.uniform(*interval_range_ms)
    jitter_ms = rng.normal(0.0, base_interval_ms * 0.05, size=max(n_presses - 1, 0))
    intervals_ms = np.clip(base_interval_ms + jitter_ms, 0.1, None)
    dwell_values_ms = np.full(n_presses, dwell_ms, dtype=float)
    return _events_from_intervals(device_id, intervals_ms, dwell_values_ms, start_timestamp_ns)


def generate_slowed_injection(
    device_id: str,
    n_presses: int,
    *,
    seed: int,
    interval_range_ms: tuple[float, float] = DEFAULT_SLOWED_INTERVAL_RANGE_MS,
    dwell_ms: float = DEFAULT_SLOWED_DWELL_MS,
    start_timestamp_ns: int = 0,
) -> list[KeyEvent]:
    """Constant intervals at a human-plausible speed: no natural variance."""
    rng = np.random.default_rng(seed)
    interval_ms = rng.uniform(*interval_range_ms)
    return injection_like_events(
        device_id,
        n_presses,
        interval_ms=interval_ms,
        dwell_ms=dwell_ms,
        start_timestamp_ns=start_timestamp_ns,
    )


def generate_randomized_injection(
    device_id: str,
    n_presses: int,
    *,
    seed: int,
    distribution: Literal["uniform", "gaussian"] | None = None,
    mean_range_ms: tuple[float, float] = DEFAULT_RANDOMIZED_MEAN_RANGE_MS,
    std_range_ms: tuple[float, float] = DEFAULT_RANDOMIZED_STD_RANGE_MS,
    start_timestamp_ns: int = 0,
) -> list[KeyEvent]:
    """Random-jitter intervals around a human-plausible mean: an evasion case.

    Unlike slowed_injection, every interval is different, drawn from a
    uniform or Gaussian distribution rather than copied from real human
    timing (which is lognormal and right-skewed, not symmetric). That
    shape difference is subtle and a timing-only model may well miss it;
    see docs/eval_results.md.
    """
    rng = np.random.default_rng(seed)
    chosen_distribution = (
        distribution if distribution is not None else rng.choice(["uniform", "gaussian"])
    )
    mean_ms = rng.uniform(*mean_range_ms)
    std_ms = rng.uniform(*std_range_ms)

    n_intervals = max(n_presses - 1, 0)
    if chosen_distribution == "uniform":
        half_width = std_ms * np.sqrt(3.0)  # matches the Gaussian's std for a fair comparison
        intervals_ms = rng.uniform(mean_ms - half_width, mean_ms + half_width, size=n_intervals)
    else:
        intervals_ms = rng.normal(mean_ms, std_ms, size=n_intervals)
    intervals_ms = np.clip(intervals_ms, DEFAULT_RANDOMIZED_MIN_INTERVAL_MS, None)

    dwell_ms = np.clip(
        rng.normal(DEFAULT_HUMAN_DWELL_MEAN_MS, DEFAULT_HUMAN_DWELL_SIGMA_MS, size=n_presses),
        DEFAULT_HUMAN_MIN_DWELL_MS,
        None,
    )
    return _events_from_intervals(device_id, intervals_ms, dwell_ms, start_timestamp_ns)


def generate_hybrid(
    device_id: str,
    *,
    seed: int,
    n_human_before: int = DEFAULT_HYBRID_N_HUMAN_BEFORE,
    n_burst: int = DEFAULT_HYBRID_N_BURST,
    n_human_after: int = DEFAULT_HYBRID_N_HUMAN_AFTER,
    wpm_range: tuple[float, float] = DEFAULT_WPM_RANGE,
    burst_interval_range_ms: tuple[float, float] = DEFAULT_BURST_INTERVAL_RANGE_MS,
) -> list[KeyEvent]:
    """Normal human typing, a brief injected burst, then human typing again.

    One continuous device_id, so this looks like a single real session
    with a short-lived attack in the middle, the way an actual Rubber
    Ducky payload (a few seconds) would look inside a longer human
    session. Each segment numbers its own presses from 0; that is safe
    to concatenate because every press in a synthetic segment opens and
    closes (down then up) before the next one starts, so reused press
    ids across segment boundaries never pair with the wrong event.
    """
    before = generate_human(device_id, n_human_before, seed=seed, wpm_range=wpm_range)
    before_end_ns = before[-1].timestamp_ns if before else 0

    burst = generate_burst_injection(
        device_id,
        n_burst,
        seed=seed + 1,
        interval_range_ms=burst_interval_range_ms,
        start_timestamp_ns=before_end_ns + _SEGMENT_GAP_NS,
    )
    burst_end_ns = burst[-1].timestamp_ns if burst else before_end_ns

    after = generate_human(
        device_id,
        n_human_after,
        seed=seed + 2,
        wpm_range=wpm_range,
        start_timestamp_ns=burst_end_ns + _SEGMENT_GAP_NS,
    )

    return before + burst + after


def generate(
    attack_type: str,
    device_id: str,
    n_presses: int,
    *,
    seed: int,
    **kwargs: object,
) -> list[KeyEvent]:
    """Dispatch to the named generator. attack_type must be in ATTACK_TYPES."""
    if attack_type == "human":
        return generate_human(device_id, n_presses, seed=seed, **kwargs)
    if attack_type == "burst_injection":
        return generate_burst_injection(device_id, n_presses, seed=seed, **kwargs)
    if attack_type == "slowed_injection":
        return generate_slowed_injection(device_id, n_presses, seed=seed, **kwargs)
    if attack_type == "randomized_injection":
        return generate_randomized_injection(device_id, n_presses, seed=seed, **kwargs)
    if attack_type == "hybrid":
        return generate_hybrid(device_id, seed=seed, **kwargs)
    raise ValueError(f"unknown attack_type: {attack_type!r}, expected one of {ATTACK_TYPES}")
