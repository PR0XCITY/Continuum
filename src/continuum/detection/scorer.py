"""Detection orchestration: features, model and decision.

Responsibility: take FeatureWindow objects (one at a time, or a whole
event stream) and turn each into a DetectionResult, applying:

    - the model's calibrated threshold, raised in strictness for a
      device that was never part of the baseline, for its first
      NEW_DEVICE_GRACE_PERIOD_SECONDS;
    - debounce: a single flagged window is only ever "suspicious"; the
      verdict escalates to "blocked" only once DEBOUNCE_SUSPICIOUS_COUNT
      windows for that device were flagged within the trailing
      DEBOUNCE_SECONDS, so one odd window from a fast typist cannot by
      itself trigger a block;
    - per-device state, keyed by device_id, so a newly attached device
      is scored from its very first window, with its own debounce
      history and its own "how long have I known about this device"
      clock.

This is the only module allowed to turn an anomaly score into a verdict.
It never touches scikit-learn directly (that is model.py's job) and
never touches raw key content (there is none this far from capture).
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field

from continuum.common.schemas import DetectionResult, FeatureWindow, KeyEvent, Verdict
from continuum.detection.features import NANOS_PER_SECOND, iter_feature_windows
from continuum.detection.model import CadenceModel

DEFAULT_DEBOUNCE_SUSPICIOUS_COUNT = 2
DEFAULT_DEBOUNCE_SECONDS = 3.0
DEFAULT_NEW_DEVICE_GRACE_PERIOD_SECONDS = 60.0
DEFAULT_NEW_DEVICE_THRESHOLD_MULTIPLIER = 0.5

# Sensitivity 1 (fewest alerts) to 10 (most alerts). The default, 5, is
# exactly the model's calibrated threshold; each step away shifts the
# threshold by SENSITIVITY_STEP in anomaly-score units. The step is sized
# for isolation_forest scores, which sit roughly in [-0.3, 0.3].
MIN_SENSITIVITY = 1
MAX_SENSITIVITY = 10
DEFAULT_SENSITIVITY = 5
SENSITIVITY_STEP = 0.01


def threshold_offset_for_sensitivity(sensitivity: int) -> float:
    """Offset added to the calibrated threshold. Higher sensitivity, lower threshold."""
    if not MIN_SENSITIVITY <= sensitivity <= MAX_SENSITIVITY:
        raise ValueError(
            f"sensitivity must be between {MIN_SENSITIVITY} and {MAX_SENSITIVITY}"
        )
    return (DEFAULT_SENSITIVITY - sensitivity) * SENSITIVITY_STEP


@dataclass
class _DeviceState:
    """Per-device debounce and "how new is this device" bookkeeping."""

    first_seen_seconds: float
    suspicious_times_seconds: deque[float] = field(default_factory=deque)


class Scorer:
    """Turns FeatureWindow objects into DetectionResult objects.

    One Scorer holds the state for every device it has seen; construct
    one per running capture session (the runtime entry point owns it),
    not one per window.
    """

    def __init__(
        self,
        model: CadenceModel,
        *,
        baseline_device_id: str | None = None,
        debounce_suspicious_count: int = DEFAULT_DEBOUNCE_SUSPICIOUS_COUNT,
        debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
        new_device_grace_period_seconds: float = DEFAULT_NEW_DEVICE_GRACE_PERIOD_SECONDS,
        new_device_threshold_multiplier: float = DEFAULT_NEW_DEVICE_THRESHOLD_MULTIPLIER,
        threshold_offset: float = 0.0,
    ) -> None:
        if debounce_suspicious_count < 1:
            raise ValueError("debounce_suspicious_count must be at least 1")
        if not (0.0 < new_device_threshold_multiplier <= 1.0):
            raise ValueError("new_device_threshold_multiplier must be in (0, 1]")

        self._model = model
        self._baseline_device_id = (
            baseline_device_id if baseline_device_id is not None else model.baseline_device_id
        )
        self._debounce_suspicious_count = debounce_suspicious_count
        self._debounce_seconds = debounce_seconds
        self._new_device_grace_period_seconds = new_device_grace_period_seconds
        self._new_device_threshold_multiplier = new_device_threshold_multiplier
        self._threshold_offset = threshold_offset
        self._device_state: dict[str, _DeviceState] = {}

    @property
    def base_threshold(self) -> float:
        """The calibrated threshold plus the configured sensitivity offset."""
        return self._model.threshold + self._threshold_offset

    def score_window(self, window: FeatureWindow) -> DetectionResult:
        """Score one window, updating that device's debounce state."""
        window_time_seconds = window.window_start_ns / NANOS_PER_SECOND
        state = self._device_state.get(window.device_id)
        if state is None:
            state = _DeviceState(first_seen_seconds=window_time_seconds)
            self._device_state[window.device_id] = state

        anomaly_score = self._model.score_one(window.features)
        effective_threshold = self._effective_threshold(
            window.device_id, state, window_time_seconds
        )
        flagged = anomaly_score > effective_threshold

        if flagged:
            state.suspicious_times_seconds.append(window_time_seconds)
        cutoff_seconds = window_time_seconds - self._debounce_seconds
        while state.suspicious_times_seconds and state.suspicious_times_seconds[0] < cutoff_seconds:
            state.suspicious_times_seconds.popleft()

        verdict: Verdict
        if flagged and len(state.suspicious_times_seconds) >= self._debounce_suspicious_count:
            verdict = "blocked"
        elif flagged:
            verdict = "suspicious"
        else:
            verdict = "normal"

        return DetectionResult(
            device_id=window.device_id,
            anomaly_score=anomaly_score,
            threshold=effective_threshold,
            verdict=verdict,
            window=window,
            model_version=self._model.version,
        )

    def score_events(
        self,
        events: Sequence[KeyEvent],
        device_id: str,
        **window_kwargs: object,
    ) -> list[DetectionResult]:
        """Window a raw event stream for one device and score every window."""
        windows = iter_feature_windows(events, device_id, **window_kwargs)
        return [self.score_window(window) for window in windows]

    def reset_device(self, device_id: str) -> None:
        """Drop all debounce state for a device, for example after it is released."""
        self._device_state.pop(device_id, None)

    def _effective_threshold(
        self, device_id: str, state: _DeviceState, window_time_seconds: float
    ) -> float:
        if device_id == self._baseline_device_id:
            return self.base_threshold

        age_seconds = window_time_seconds - state.first_seen_seconds
        if age_seconds <= self._new_device_grace_period_seconds:
            return self.base_threshold * self._new_device_threshold_multiplier

        return self.base_threshold
