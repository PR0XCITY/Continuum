"""Remote-access typing detection: keystrokes with no physical keyboard.

Responsibility: decide when software-generated typing has become a run
of typing rather than a stray synthetic key. Raw Input reports a
keystroke created by software (SendInput, which remote-access tools and
macros use) with no device handle; the capture layer tags those with
SOFTWARE_INPUT_DEVICE_ID. This module only counts their key presses in
a sliding time window. Like the rest of detection it sees timing and
down/up only, never which keys were pressed.

Whether a remote-access tool is running, and what to do about it, is
decided by the runtime and continuum.response.remote_session; this
module is pure and needs no Windows.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from continuum.common.schemas import KeyEvent

# After a trigger, further software typing is not reported again for
# this long, so one remote session produces one incident, not dozens.
DEFAULT_COOLDOWN_SECONDS = 30.0


@dataclass
class RemoteInputTrigger:
    """A run of software-generated typing that crossed the threshold."""

    presses: int
    first_press_s: float
    triggered_s: float

    @property
    def time_to_detect_ms(self) -> int:
        return max(int((self.triggered_s - self.first_press_s) * 1000), 0)


@dataclass
class RemoteInputMonitor:
    """Counts software-generated key presses in a sliding window.

    observe() takes monotonic seconds rather than the event's own
    timestamp so tests can drive it with a fake clock; the runtime passes
    time.monotonic().
    """

    min_presses: int
    window_seconds: float
    cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS
    _presses: deque[float] = field(default_factory=deque)
    _last_trigger_s: float | None = None

    def observe(self, event: KeyEvent, now_s: float) -> RemoteInputTrigger | None:
        """Record one software-generated event; return a trigger if typing crossed the line."""
        if event.event_type != "down" or event.is_repeat:
            return None
        self._presses.append(now_s)
        while self._presses and now_s - self._presses[0] > self.window_seconds:
            self._presses.popleft()

        if len(self._presses) < self.min_presses:
            return None
        if self.in_cooldown(now_s):
            return None

        trigger = RemoteInputTrigger(
            presses=len(self._presses), first_press_s=self._presses[0], triggered_s=now_s
        )
        self._last_trigger_s = now_s
        self._presses.clear()
        return trigger

    def in_cooldown(self, now_s: float) -> bool:
        return (
            self._last_trigger_s is not None
            and now_s - self._last_trigger_s < self.cooldown_seconds
        )

    def reset(self) -> None:
        self._presses.clear()
        self._last_trigger_s = None
