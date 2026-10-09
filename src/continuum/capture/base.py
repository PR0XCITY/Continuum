"""Abstract capture device interface.

Responsibility: define the minimal contract every capture backend must
implement (start, stop, and pushing KeyEvent records onto a thread-safe
queue), plus device enumeration, so the rest of the system never depends
on Windows-specific capture details.

Any implementation of this interface must preserve the hard rule that no
key identity, character or scan-code-to-character mapping ever leaves the
capture layer. Only timestamp, event type, per-session press counter and
device identifier may cross this boundary; see continuum.common.schemas.
KeyEvent.
"""

from __future__ import annotations

import queue
from abc import ABC, abstractmethod

from continuum.common.schemas import DeviceInfo, KeyEvent

DEFAULT_QUEUE_MAXSIZE = 4096
DEFAULT_PUT_TIMEOUT_SECONDS = 0.1


class CaptureSource(ABC):
    """Base class for every Continuum capture backend.

    Subclasses do the minimum work needed to turn raw input into
    KeyEvent records and push them onto self.events. They must not
    compute features, score anything, or make a blocking decision; that
    is detection's job, not capture's.
    """

    def __init__(
        self,
        queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE,
        put_timeout_seconds: float = DEFAULT_PUT_TIMEOUT_SECONDS,
    ) -> None:
        self.events: queue.Queue[KeyEvent] = queue.Queue(maxsize=queue_maxsize)
        self._put_timeout_seconds = put_timeout_seconds
        self._dropped_event_count = 0

    @abstractmethod
    def start(self) -> None:
        """Begin capturing in the background. Must not block the caller."""

    @abstractmethod
    def stop(self) -> None:
        """Stop capturing and release any OS resources. Safe to call twice."""

    @abstractmethod
    def list_devices(self) -> list[DeviceInfo]:
        """Return every keyboard-class device seen so far, most recent info."""

    @property
    def dropped_event_count(self) -> int:
        """How many events were discarded because the queue stayed full.

        Capture never blocks past put_timeout_seconds waiting for a
        consumer; if the queue is still full after that, the event is
        dropped and this counter increments instead of the capture
        thread stalling.
        """
        return self._dropped_event_count

    def _push_event(self, event: KeyEvent) -> None:
        """Push one event onto the queue without blocking indefinitely."""
        try:
            self.events.put(event, timeout=self._put_timeout_seconds)
        except queue.Full:
            self._dropped_event_count += 1
