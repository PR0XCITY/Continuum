"""Tests for continuum.capture.base.

Covers the one behaviour every capture backend inherits for free: the
event queue never blocks past its configured timeout, dropping events
instead of stalling the capture thread.
"""

from __future__ import annotations

import time

from continuum.capture.base import CaptureSource
from continuum.common.schemas import DeviceInfo, KeyEvent


class _FakeCaptureSource(CaptureSource):
    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def list_devices(self) -> list[DeviceInfo]:
        return []


def _make_event(press_id: int) -> KeyEvent:
    return KeyEvent(
        device_id="device-1",
        timestamp_ns=press_id,
        event_type="down",
        press_id=press_id,
        is_repeat=False,
    )


def test_push_event_delivers_to_the_queue():
    capture = _FakeCaptureSource()
    capture._push_event(_make_event(1))

    event = capture.events.get_nowait()
    assert event.press_id == 1
    assert capture.dropped_event_count == 0


def test_push_event_drops_without_blocking_long_when_queue_is_full():
    capture = _FakeCaptureSource(queue_maxsize=1, put_timeout_seconds=0.05)
    capture._push_event(_make_event(1))

    start = time.monotonic()
    capture._push_event(_make_event(2))
    elapsed = time.monotonic() - start

    assert elapsed < 1.0
    assert capture.dropped_event_count == 1
    assert capture.events.qsize() == 1
    assert capture.events.get_nowait().press_id == 1
