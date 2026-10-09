"""Keystroke timing capture, isolated from analysis.

Responsibility: read raw HID input events from Windows and turn them into
minimal, non-sensitive KeyEvent records (timestamp, event type, per-session
counter, device identifier) on a queue for the detection pipeline to
consume.

Capture is deliberately dumb. The capture thread does the minimum work
needed to timestamp and queue an event; it never computes features, never
scores anything, and never records which key was pressed. That separation
is what lets this package be audited in isolation as "cannot be a
keylogger".

Modules:
    base.py                Abstract capture device interface.
    windows_rawinput.py    Windows Raw Input API (ctypes) implementation.
                           Uses Raw Input, not a keyboard hook, because
                           hooks cannot identify which physical device an
                           event came from.
    factory.py             Picks and constructs the right capture backend
                           for the current platform and config.
"""

from continuum.capture.base import CaptureSource
from continuum.capture.factory import create_capture_source

__all__ = ["CaptureSource", "create_capture_source"]
