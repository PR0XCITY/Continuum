"""Capture backend factory.

Responsibility: given the running platform, construct and return the
correct capture backend behind the capture.base.CaptureSource interface.
"""

from __future__ import annotations

import sys

from continuum.capture.base import CaptureSource


def create_capture_source(**kwargs: object) -> CaptureSource:
    """Return the capture backend for the current platform.

    Only Windows is supported today, via the Raw Input API. A Linux
    port, if ever added, would live behind this same factory function
    and the same CaptureSource interface, so nothing above capture
    would need to change.
    """
    if sys.platform == "win32":
        from continuum.capture.windows_rawinput import WindowsRawInputCapture

        return WindowsRawInputCapture(**kwargs)

    raise RuntimeError(
        f"No capture backend is implemented for platform {sys.platform!r}. "
        "Continuum's HID Firewall currently supports Windows only."
    )
