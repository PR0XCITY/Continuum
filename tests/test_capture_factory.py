"""Tests for continuum.capture.factory."""

from __future__ import annotations

import sys

import pytest

from continuum.capture import factory as factory_module


def test_create_capture_source_returns_windows_backend_on_win32(monkeypatch):
    monkeypatch.setattr(factory_module.sys, "platform", "win32")

    capture = factory_module.create_capture_source()

    from continuum.capture.windows_rawinput import WindowsRawInputCapture

    assert isinstance(capture, WindowsRawInputCapture)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_create_capture_source_raises_a_clear_error_elsewhere(monkeypatch, platform):
    monkeypatch.setattr(factory_module.sys, "platform", platform)

    with pytest.raises(RuntimeError, match="Windows"):
        factory_module.create_capture_source()


def test_real_platform_is_windows_for_this_suite():
    # Sanity check: this project only ships a Windows backend, and this
    # test suite runs on the Windows box it targets.
    assert sys.platform == "win32"
