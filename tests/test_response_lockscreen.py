"""Tests for continuum.response.lockscreen. No real Win32 calls."""

from __future__ import annotations

from unittest.mock import MagicMock

from continuum.response import lockscreen


def test_lock_workstation_calls_user32_and_returns_true_on_success(monkeypatch):
    fake_user32 = MagicMock()
    fake_user32.LockWorkStation.return_value = 1
    monkeypatch.setattr(lockscreen, "_user32", fake_user32)
    monkeypatch.setattr(lockscreen, "IS_WINDOWS", True)

    assert lockscreen.lock_workstation() is True
    fake_user32.LockWorkStation.assert_called_once()


def test_lock_workstation_returns_false_when_user32_reports_failure(monkeypatch):
    fake_user32 = MagicMock()
    fake_user32.LockWorkStation.return_value = 0
    monkeypatch.setattr(lockscreen, "_user32", fake_user32)
    monkeypatch.setattr(lockscreen, "IS_WINDOWS", True)

    assert lockscreen.lock_workstation() is False


def test_lock_workstation_never_raises_on_oserror(monkeypatch):
    fake_user32 = MagicMock()
    fake_user32.LockWorkStation.side_effect = OSError("boom")
    monkeypatch.setattr(lockscreen, "_user32", fake_user32)
    monkeypatch.setattr(lockscreen, "IS_WINDOWS", True)

    assert lockscreen.lock_workstation() is False


def test_lock_workstation_returns_false_off_windows(monkeypatch):
    monkeypatch.setattr(lockscreen, "IS_WINDOWS", False)

    assert lockscreen.lock_workstation() is False
