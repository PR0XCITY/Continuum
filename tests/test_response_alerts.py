"""Tests for continuum.response.alerts."""

from __future__ import annotations

import json

from continuum.response import alerts


def test_log_event_appends_a_jsonl_line(tmp_path):
    path = tmp_path / "events.jsonl"

    alerts.log_event("blocked", "device X blocked", device_id="dev-1", path=path)
    alerts.log_event("auto_release", "device X released", device_id="dev-1", path=path)

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    first = json.loads(lines[0])
    assert first["event_type"] == "blocked"
    assert first["device_id"] == "dev-1"
    assert first["message"] == "device X blocked"
    assert "timestamp" in first


def test_log_event_creates_parent_directories(tmp_path):
    path = tmp_path / "nested" / "dir" / "events.jsonl"

    alerts.log_event("notification", "hello", path=path)

    assert path.exists()


def test_send_toast_returns_false_off_windows(monkeypatch):
    monkeypatch.setattr(alerts, "IS_WINDOWS", False)

    assert alerts._send_toast("title", "message") is False


def test_notify_prints_and_logs(monkeypatch, tmp_path, capsys):
    path = tmp_path / "events.jsonl"
    monkeypatch.setattr(alerts, "_send_toast", lambda title, message: True)

    alerts.notify("Continuum alert", "something happened", device_id="dev-1", log_path=path)

    captured = capsys.readouterr()
    assert "Continuum alert" in captured.out
    assert "something happened" in captured.out

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["device_id"] == "dev-1"


def test_notify_does_not_raise_if_toast_fails(monkeypatch, tmp_path):
    path = tmp_path / "events.jsonl"
    monkeypatch.setattr(alerts, "_send_toast", lambda title, message: False)
    # notify() must survive even if the underlying toast call itself
    # would have raised; _send_toast already guarantees that, this just
    # confirms notify() does not also need its own try/except.
    alerts.notify("title", "message", log_path=path)

    assert path.exists()
