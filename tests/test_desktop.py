"""Tests for the desktop app (continuum.desktop).

Qt runs on the "offscreen" platform, so no window ever appears, and the
connector API is a fake httpx transport returning the shapes the real
API returns. Covers the pure helpers, that untrusted text is never
rendered as rich text, and that every page loads its data and draws
without raising.
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import json  # noqa: E402
from datetime import UTC, datetime, timedelta  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402

pytest.importorskip("PySide6")

from PySide6.QtCore import QEventLoop, Qt, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from continuum.common.config import load_settings  # noqa: E402
from continuum.dashboard.api import ConnectorClient  # noqa: E402
from continuum.desktop import backend  # noqa: E402
from continuum.desktop.typing_stats import typing_stats  # noqa: E402
from continuum.desktop.widgets import ZERO_WIDTH_SPACE, breakable, plain_label  # noqa: E402

NOW = datetime.now(UTC)
DIGISPARK = r"HID\VID_16C0&PID_27DB\7&286123A5&0&0000"


def _device(device_id=DIGISPARK, *, disabled=False, quarantined=False):
    return {
        "device_id": device_id,
        "name": "USB Keyboard (VID_16C0 PID_27DB)",
        "vendor_id": "16C0",
        "product_id": "27DB",
        "bus_type": "USB",
        "is_usb": True,
        "disabled": disabled,
        "quarantined": quarantined,
    }


def _incident():
    return {
        "incident_id": "8e636b63-dee6-490c-a04a-b3ce7a2bd30e",
        "detected_at": NOW.isoformat(),
        "device": {**_device(), "instance_id": DIGISPARK, "first_seen": NOW.isoformat()},
        "anomaly_score": 0.12,
        "threshold": 0.012,
        "verdict": "blocked",
        "attack_pattern": "burst_injection",
        "features_summary": {"flight_mean_ms": 16.0, "trial_ms_first_press_to_block": 270.0,
                             "trial_presses_to_block": 40.0},
        "action_taken": "locked_and_quarantined",
        "time_to_detect_ms": 458,
        "mitre_technique": "T1200 Hardware Additions",
        "recommended_followups": ["isolate_device", "notify_security_team"],
        "notes": "<img src=http://example.invalid/x.png> <b>not bold</b>",
    }


RESPONSES = {
    ("GET", "/health"): {"status": "ok"},
    ("GET", "/runtime"): {
        "running": True, "state": "running", "started_at": NOW.isoformat(),
        "last_heartbeat": NOW.isoformat(), "seconds_since_heartbeat": 1.0, "pid": 1,
        "elevated": True, "configured_mode": "disable_only", "effective_mode": "disable_only",
        "dry_run": False, "model_version": "isolation_forest-20261015T120822Z",
        "calibrated_threshold": 0.0236, "threshold": 0.0236, "sensitivity": 5,
        "devices": [_device(disabled=True, quarantined=True)],
    },
    ("GET", "/live"): [
        {"device_id": DIGISPARK, "verdict": "blocked", "anomaly_score": 0.119,
         "threshold": 0.0118, "features": {"flight_mean_ms": 16.0},
         "updated_at": (NOW - timedelta(seconds=5)).isoformat()},
    ],
    ("GET", "/remote"): {
        "enabled": True, "trigger": "remote_tool_running", "response": "lock",
        "allow_minutes": 30, "allowed": False, "allowed_until": None,
        "tools_running": ["AnyDesk.exe"], "last_detected_at": None, "last_action": None,
        "last_tools": [], "updated_at": NOW.isoformat(),
    },
    ("GET", "/stats"): {"total_incidents": 1, "mean_anomaly_score": 0.12,
                        "mean_time_to_detect_ms": 458.0, "counts_by_attack_pattern": {},
                        "counts_by_day": []},
    ("GET", "/incidents"): {"items": [_incident()], "total": 1},
    ("GET", "/training"): {
        "runtime_running": True, "session": None, "saved_sessions": 0,
        "baseline": {"exists": False, "n_windows": 0, "device_id": None, "updated_at": None},
        "model": {"exists": True, "version": "isolation_forest-20261015T120822Z",
                  "trained_at": NOW.isoformat(), "n_training_windows": 50},
        "minimum_windows": 60, "recommended_windows": 150,
    },
    ("GET", "/calibration"): {
        "configured_sensitivity": 5,
        "models": [{"user": "tester", "version": "isolation_forest-20261015T120822Z",
                    "model_type": "isolation_forest", "calibrated_threshold": 0.0236,
                    "threshold_at_configured_sensitivity": 0.0236,
                    "target_false_positive_rate": 0.01, "baseline_device_id": DIGISPARK,
                    "n_training_windows": 50, "n_calibration_windows": 12,
                    "modified_at": NOW.isoformat()}],
        "baselines": [],
        "eval_results_markdown": (
            "# Results\n\nSome prose.\n\n| a | b |\n| --- | --- |\n| 1 | 2 |\n"
        ),
    },
    ("GET", "/settings"): {
        "settings": {"sensitivity": 5, "response_mode": "disable_only", "dry_run": False,
                     "allowlist": []},
        "env_overridden_fields": [], "applies_on": "runtime_restart",
    },
}


def _handler(request: httpx.Request) -> httpx.Response:
    if request.headers.get("Authorization") != "Bearer test-token":
        return httpx.Response(401, json={"detail": "bad token"})
    body = RESPONSES.get((request.method, request.url.path))
    if body is None:
        return httpx.Response(404, json={"detail": "not faked"})
    return httpx.Response(200, content=json.dumps(body))


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def client():
    instance = ConnectorClient(
        "http://127.0.0.1:1", "test-token", transport=httpx.MockTransport(_handler)
    )
    yield instance
    instance.close()


def _pump(seconds: float) -> None:
    loop = QEventLoop()
    QTimer.singleShot(int(seconds * 1000), loop.quit)
    loop.exec()


# --- pure helpers -------------------------------------------------------------------


def test_typing_stats_matches_the_browser_rules():
    stats = typing_stats("hello worle", "hello world", elapsed_seconds=6.0)

    assert stats.words_per_minute == 22  # 11 characters / 5 per word / 0.1 minute
    assert stats.accuracy_percent == 91  # 10 of 11 correct
    assert stats.done_percent == 100
    assert "words per minute" in stats.describe()


def test_typing_stats_before_any_typing():
    stats = typing_stats("", "hello", elapsed_seconds=0.0)
    assert (stats.words_per_minute, stats.accuracy_percent, stats.done_percent) == (0, 100, 0)


def test_breakable_only_adds_invisible_break_points():
    text = breakable(DIGISPARK)

    assert text.replace(ZERO_WIDTH_SPACE, "") == DIGISPARK
    assert f"\\{ZERO_WIDTH_SPACE}" in text and f"&{ZERO_WIDTH_SPACE}" in text


def test_component_running_is_false_without_a_pid_file(tmp_path, monkeypatch):
    monkeypatch.setattr(backend, "RUN_DIR", tmp_path)
    assert backend.component_running("api") is False
    (tmp_path / "api.pid").write_text("not a number", encoding="ascii")
    assert backend.component_running("api") is False


def test_request_runtime_stop_writes_the_stop_file(tmp_path, monkeypatch):
    monkeypatch.setattr(backend, "RUN_DIR", tmp_path)
    monkeypatch.setattr(backend, "STOP_REQUEST_PATH", tmp_path / "runtime.stop")

    backend.request_runtime_stop()

    assert (tmp_path / "runtime.stop").exists()


# --- untrusted text -------------------------------------------------------------------


def test_labels_never_render_untrusted_text_as_html(qapp):
    label = plain_label("<img src=http://example.invalid/x.png><b>bold</b>")
    assert label.textFormat() == Qt.TextFormat.PlainText


# --- the whole window -------------------------------------------------------------------


def test_every_page_loads_and_draws(qapp, client, tmp_path):
    from continuum.desktop.app import MainWindow

    settings = load_settings(local_override_path=tmp_path / "absent.yaml", env={})
    window = MainWindow(settings, client)
    window.ctx.start_protection = lambda: None
    window.start_protection = lambda: None
    window.resize(1200, 800)
    window.show()
    try:
        for index in range(len(window.pages)):
            window.nav.setCurrentRow(index)
            _pump(0.6)
            assert not window.grab().isNull()
        window.poll_status()
        _pump(0.4)
        assert window.runtime_status.text() == "Protection on"

        live = window.pages[0]
        assert live.remote_badge.text() == "WATCHING"
        assert live.not_running.isHidden()

        incidents = window.pages[1]
        assert incidents.count_label.text() == "1 incidents"
        assert incidents.table.rowCount() == 1

        window.ask_about("What happened?")
        assert window.stack.currentWidget() is window.ask_page
        assert window.ask_page.question.toPlainText() == "What happened?"
    finally:
        window.quit()
