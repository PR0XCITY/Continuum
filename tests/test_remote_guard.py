"""Tests for remote-access typing detection: monitor, tools, guard, routes and dashboard.

Every Windows call is mocked: running processes come from a fake list,
locking and ending sessions are recorded instead of performed, and the
shared remote_status row lives in a temporary SQLite file created with
the connector's own schema.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from continuum import runtime
from continuum.common.config import RemoteSettings, load_settings
from continuum.common.schemas import (
    SOFTWARE_INPUT_DEVICE_ID,
    ActionTaken,
    AttackPattern,
    IncidentRecord,
    KeyEvent,
)
from continuum.connector import db
from continuum.dashboard import helpers
from continuum.detection.remote_input import RemoteInputMonitor
from continuum.remote_guard import (
    RemoteGuard,
    read_remote_allowance,
    write_remote_status,
)
from continuum.response import remote_session
from continuum.response.blocker_windows import DeviceBlocker


def _key(event_type="down", *, is_repeat=False, press_id=1):
    return KeyEvent(
        device_id=SOFTWARE_INPUT_DEVICE_ID,
        timestamp_ns=press_id * 1_000_000,
        event_type=event_type,
        press_id=press_id,
        is_repeat=is_repeat,
    )


class _Clock:
    def __init__(self, start=100.0):
        self.now = start

    def __call__(self):
        return self.now


@pytest.fixture
def connector_db(tmp_path):
    path = tmp_path / "connector.sqlite3"
    engine = db.create_db_engine(path)
    factory = db.make_session_factory(engine)
    yield path, factory
    engine.dispose()


def _guard(path, *, tools=("AnyDesk.exe",), **settings_overrides):
    locks: list[int] = []
    ended: list[list[str]] = []
    clock = _Clock()
    guard = RemoteGuard(
        settings=RemoteSettings(**settings_overrides),
        connector_db_path=path,
        clock=clock,
        list_tools=lambda configured: list(tools),
        lock=lambda: locks.append(1) or True,
        end_sessions=lambda names: ended.append(list(names)) or list(names),
    )
    return guard, clock, locks, ended


def _type(guard, clock, presses, *, gap=0.2):
    incidents = []
    for press in range(presses):
        clock.now += gap
        incidents.append(guard.handle(_key(press_id=press * 2)))
        incidents.append(guard.handle(_key("up", press_id=press * 2)))
    return [incident for incident in incidents if incident is not None]


# --- the monitor ----------------------------------------------------------------


def test_monitor_triggers_on_a_run_of_presses_and_ignores_ups_and_repeats():
    monitor = RemoteInputMonitor(min_presses=3, window_seconds=5.0)

    assert monitor.observe(_key(), 0.0) is None
    assert monitor.observe(_key("up"), 0.1) is None
    assert monitor.observe(_key(is_repeat=True), 0.2) is None
    assert monitor.observe(_key(), 0.3) is None
    trigger = monitor.observe(_key(), 0.5)

    assert trigger is not None
    assert trigger.presses == 3
    assert trigger.time_to_detect_ms == 500


def test_monitor_forgets_presses_older_than_the_window():
    monitor = RemoteInputMonitor(min_presses=3, window_seconds=5.0)
    monitor.observe(_key(), 0.0)
    monitor.observe(_key(), 1.0)

    assert monitor.observe(_key(), 7.0) is None  # the first two have aged out


def test_monitor_reports_one_trigger_per_cooldown():
    monitor = RemoteInputMonitor(min_presses=2, window_seconds=5.0, cooldown_seconds=30.0)
    monitor.observe(_key(), 0.0)
    assert monitor.observe(_key(), 0.1) is not None

    monitor.observe(_key(), 1.0)
    assert monitor.observe(_key(), 1.1) is None  # still cooling down
    monitor.observe(_key(), 40.0)
    assert monitor.observe(_key(), 40.1) is not None


# --- remote-access tools ----------------------------------------------------------


def test_running_remote_tools_matches_names_ignoring_case():
    found = remote_session.running_remote_tools(
        ["AnyDesk.exe", "TeamViewer.exe"],
        list_processes=lambda: ["explorer.exe", "anydesk.EXE", "python.exe"],
    )

    assert found == ["AnyDesk.exe"]


def test_end_remote_sessions_reports_only_what_taskkill_ended(monkeypatch):
    monkeypatch.setattr(remote_session, "IS_WINDOWS", True)
    results = {
        "AnyDesk.exe": subprocess.CompletedProcess([], 0, "", ""),
        "TeamViewer.exe": subprocess.CompletedProcess([], 128, "", "not found"),
    }

    ended = remote_session.end_remote_sessions(
        ["AnyDesk.exe", "TeamViewer.exe"], kill=results.get
    )

    assert ended == ["AnyDesk.exe"]


def test_end_remote_sessions_does_nothing_off_windows(monkeypatch):
    monkeypatch.setattr(remote_session, "IS_WINDOWS", False)
    assert remote_session.end_remote_sessions(["AnyDesk.exe"], kill=pytest.fail) == []


def test_default_config_ships_the_remote_section(tmp_path):
    settings = load_settings(local_override_path=tmp_path / "absent.yaml", env={})
    assert settings.remote.enabled is True
    assert settings.remote.trigger == "remote_tool_running"
    assert settings.remote.response == "lock"
    assert "AnyDesk.exe" in settings.remote.tools


# --- the guard -------------------------------------------------------------------


def test_remote_typing_with_anydesk_running_locks_and_records_an_incident(connector_db):
    path, factory = connector_db
    guard, clock, locks, ended = _guard(path)

    incidents = _type(guard, clock, 5)

    assert len(incidents) == 1
    incident = incidents[0]
    assert locks == [1]
    assert ended == []
    assert incident.action_taken == ActionTaken.WORKSTATION_LOCKED
    assert incident.attack_pattern == AttackPattern.REMOTE_ACCESS_INPUT
    assert incident.mitre_technique == "T1219 Remote Access Software"
    assert incident.device.device_id == SOFTWARE_INPUT_DEVICE_ID
    assert "AnyDesk.exe" in incident.notes
    IncidentRecord.model_validate(incident.model_dump())  # survives the connector's check

    session = factory()
    row = db.get_remote_status(session)
    session.close()
    assert row.last_action == "workstation_locked"
    assert row.last_detected_at is not None


def test_software_typing_without_a_remote_tool_is_ignored_by_default(connector_db):
    path, _ = connector_db
    guard, clock, locks, _ = _guard(path, tools=())

    assert _type(guard, clock, 10) == []
    assert locks == []


def test_any_software_input_trigger_reacts_without_a_remote_tool(connector_db):
    path, _ = connector_db
    guard, clock, locks, _ = _guard(path, tools=(), trigger="any_software_input")

    assert len(_type(guard, clock, 5)) == 1
    assert locks == [1]


def test_lock_and_end_session_ends_the_remote_tool(connector_db):
    path, _ = connector_db
    guard, clock, locks, ended = _guard(path, response="lock_and_end_session")

    [incident] = _type(guard, clock, 5)

    assert ended == [["AnyDesk.exe"]]
    assert incident.action_taken == ActionTaken.LOCKED_AND_ENDED_REMOTE


def test_alert_only_never_locks(connector_db):
    path, _ = connector_db
    guard, clock, locks, _ = _guard(path, response="alert_only")

    [incident] = _type(guard, clock, 5)

    assert locks == []
    assert incident.action_taken == ActionTaken.ALERT_ONLY


def test_dry_run_never_locks(connector_db):
    path, _ = connector_db
    guard, clock, locks, _ = _guard(path)
    guard.dry_run = True

    [incident] = _type(guard, clock, 5)

    assert locks == []
    assert incident.action_taken == ActionTaken.ALERT_ONLY


def test_disabled_guard_does_nothing(connector_db):
    path, _ = connector_db
    guard, clock, locks, _ = _guard(path, enabled=False)

    assert _type(guard, clock, 10) == []
    assert locks == []


def test_an_open_allowance_lets_remote_typing_through(connector_db):
    path, factory = connector_db
    session = factory()
    db.set_remote_allowance(session, datetime.now(UTC) + timedelta(minutes=30))
    session.close()
    guard, clock, locks, _ = _guard(path)

    assert _type(guard, clock, 10) == []
    assert locks == []


def test_an_expired_allowance_no_longer_applies(connector_db):
    path, factory = connector_db
    session = factory()
    db.set_remote_allowance(session, datetime.now(UTC) - timedelta(minutes=1))
    session.close()

    assert read_remote_allowance(path) is False


def test_status_writes_keep_the_dashboard_allowance(connector_db):
    path, factory = connector_db
    until = datetime.now(UTC) + timedelta(minutes=10)
    session = factory()
    db.set_remote_allowance(session, until)
    session.close()

    write_remote_status(path, tools_running=["AnyDesk.exe"])

    session = factory()
    row = db.get_remote_status(session)
    session.close()
    assert row.allowed_until is not None
    assert row.tools_running_json == '["AnyDesk.exe"]'
    assert read_remote_allowance(path) is True


def test_remote_status_helpers_survive_a_database_without_the_table(tmp_path):
    missing = tmp_path / "empty.sqlite3"
    write_remote_status(missing, tools_running=[])  # must not raise
    assert read_remote_allowance(missing) is False


# --- the runtime routes software input to the guard, never to cadence ---------------


class _FakeCapture:
    def list_devices(self):
        return []


def test_process_event_sends_software_input_to_the_guard_only(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "notify", lambda *args, **kwargs: None)
    path = tmp_path / "connector.sqlite3"
    db.create_db_engine(path).dispose()
    guard, clock, locks, _ = _guard(path)
    recorder = runtime.BaselineRecorder()
    recorder.start(1)
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    client = httpx.Client()
    buffers: dict = {}
    try:
        for press in range(5):
            clock.now += 0.2
            runtime.process_event(
                _key(press_id=press),
                device_buffers=buffers,
                pending_since={},
                scorer=None,
                capture=_FakeCapture(),
                blocker=DeviceBlocker(dry_run=True, disabled_devices_path=tmp_path / "d.json"),
                outbox=outbox,
                http_client=client,
                base_url="http://127.0.0.1:1",
                token="t",
                effective_mode="lock_only",
                allowlist=[],
                connector_db_path=path,
                recorder=recorder,
                remote_guard=guard,
            )
        queued = len(outbox)
    finally:
        client.close()
        outbox.close()

    assert locks == [1]
    assert queued == 1  # the connector is unreachable, so the incident waits in the outbox
    assert buffers == {}
    assert recorder.presses_by_device() == {}  # never mixed into a typing baseline


# --- connector routes ----------------------------------------------------------------

ROUTES = [
    ("get", "/remote", None),
    ("post", "/remote/allow", {"minutes": 10}),
    ("delete", "/remote/allow", None),
]


def _call(client, method, path, body=None, headers=None):
    kwargs = {"headers": headers or {}}
    if body is not None:
        kwargs["json"] = body
    return getattr(client, method)(path, **kwargs)


@pytest.mark.parametrize(("method", "path", "body"), ROUTES)
def test_remote_routes_reject_a_missing_or_wrong_token(connector_client, method, path, body):
    assert _call(connector_client, method, path, body).status_code == 401
    wrong = {"Authorization": "Bearer wrong"}
    assert _call(connector_client, method, path, body, wrong).status_code == 401


def test_remote_status_starts_protected(connector_client, auth_headers):
    body = connector_client.get("/remote", headers=auth_headers).json()

    assert body["enabled"] is True
    assert body["allowed"] is False
    assert body["tools_running"] == []
    assert body["last_detected_at"] is None


def test_allow_and_stop_allowing(connector_client, auth_headers):
    allowed = connector_client.post(
        "/remote/allow", json={"minutes": 10}, headers=auth_headers
    ).json()
    assert allowed["allowed"] is True
    until = datetime.fromisoformat(allowed["allowed_until"])
    assert timedelta(minutes=9) < until - datetime.now(UTC) <= timedelta(minutes=10)

    stopped = connector_client.delete("/remote/allow", headers=auth_headers).json()
    assert stopped["allowed"] is False
    assert stopped["allowed_until"] is None


def test_allow_uses_the_configured_minutes_by_default(connector_client, auth_headers):
    body = connector_client.post("/remote/allow", json={}, headers=auth_headers).json()
    until = datetime.fromisoformat(body["allowed_until"])
    assert until - datetime.now(UTC) > timedelta(minutes=29)


def test_allow_rejects_an_out_of_range_duration(connector_client, auth_headers):
    response = connector_client.post(
        "/remote/allow", json={"minutes": 100000}, headers=auth_headers
    )
    assert response.status_code == 422


# --- dashboard helper ---------------------------------------------------------------


def test_remote_summary_states():
    now = datetime.now(UTC)
    base = {"enabled": True, "response": "lock", "allowed": False, "tools_running": []}

    assert helpers.remote_summary({"enabled": False}, now=now)["badge"] == "off"
    assert helpers.remote_summary(base, now=now)["badge"] == "protected"
    watching = helpers.remote_summary({**base, "tools_running": ["AnyDesk.exe"]}, now=now)
    assert watching["badge"] == "watching"
    assert "AnyDesk.exe" in watching["hint"]
    allowed = helpers.remote_summary(
        {**base, "allowed": True, "allowed_until": (now + timedelta(minutes=5)).isoformat()},
        now=now,
    )
    assert allowed["badge"] == "allowed"
