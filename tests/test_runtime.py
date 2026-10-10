"""Tests for continuum.runtime.

Covers the pure/testable pieces: attack-pattern classification, incident
building, the outbox's retry and backoff logic, that lock_workstation()
runs before the API post is even attempted, and a full process_event
pass through to a queued incident with every Win32, pnputil and network
call mocked.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import numpy as np
import pytest
from tools.simulators import human_like_events

from continuum import runtime
from continuum.common.config import load_settings
from continuum.common.schemas import (
    ActionTaken,
    AttackPattern,
    DetectionResult,
    DeviceInfo,
    FeatureWindow,
)
from continuum.connector import db as connector_db
from continuum.detection.scorer import Scorer
from continuum.response import blocker_windows as blocker_module
from continuum.response.blocker_windows import DeviceBlocker

DEVICE_ID = "device-under-test"


def _device(**overrides: object) -> DeviceInfo:
    base = dict(
        device_id=DEVICE_ID,
        vendor_id="046D",
        product_id="C52B",
        name="Test Keyboard",
        bus_type="USB",
        is_usb=True,
        instance_id=r"HID\VID_046D&PID_C52B\0",
        first_seen=datetime(2026, 1, 1, tzinfo=UTC),
    )
    base.update(overrides)
    return DeviceInfo(**base)


def _window(**features: float) -> FeatureWindow:
    return FeatureWindow(
        device_id=DEVICE_ID,
        window_start_ns=0,
        n_events=30,
        features={
            "flight_mean_ms": 100.0,
            "flight_cv": 0.3,
            "burst_score": 0.0,
            "regularity_ratio": 0.2,
            **features,
        },
    )


def _detection_result(**window_features: float) -> DetectionResult:
    return DetectionResult(
        device_id=DEVICE_ID,
        anomaly_score=2.0,
        threshold=1.0,
        verdict="blocked",
        window=_window(**window_features),
        model_version="test-v1",
    )


# --- classify_attack_pattern -------------------------------------------------


def test_classify_attack_pattern_burst():
    pattern = runtime.classify_attack_pattern({"burst_score": 0.95, "flight_cv": 0.0})
    assert pattern == AttackPattern.BURST_INJECTION


def test_classify_attack_pattern_slowed():
    pattern = runtime.classify_attack_pattern(
        {"burst_score": 0.0, "flight_cv": 0.001, "regularity_ratio": 0.99}
    )
    assert pattern == AttackPattern.SLOWED_INJECTION


def test_classify_attack_pattern_randomized():
    pattern = runtime.classify_attack_pattern(
        {"burst_score": 0.0, "flight_cv": 0.2, "regularity_ratio": 0.1}
    )
    assert pattern == AttackPattern.RANDOMIZED_INJECTION


def test_classify_attack_pattern_unknown_for_human_like_variance():
    pattern = runtime.classify_attack_pattern(
        {"burst_score": 0.0, "flight_cv": 0.6, "regularity_ratio": 0.1}
    )
    assert pattern == AttackPattern.UNKNOWN


# --- build_incident -----------------------------------------------------------


def test_build_incident_populates_expected_fields():
    result = _detection_result(burst_score=0.95, flight_cv=0.01)
    device = _device()

    incident = runtime.build_incident(
        result, device, action_taken=ActionTaken.LOCKED_AND_DISABLED, time_to_detect_ms=1234
    )

    assert incident.device.device_id == DEVICE_ID
    assert incident.anomaly_score == 2.0
    assert incident.threshold == 1.0
    assert incident.verdict == "blocked"
    assert incident.action_taken == ActionTaken.LOCKED_AND_DISABLED
    assert incident.time_to_detect_ms == 1234
    assert incident.attack_pattern == AttackPattern.BURST_INJECTION
    assert len(incident.notes) <= 280
    assert "isolate_device" in [f.value for f in incident.recommended_followups]
    assert "notify_security_team" in [f.value for f in incident.recommended_followups]


def test_build_incident_includes_window_n_events_for_hardware_trials():
    result = _detection_result()
    device = _device()

    incident = runtime.build_incident(
        result, device, action_taken=ActionTaken.ALERT_ONLY, time_to_detect_ms=0
    )

    assert incident.features_summary["window_n_events"] == 30.0


def test_build_incident_negative_time_to_detect_is_clamped_to_zero():
    result = _detection_result()
    device = _device()

    incident = runtime.build_incident(
        result, device, action_taken=ActionTaken.ALERT_ONLY, time_to_detect_ms=-50
    )

    assert incident.time_to_detect_ms == 0


# --- other_enabled_keyboard_count --------------------------------------------


class _FakeCapture:
    def __init__(self, devices: list[DeviceInfo]) -> None:
        self._devices = devices

    def list_devices(self) -> list[DeviceInfo]:
        return self._devices


class _FakeBlocker:
    def __init__(self, disabled_instance_ids: list[str]) -> None:
        self.disabled_instance_ids = disabled_instance_ids


def test_other_enabled_keyboard_count_excludes_self_and_disabled():
    other = _device(device_id="other-device", instance_id=r"HID\other")
    this_device = _device()
    capture = _FakeCapture([this_device, other])
    blocker = _FakeBlocker(disabled_instance_ids=[])

    count = runtime.other_enabled_keyboard_count(capture, blocker, DEVICE_ID)

    assert count == 1


def test_other_enabled_keyboard_count_excludes_already_disabled_devices():
    other = _device(device_id="other-device", instance_id=r"HID\other")
    capture = _FakeCapture([_device(), other])
    blocker = _FakeBlocker(disabled_instance_ids=[other.instance_id])

    count = runtime.other_enabled_keyboard_count(capture, blocker, DEVICE_ID)

    assert count == 0


# --- respond_to_block: lock first, disable only in lock_and_disable mode ----


def test_respond_to_block_lock_only_mode_never_calls_disable(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "lock_workstation", lambda: True)
    disable_calls = []

    class _NoDisableBlocker(DeviceBlocker):
        def disable(self, *args, **kwargs):
            disable_calls.append(args)
            raise AssertionError("disable must not be called in lock_only mode")

    blocker = _NoDisableBlocker(disabled_devices_path=tmp_path / "disabled.json")
    device = _device()
    result = _detection_result()

    action = runtime.respond_to_block(
        device,
        result,
        effective_mode="lock_only",
        blocker=blocker,
        allowlist=[],
        other_enabled_keyboard_count_value=1,
    )

    assert action == ActionTaken.WORKSTATION_LOCKED
    assert disable_calls == []


def test_lock_is_called_before_disable_is_attempted(tmp_path, monkeypatch):
    call_order: list[str] = []
    monkeypatch.setattr(runtime, "lock_workstation", lambda: call_order.append("lock") or True)
    monkeypatch.setattr(blocker_module, "is_elevated", lambda: True)

    monkeypatch.setattr(
        blocker_module, "_pnputil_disable", lambda i: call_order.append("disable")
    )
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: False)

    blocker = DeviceBlocker(disabled_devices_path=tmp_path / "disabled.json")
    device = _device()
    result = _detection_result()

    action = runtime.respond_to_block(
        device,
        result,
        effective_mode="lock_and_disable",
        blocker=blocker,
        allowlist=[],
        other_enabled_keyboard_count_value=1,
    )

    assert action == ActionTaken.LOCKED_AND_DISABLED
    assert call_order == ["lock", "disable"]


def test_lock_is_called_before_the_api_post(tmp_path, monkeypatch):
    call_order: list[str] = []
    monkeypatch.setattr(runtime, "lock_workstation", lambda: call_order.append("lock") or True)
    monkeypatch.setattr(
        runtime, "post_incident", lambda *a, **k: call_order.append("post") or False
    )

    blocker = DeviceBlocker(dry_run=True, disabled_devices_path=tmp_path / "disabled.json")
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    client = httpx.Client()
    device = _device()
    result = _detection_result()

    action = runtime.respond_to_block(
        device,
        result,
        effective_mode="lock_and_disable",
        blocker=blocker,
        allowlist=[],
        other_enabled_keyboard_count_value=1,
    )
    incident = runtime.build_incident(
        result, device, action_taken=action, time_to_detect_ms=10
    )
    runtime.post_or_queue_incident(outbox, client, "http://127.0.0.1:1", "token", incident)

    assert call_order == ["lock", "post"]
    client.close()
    outbox.close()


# --- IncidentOutbox: retry and backoff ---------------------------------------


def _incident() -> object:
    device = _device()
    result = _detection_result()
    return runtime.build_incident(
        result, device, action_taken=ActionTaken.ALERT_ONLY, time_to_detect_ms=0
    )


def test_outbox_enqueue_then_due_entries(tmp_path):
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    outbox.enqueue(_incident())

    entries = outbox.due_entries()

    assert len(entries) == 1
    row_id, incident, attempts = entries[0]
    assert attempts == 0
    assert incident.device.device_id == DEVICE_ID
    outbox.close()


def test_outbox_mark_sent_removes_the_entry(tmp_path):
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    outbox.enqueue(_incident())
    [(row_id, _, _)] = outbox.due_entries()

    outbox.mark_sent(row_id)

    assert outbox.due_entries() == []
    assert len(outbox) == 0
    outbox.close()


def test_outbox_mark_retry_schedules_a_future_retry_with_backoff(tmp_path):
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    outbox.enqueue(_incident())
    [(row_id, _, attempts)] = outbox.due_entries()

    new_attempts = attempts + 1
    outbox.mark_retry(row_id, attempts=new_attempts)

    # Not due immediately: backoff pushed next_retry_at into the future.
    assert outbox.due_entries(now=datetime.now(UTC)) == []
    expected_delay = runtime.OUTBOX_BASE_BACKOFF_SECONDS * (2**new_attempts)
    future = datetime.now(UTC) + timedelta(seconds=expected_delay + 1)
    due_later = outbox.due_entries(now=future)
    assert len(due_later) == 1
    assert due_later[0][2] == 1
    outbox.close()


def test_outbox_backoff_grows_and_is_capped(tmp_path):
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    outbox.enqueue(_incident())
    [(row_id, _, _)] = outbox.due_entries()

    outbox.mark_retry(row_id, attempts=10)  # a high attempt count

    far_future = datetime.now(UTC) + timedelta(seconds=runtime.OUTBOX_MAX_BACKOFF_SECONDS + 1)
    assert len(outbox.due_entries(now=far_future)) == 1
    outbox.close()


def test_post_or_queue_incident_queues_on_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "post_incident", lambda *a, **k: False)
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    client = httpx.Client()

    runtime.post_or_queue_incident(outbox, client, "http://127.0.0.1:1", "token", _incident())

    assert len(outbox) == 1
    client.close()
    outbox.close()


def test_post_or_queue_incident_does_not_queue_on_success(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "post_incident", lambda *a, **k: True)
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    client = httpx.Client()

    runtime.post_or_queue_incident(outbox, client, "http://127.0.0.1:1", "token", _incident())

    assert len(outbox) == 0
    client.close()
    outbox.close()


def test_drain_outbox_posts_due_entries_and_removes_them_on_success(tmp_path, monkeypatch):
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    outbox.enqueue(_incident())
    monkeypatch.setattr(runtime, "post_incident", lambda *a, **k: True)
    client = httpx.Client()

    runtime.drain_outbox(outbox, client, "http://127.0.0.1:1", "token")

    assert len(outbox) == 0
    client.close()
    outbox.close()


def test_drain_outbox_reschedules_on_continued_failure(tmp_path, monkeypatch):
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    outbox.enqueue(_incident())
    monkeypatch.setattr(runtime, "post_incident", lambda *a, **k: False)
    client = httpx.Client()

    runtime.drain_outbox(outbox, client, "http://127.0.0.1:1", "token")

    assert len(outbox) == 1  # still queued, not lost
    assert outbox.due_entries(now=datetime.now(UTC)) == []  # but not due again yet
    client.close()
    outbox.close()


# --- determine_effective_mode -------------------------------------------------


def test_determine_effective_mode_degrades_without_elevation():
    settings = load_settings(env={"CONTINUUM_RESPONSE__MODE": "lock_and_disable"})

    assert runtime.determine_effective_mode(settings, elevated=False) == "lock_only"
    assert runtime.determine_effective_mode(settings, elevated=True) == "lock_and_disable"


def test_determine_effective_mode_leaves_other_modes_untouched():
    settings = load_settings(env={"CONTINUUM_RESPONSE__MODE": "alert_only"})

    assert runtime.determine_effective_mode(settings, elevated=False) == "alert_only"


# --- process_event: full pass with everything mocked --------------------------


def test_process_event_on_blocked_verdict_locks_then_queues_an_incident(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "lock_workstation", lambda: True)
    monkeypatch.setattr(blocker_module, "is_elevated", lambda: True)
    monkeypatch.setattr(runtime, "post_incident", lambda *a, **k: False)
    monkeypatch.setattr(runtime, "notify", lambda *a, **k: None)

    monkeypatch.setattr(blocker_module, "_pnputil_disable", lambda i: None)
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: False)

    device = _device()
    other_device = _device(
        device_id="other-keyboard", instance_id=r"ACPI\ATK3001\0", bus_type="PS2", is_usb=False
    )
    capture = _FakeCapture([device, other_device])
    blocker = DeviceBlocker(disabled_devices_path=tmp_path / "disabled.json")
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    client = httpx.Client()

    class _AlwaysFlagModel:
        version = "test-v1"
        baseline_device_id = "a-different-baseline-device"
        threshold = 0.0

        def score_one(self, features: dict[str, float]) -> float:
            return 1.0  # above threshold for every window

    scorer = Scorer(_AlwaysFlagModel())
    device_buffers: dict = {}
    pending_since: dict = {}

    events = human_like_events(DEVICE_ID, 70, rng=np.random.default_rng(1))

    for event in events:
        runtime.process_event(
            event,
            device_buffers=device_buffers,
            pending_since=pending_since,
            scorer=scorer,
            capture=capture,
            blocker=blocker,
            outbox=outbox,
            http_client=client,
            base_url="http://127.0.0.1:1",
            token="test-token",
            effective_mode="lock_and_disable",
            allowlist=[],
            connector_db_path=tmp_path / "connector.sqlite3",
        )

    assert len(outbox) >= 1
    assert blocker.is_disabled(device.instance_id) is True

    # With every window flagged, the block lands on the second window: 30
    # presses for the first window plus a 10-press step for the second.
    _, incident, _ = outbox.due_entries(now=datetime.now(UTC))[0]
    summary = incident.features_summary
    assert summary[runtime.TRIAL_PRESSES_TO_BLOCK] == 40.0
    expected_ms = (events_by_press(events)[39] - events_by_press(events)[0]) / 1_000_000
    assert summary[runtime.TRIAL_MS_TO_BLOCK] == pytest.approx(expected_ms, abs=0.01)
    assert summary[runtime.TRIAL_MS_TO_LOCK] >= summary[runtime.TRIAL_MS_TO_BLOCK]
    assert summary[runtime.TRIAL_MS_TO_RESPONSE] >= summary[runtime.TRIAL_MS_TO_LOCK]

    client.close()
    outbox.close()


def events_by_press(events):
    """Timestamps of non-repeat key-downs, in order."""
    return [e.timestamp_ns for e in events if e.event_type == "down" and not e.is_repeat]


def test_trial_timing_summary_without_a_lock_omits_the_lock_figure():
    buffer = runtime._DeviceBuffer(first_press_ns=1_000_000, presses_seen=45)
    event = human_like_events(DEVICE_ID, 1, rng=np.random.default_rng(3))[0].model_copy(
        update={"timestamp_ns": 501_000_000}
    )

    summary = runtime.trial_timing_summary(buffer, event, {"response_done_ms": 2.0})

    assert summary[runtime.TRIAL_PRESSES_TO_BLOCK] == 45.0
    assert summary[runtime.TRIAL_MS_TO_BLOCK] == pytest.approx(500.0)
    assert summary[runtime.TRIAL_MS_TO_RESPONSE] == pytest.approx(502.0)
    assert runtime.TRIAL_MS_TO_LOCK not in summary


def test_trial_timing_summary_is_empty_without_a_first_press():
    event = human_like_events(DEVICE_ID, 1, rng=np.random.default_rng(4))[0]

    assert runtime.trial_timing_summary(runtime._DeviceBuffer(), event, {}) == {}


def test_process_event_normal_verdict_does_nothing_harmful(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "lock_workstation", lambda: pytest.fail("must not lock"))

    device = _device()
    capture = _FakeCapture([device])
    blocker = DeviceBlocker(dry_run=True, disabled_devices_path=tmp_path / "disabled.json")
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    client = httpx.Client()

    class _NeverFlagModel:
        version = "test-v1"
        baseline_device_id = DEVICE_ID
        threshold = 1_000_000.0

        def score_one(self, features: dict[str, float]) -> float:
            return 0.0

    scorer = Scorer(_NeverFlagModel())
    device_buffers: dict = {}
    pending_since: dict = {}

    events = human_like_events(DEVICE_ID, 70, rng=np.random.default_rng(2))
    for event in events:
        runtime.process_event(
            event,
            device_buffers=device_buffers,
            pending_since=pending_since,
            scorer=scorer,
            capture=capture,
            blocker=blocker,
            outbox=outbox,
            http_client=client,
            base_url="http://127.0.0.1:1",
            token="test-token",
            effective_mode="lock_and_disable",
            allowlist=[],
            connector_db_path=tmp_path / "connector.sqlite3",
        )

    assert len(outbox) == 0
    assert blocker.disabled_instance_ids == []
    client.close()
    outbox.close()


# --- poll_unblock_commands and update_live_snapshot: the shared-table --------
# --- contract with continuum.connector.db ------------------------------------


def _connector_db(tmp_path):
    engine = connector_db.create_db_engine(tmp_path / "connector.sqlite3")
    return tmp_path / "connector.sqlite3", connector_db.make_session_factory(engine)


def test_poll_unblock_commands_releases_a_pending_device_and_marks_it_done(tmp_path):
    db_path, session_factory = _connector_db(tmp_path)
    session = session_factory()
    try:
        connector_db.insert_command(session, command_type="unblock", device_id="dev-1")
        session.commit()
    finally:
        session.close()

    released = []

    class _FakeBlocker:
        def enable(self, device_id: str) -> bool:
            released.append(device_id)
            return True

    runtime.poll_unblock_commands(db_path, _FakeBlocker())

    assert released == ["dev-1"]

    session = session_factory()
    try:
        [row] = session.execute(connector_db.select(connector_db.CommandRow)).scalars().all()
        assert row.status == "done"
        assert row.completed_at is not None
    finally:
        session.close()


def test_poll_unblock_commands_ignores_non_unblock_and_already_done_rows(tmp_path):
    db_path, session_factory = _connector_db(tmp_path)
    session = session_factory()
    try:
        connector_db.insert_command(session, command_type="unblock", device_id="already-done")
        session.execute(
            connector_db.CommandRow.__table__.update()
            .where(connector_db.CommandRow.device_id == "already-done")
            .values(status="done")
        )
        session.commit()
    finally:
        session.close()

    calls = []

    class _FakeBlocker:
        def enable(self, device_id: str) -> bool:
            calls.append(device_id)
            return True

    runtime.poll_unblock_commands(db_path, _FakeBlocker())

    assert calls == []


def test_poll_unblock_commands_is_a_safe_no_op_without_a_connector_db(tmp_path):
    missing_path = tmp_path / "does-not-exist" / "connector.sqlite3"

    class _FakeBlocker:
        def enable(self, device_id: str) -> bool:
            return True

    runtime.poll_unblock_commands(missing_path, _FakeBlocker())  # must not raise


def test_update_live_snapshot_upserts_the_latest_status(tmp_path):
    db_path, session_factory = _connector_db(tmp_path)
    window = FeatureWindow(
        device_id=DEVICE_ID, window_start_ns=0, n_events=30, features={"flight_mean_ms": 90.0}
    )
    first_result = DetectionResult(
        device_id=DEVICE_ID,
        anomaly_score=0.2,
        threshold=1.0,
        verdict="normal",
        window=window,
        model_version="test-v1",
    )

    runtime.update_live_snapshot(db_path, DEVICE_ID, first_result)

    session = session_factory()
    try:
        [row] = session.execute(connector_db.select(connector_db.LiveSnapshotRow)).scalars().all()
        assert row.verdict == "normal"
        assert row.anomaly_score == 0.2
    finally:
        session.close()

    second_result = DetectionResult(
        device_id=DEVICE_ID,
        anomaly_score=2.0,
        threshold=1.0,
        verdict="blocked",
        window=window,
        model_version="test-v1",
    )
    runtime.update_live_snapshot(db_path, DEVICE_ID, second_result)

    session = session_factory()
    try:
        rows = session.execute(connector_db.select(connector_db.LiveSnapshotRow)).scalars().all()
        assert len(rows) == 1  # upsert, not a second row
        assert rows[0].verdict == "blocked"
        assert rows[0].anomaly_score == 2.0
    finally:
        session.close()


def test_update_live_snapshot_is_a_safe_no_op_without_a_connector_db(tmp_path):
    missing_path = tmp_path / "does-not-exist" / "connector.sqlite3"
    window = FeatureWindow(
        device_id=DEVICE_ID, window_start_ns=0, n_events=30, features={"flight_mean_ms": 90.0}
    )
    result = DetectionResult(
        device_id=DEVICE_ID,
        anomaly_score=0.1,
        threshold=1.0,
        verdict="normal",
        window=window,
        model_version="test-v1",
    )

    runtime.update_live_snapshot(missing_path, DEVICE_ID, result)  # must not raise
