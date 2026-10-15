"""Tests for continuum.response.blocker_windows.

Every pnputil and CfgMgr32 call is mocked. The safety-rail tests
confirm the refusal happens before pnputil is ever touched, by making
the mocked pnputil call raise if it is reached at all.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from continuum.response import blocker_windows as blocker_module
from continuum.response.blocker_windows import (
    DeviceBlocker,
    DisabledDeviceRecord,
    evaluate_block_decision,
    load_disabled_devices,
    save_disabled_devices,
)

CHILD_ID = r"HID\VID_046D&PID_C52B&MI_00\7&2F4BB3A7&0&0000"
PARENT_ID = r"USB\VID_046D&PID_C52B\7&2F4BB3A7&0&0000"


def _fail_if_called(*args, **kwargs):
    raise AssertionError("pnputil must not be called when the safety rails refuse")


@pytest.fixture
def blocker(tmp_path, monkeypatch):
    monkeypatch.setattr(blocker_module, "is_elevated", lambda: True)
    return DeviceBlocker(disabled_devices_path=tmp_path / "disabled_devices.json")


# --- evaluate_block_decision: pure, no mocking needed -----------------------


def test_evaluate_block_decision_allows_the_normal_case():
    decision = evaluate_block_decision(
        CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1
    )
    assert decision.allowed is True


def test_evaluate_block_decision_refuses_an_allowlisted_device():
    decision = evaluate_block_decision(
        CHILD_ID, is_usb=True, allowlist=[CHILD_ID], other_enabled_keyboard_count=1
    )
    assert decision.allowed is False
    assert "allowlist" in decision.reason


def test_evaluate_block_decision_refuses_non_usb_by_default():
    decision = evaluate_block_decision(
        CHILD_ID, is_usb=False, allowlist=[], other_enabled_keyboard_count=1
    )
    assert decision.allowed is False
    assert "non-USB" in decision.reason


def test_evaluate_block_decision_allows_non_usb_when_explicitly_configured():
    decision = evaluate_block_decision(
        CHILD_ID,
        is_usb=False,
        allowlist=[],
        other_enabled_keyboard_count=1,
        allow_non_usb=True,
    )
    assert decision.allowed is True


def test_evaluate_block_decision_refuses_the_last_remaining_keyboard():
    decision = evaluate_block_decision(
        CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=0
    )
    assert decision.allowed is False
    assert "last remaining keyboard" in decision.reason


# --- DeviceBlocker.disable: safety rails checked before any pnputil call ---


def test_disable_refuses_allowlisted_device_without_calling_pnputil(blocker, monkeypatch):
    monkeypatch.setattr(blocker_module, "_pnputil_disable", _fail_if_called)

    result = blocker.disable(
        CHILD_ID, is_usb=True, allowlist=[CHILD_ID], other_enabled_keyboard_count=1
    )

    assert result.success is False
    assert "allowlist" in result.reason


def test_disable_refuses_last_keyboard_without_calling_pnputil(blocker, monkeypatch):
    monkeypatch.setattr(blocker_module, "_pnputil_disable", _fail_if_called)

    result = blocker.disable(
        CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=0
    )

    assert result.success is False
    assert "last remaining keyboard" in result.reason


def test_disable_refuses_non_usb_without_calling_pnputil(blocker, monkeypatch):
    monkeypatch.setattr(blocker_module, "_pnputil_disable", _fail_if_called)

    result = blocker.disable(
        CHILD_ID, is_usb=False, allowlist=[], other_enabled_keyboard_count=1
    )

    assert result.success is False


def test_disable_refuses_when_not_elevated(tmp_path, monkeypatch):
    monkeypatch.setattr(blocker_module, "is_elevated", lambda: False)
    monkeypatch.setattr(blocker_module, "_pnputil_disable", _fail_if_called)
    local_blocker = DeviceBlocker(disabled_devices_path=tmp_path / "disabled_devices.json")

    result = local_blocker.disable(
        CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1
    )

    assert result.success is False
    assert "elevated" in result.reason


# --- DeviceBlocker.disable: the real mechanism, mocked -----------------------


def test_disable_succeeds_and_persists_a_record(blocker, monkeypatch, tmp_path):
    monkeypatch.setattr(blocker_module, "_pnputil_disable", lambda instance_id: None)
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda instance_id: False)

    result = blocker.disable(
        CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1, reason="test"
    )

    assert result.success is True
    assert result.disabled_instance_id == CHILD_ID
    assert blocker.is_disabled(CHILD_ID) is True

    persisted = load_disabled_devices(blocker._path)
    assert len(persisted) == 1
    assert persisted[0].requested_instance_id == CHILD_ID
    assert persisted[0].disabled_instance_id == CHILD_ID


def test_disable_falls_back_to_the_parent_when_the_child_is_still_started(blocker, monkeypatch):
    attempted = []

    def fake_disable(instance_id):
        attempted.append(instance_id)

    def fake_status(instance_id):
        # Child never actually disables; parent does.
        return instance_id != PARENT_ID

    monkeypatch.setattr(blocker_module, "_pnputil_disable", fake_disable)
    monkeypatch.setattr(blocker_module, "is_devnode_started", fake_status)
    monkeypatch.setattr(blocker_module, "get_parent_instance_id", lambda instance_id: PARENT_ID)

    result = blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1)

    assert result.success is True
    assert result.disabled_instance_id == PARENT_ID
    assert attempted == [CHILD_ID, PARENT_ID]


def _refuse_every_disable(monkeypatch):
    monkeypatch.setattr(blocker_module, "DISABLE_VERIFY_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(blocker_module, "_pnputil_disable", lambda instance_id: None)
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda instance_id: True)
    monkeypatch.setattr(blocker_module, "get_parent_instance_id", lambda instance_id: PARENT_ID)


def test_a_device_windows_will_not_disable_is_quarantined(blocker, monkeypatch, tmp_path):
    _refuse_every_disable(monkeypatch)

    result = blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1)

    assert result.success is True
    assert result.quarantined is True
    assert result.disabled_instance_id == CHILD_ID
    assert blocker.is_disabled(CHILD_ID) is True
    assert blocker.is_quarantined(CHILD_ID) is True
    assert blocker.blocked_instance_ids == [CHILD_ID]
    # Persisted, so release-all from another process can see and clear it.
    [record] = load_disabled_devices(tmp_path / "disabled_devices.json")
    assert record.quarantined is True


def test_unblocking_a_quarantined_device_never_calls_pnputil(blocker, monkeypatch):
    _refuse_every_disable(monkeypatch)
    blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1)
    monkeypatch.setattr(blocker_module, "_pnputil_enable", _fail_if_called)

    assert blocker.enable(CHILD_ID) is True
    assert blocker.is_disabled(CHILD_ID) is False
    assert blocker.is_quarantined(CHILD_ID) is False


def test_a_quarantine_still_respects_the_safety_rails(blocker, monkeypatch):
    _refuse_every_disable(monkeypatch)

    last_keyboard = blocker.disable(
        CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=0
    )
    allowlisted = blocker.disable(
        CHILD_ID, is_usb=True, allowlist=[CHILD_ID], other_enabled_keyboard_count=1
    )

    assert not last_keyboard.success
    assert not allowlisted.success
    assert blocker.is_disabled(CHILD_ID) is False


def test_quarantines_are_released_by_release_all_and_auto_release(blocker, monkeypatch):
    _refuse_every_disable(monkeypatch)
    monkeypatch.setattr(blocker_module, "_pnputil_enable", _fail_if_called)
    blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1)
    assert blocker.release_all() == [CHILD_ID]

    blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1)
    later = datetime.now(UTC) + timedelta(days=1)
    assert blocker.check_auto_release(now=later) == [CHILD_ID]
    assert blocker.blocked_instance_ids == []


def test_a_record_without_the_quarantined_field_loads_as_disabled():
    record = DisabledDeviceRecord.from_json(
        {
            "requested_instance_id": CHILD_ID,
            "disabled_instance_id": PARENT_ID,
            "reason": "test",
            "disabled_at": "2026-01-01T00:00:00+00:00",
            "auto_release_at": "2026-01-01T00:10:00+00:00",
        }
    )
    assert record.quarantined is False


def test_disable_dry_run_never_calls_pnputil_and_persists_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(blocker_module, "is_elevated", lambda: True)
    monkeypatch.setattr(blocker_module, "_pnputil_disable", _fail_if_called)
    path = tmp_path / "disabled_devices.json"
    dry_run_blocker = DeviceBlocker(dry_run=True, disabled_devices_path=path)

    result = dry_run_blocker.disable(
        CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1
    )

    assert result.success is True
    assert result.dry_run is True
    assert dry_run_blocker.is_disabled(CHILD_ID) is False
    assert not path.exists()


def test_disable_is_idempotent_for_an_already_disabled_device(blocker, monkeypatch):
    calls = []
    monkeypatch.setattr(blocker_module, "_pnputil_disable", lambda i: calls.append(i))
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: False)

    first = blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1)
    second = blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1)

    assert first.success is True
    assert second.success is True
    assert second.reason == "already blocked"
    assert calls == [CHILD_ID]  # pnputil was only invoked once


# --- enable / release_all / auto-release -------------------------------------


def test_enable_calls_pnputil_and_removes_the_record(blocker, monkeypatch):
    monkeypatch.setattr(blocker_module, "_pnputil_disable", lambda i: None)
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: False)
    blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1)

    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: True)
    enable_calls = []
    monkeypatch.setattr(blocker_module, "_pnputil_enable", lambda i: enable_calls.append(i))

    assert blocker.enable(CHILD_ID) is True
    assert enable_calls == [CHILD_ID]
    assert blocker.is_disabled(CHILD_ID) is False


def test_enable_returns_false_for_an_unknown_device(blocker):
    assert blocker.enable("not-a-tracked-device") is False


def test_release_all_releases_every_device_regardless_of_its_own_timer(blocker, monkeypatch):
    monkeypatch.setattr(blocker_module, "_pnputil_disable", lambda i: None)
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: False)
    blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=2)
    blocker.disable(PARENT_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=2)

    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: True)
    monkeypatch.setattr(blocker_module, "_pnputil_enable", lambda i: None)

    released = blocker.release_all()

    assert set(released) == {CHILD_ID, PARENT_ID}
    assert blocker.disabled_instance_ids == []


def test_check_auto_release_only_releases_expired_entries(blocker, monkeypatch):
    monkeypatch.setattr(blocker_module, "_pnputil_disable", lambda i: None)
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: False)
    blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=2)
    blocker.disable(PARENT_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=2)

    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: True)
    monkeypatch.setattr(blocker_module, "_pnputil_enable", lambda i: None)

    # Manually age one record past its auto-release time, leave the other fresh.
    blocker._records[CHILD_ID].auto_release_at = datetime.now(UTC) - timedelta(seconds=1)
    blocker._records[PARENT_ID].auto_release_at = datetime.now(UTC) + timedelta(hours=1)

    released = blocker.check_auto_release()

    assert released == [CHILD_ID]
    assert blocker.is_disabled(CHILD_ID) is False
    assert blocker.is_disabled(PARENT_ID) is True


def test_a_fake_clock_drives_auto_release(blocker, monkeypatch):
    monkeypatch.setattr(blocker_module, "_pnputil_disable", lambda i: None)
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: False)
    blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1)

    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: True)
    monkeypatch.setattr(blocker_module, "_pnputil_enable", lambda i: None)

    too_early = blocker._records[CHILD_ID].disabled_at + timedelta(seconds=1)
    assert blocker.check_auto_release(now=too_early) == []

    just_after = blocker._records[CHILD_ID].auto_release_at + timedelta(seconds=1)
    assert blocker.check_auto_release(now=just_after) == [CHILD_ID]


# --- persistence survives across process restarts ----------------------------


def test_a_crash_cannot_strand_a_disabled_device(tmp_path, monkeypatch):
    monkeypatch.setattr(blocker_module, "is_elevated", lambda: True)
    monkeypatch.setattr(blocker_module, "_pnputil_disable", lambda i: None)
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: False)

    path = tmp_path / "disabled_devices.json"
    first_process_blocker = DeviceBlocker(disabled_devices_path=path)
    first_process_blocker.disable(
        CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1
    )
    # The process "crashes" here: no clean shutdown, no release_all().

    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: True)
    monkeypatch.setattr(blocker_module, "_pnputil_enable", lambda i: None)

    second_process_blocker = DeviceBlocker(disabled_devices_path=path)
    assert second_process_blocker.is_disabled(CHILD_ID) is True

    released = second_process_blocker.release_all()
    assert released == [CHILD_ID]


def test_save_and_load_disabled_devices_roundtrip(tmp_path):
    path = tmp_path / "disabled_devices.json"
    now = datetime.now(UTC)
    records = [
        DisabledDeviceRecord(
            requested_instance_id=CHILD_ID,
            disabled_instance_id=CHILD_ID,
            reason="test",
            disabled_at=now,
            auto_release_at=now + timedelta(minutes=10),
        )
    ]

    save_disabled_devices(path, records)
    loaded = load_disabled_devices(path)

    assert len(loaded) == 1
    assert loaded[0].requested_instance_id == CHILD_ID
    assert loaded[0].reason == "test"


def test_load_disabled_devices_missing_file_returns_empty_list(tmp_path):
    assert load_disabled_devices(tmp_path / "does-not-exist.json") == []


# --- releases made by another process (--release-all while the runtime runs) --


def _disable_one(blocker, monkeypatch):
    monkeypatch.setattr(blocker_module, "_pnputil_disable", lambda i: None)
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: False)
    result = blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1)
    assert result.success


def test_forget_released_elsewhere_drops_a_record_another_process_released(
    blocker, monkeypatch, tmp_path
):
    _disable_one(blocker, monkeypatch)
    # A second blocker (python -m continuum.runtime --release-all) re-enables it.
    other = DeviceBlocker(disabled_devices_path=tmp_path / "disabled_devices.json")
    monkeypatch.setattr(blocker_module, "_pnputil_enable", lambda i: None)
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: True)
    assert other.release_all() == [CHILD_ID]

    assert blocker.forget_released_elsewhere() == [CHILD_ID]
    assert not blocker.is_disabled(CHILD_ID)


def test_forget_released_elsewhere_keeps_a_device_that_is_still_disabled(
    blocker, monkeypatch, tmp_path
):
    _disable_one(blocker, monkeypatch)
    # The file lost its entry, but the device is still disabled: keep tracking it,
    # so auto-release can still re-enable it.
    (tmp_path / "disabled_devices.json").unlink()

    assert blocker.forget_released_elsewhere() == []
    assert blocker.is_disabled(CHILD_ID)


def test_forget_released_elsewhere_keeps_records_still_on_disk(blocker, monkeypatch):
    _disable_one(blocker, monkeypatch)
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: True)

    assert blocker.forget_released_elsewhere() == []
    assert blocker.is_disabled(CHILD_ID)


def test_disable_succeeds_when_the_status_changes_a_moment_later(blocker, monkeypatch):
    monkeypatch.setattr(blocker_module, "DISABLE_VERIFY_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(blocker_module, "_pnputil_disable", lambda i: None)
    statuses = iter([True, True, False])
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: next(statuses))

    result = blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1)

    assert result.success
    assert result.disabled_instance_id == CHILD_ID


def test_a_refused_disable_is_checked_once_not_polled(blocker, monkeypatch):
    # pnputil refused (keyboards are "critical system devices"): waiting cannot
    # help, and every moment spent waiting is more keystrokes before the fallback.
    class _Refused:
        returncode = 3758096945
        stdout = "Failed to disable device: Cannot disable critical system device."
        stderr = ""

    checks = []
    sleeps = []
    monkeypatch.setattr(blocker_module, "_pnputil_disable", lambda i: _Refused())
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda i: checks.append(i) or True)
    monkeypatch.setattr(blocker_module, "get_parent_instance_id", lambda i: PARENT_ID)
    monkeypatch.setattr(blocker_module.time, "sleep", sleeps.append)

    result = blocker.disable(CHILD_ID, is_usb=True, allowlist=[], other_enabled_keyboard_count=1)

    assert result.quarantined
    assert checks == [CHILD_ID, PARENT_ID]
    assert sleeps == []
