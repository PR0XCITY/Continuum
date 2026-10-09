"""Tests for continuum.common.schemas.

Covers a valid and an invalid case for every model, with extra emphasis
on the one rule that must never break: a KeyEvent can carry no
information about which key was pressed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from continuum.common import (
    ActionTaken,
    AttackPattern,
    DetectionResult,
    DeviceInfo,
    FeatureWindow,
    IncidentRecord,
    KeyEvent,
    RecommendedFollowup,
)


def _device_kwargs(**overrides: object) -> dict:
    base = dict(
        device_id="hid-0001",
        vendor_id="046D",
        product_id="C52B",
        name="Logitech USB Receiver",
        bus_type="USB",
        is_usb=True,
        instance_id=r"HID\VID_046D&PID_C52B\6&1a2b3c4d&0&0000",
        first_seen=datetime(2026, 1, 1, tzinfo=UTC),
    )
    base.update(overrides)
    return base


def _feature_window_kwargs(**overrides: object) -> dict:
    base = dict(
        device_id="hid-0001",
        window_start_ns=1_000_000,
        n_events=40,
        features={"mean_interval_ms": 85.2, "stdev_interval_ms": 12.4},
    )
    base.update(overrides)
    return base


# --- KeyEvent -----------------------------------------------------------


def test_key_event_valid():
    event = KeyEvent(
        device_id="hid-0001",
        timestamp_ns=123_456_789,
        event_type="down",
        press_id=1,
        is_repeat=False,
    )
    assert event.event_type == "down"
    assert event.press_id == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"event_type": "sideways"},
        {"timestamp_ns": -1},
        {"press_id": -1},
        {"device_id": ""},
    ],
)
def test_key_event_invalid_field_values(overrides):
    kwargs = dict(
        device_id="hid-0001",
        timestamp_ns=1,
        event_type="down",
        press_id=1,
        is_repeat=False,
    )
    kwargs.update(overrides)
    with pytest.raises(ValidationError):
        KeyEvent(**kwargs)


def test_key_event_rejects_unknown_field():
    with pytest.raises(ValidationError):
        KeyEvent(
            device_id="hid-0001",
            timestamp_ns=1,
            event_type="down",
            press_id=1,
            is_repeat=False,
            extra_field="not allowed",
        )


@pytest.mark.parametrize("forbidden_field", ["key", "char", "vk", "scan_code"])
def test_key_event_rejects_key_content_fields(forbidden_field):
    kwargs = dict(
        device_id="hid-0001",
        timestamp_ns=1,
        event_type="down",
        press_id=1,
        is_repeat=False,
    )
    kwargs[forbidden_field] = "a"
    with pytest.raises(ValidationError):
        KeyEvent(**kwargs)


# --- DeviceInfo -----------------------------------------------------------


def test_device_info_valid():
    device = DeviceInfo(**_device_kwargs())
    assert device.is_usb is True
    assert device.first_seen.tzinfo is not None


def test_device_info_rejects_bad_vendor_id():
    with pytest.raises(ValidationError):
        DeviceInfo(**_device_kwargs(vendor_id="not-hex"))


def test_device_info_rejects_bus_type_is_usb_mismatch():
    with pytest.raises(ValidationError):
        DeviceInfo(**_device_kwargs(bus_type="USB", is_usb=False))


def test_device_info_rejects_naive_first_seen():
    with pytest.raises(ValidationError):
        DeviceInfo(**_device_kwargs(first_seen=datetime(2026, 1, 1)))


def test_device_info_rejects_unknown_field():
    with pytest.raises(ValidationError):
        DeviceInfo(**_device_kwargs(serial_number="abc123"))


# --- FeatureWindow --------------------------------------------------------


def test_feature_window_valid():
    window = FeatureWindow(**_feature_window_kwargs())
    assert window.n_events == 40
    assert window.features["mean_interval_ms"] == 85.2


def test_feature_window_rejects_zero_events():
    with pytest.raises(ValidationError):
        FeatureWindow(**_feature_window_kwargs(n_events=0))


def test_feature_window_rejects_bool_feature_value():
    with pytest.raises(ValidationError):
        FeatureWindow(**_feature_window_kwargs(features={"is_fast": True}))


def test_feature_window_rejects_unknown_field():
    with pytest.raises(ValidationError):
        FeatureWindow(**_feature_window_kwargs(device_name="keyboard"))


# --- DetectionResult -------------------------------------------------------


def test_detection_result_valid():
    result = DetectionResult(
        device_id="hid-0001",
        anomaly_score=0.91,
        threshold=0.65,
        verdict="suspicious",
        window=FeatureWindow(**_feature_window_kwargs()),
        model_version="isoforest-2026.01",
    )
    assert result.verdict == "suspicious"
    assert result.window.device_id == "hid-0001"


def test_detection_result_rejects_bad_verdict():
    with pytest.raises(ValidationError):
        DetectionResult(
            device_id="hid-0001",
            anomaly_score=0.91,
            threshold=0.65,
            verdict="definitely_an_attack",
            window=FeatureWindow(**_feature_window_kwargs()),
            model_version="isoforest-2026.01",
        )


def test_detection_result_rejects_unknown_field():
    with pytest.raises(ValidationError):
        DetectionResult(
            device_id="hid-0001",
            anomaly_score=0.91,
            threshold=0.65,
            verdict="blocked",
            window=FeatureWindow(**_feature_window_kwargs()),
            model_version="isoforest-2026.01",
            confidence=0.5,
        )


# --- IncidentRecord --------------------------------------------------------


def _incident_kwargs(**overrides: object) -> dict:
    base = dict(
        detected_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        device=DeviceInfo(**_device_kwargs()),
        anomaly_score=0.95,
        threshold=0.65,
        verdict="blocked",
        attack_pattern=AttackPattern.BURST_INJECTION,
        features_summary={"mean_interval_ms": 1.2},
        action_taken=ActionTaken.LOCKED_AND_DISABLED,
        time_to_detect_ms=120,
        recommended_followups=[
            RecommendedFollowup.ISOLATE_DEVICE,
            RecommendedFollowup.NOTIFY_SECURITY_TEAM,
        ],
        notes="Device disabled after burst-speed input detected.",
    )
    base.update(overrides)
    return base


def test_incident_record_valid():
    incident = IncidentRecord(**_incident_kwargs())
    assert isinstance(incident.incident_id, UUID)
    assert incident.mitre_technique == "T1200 Hardware Additions"
    assert incident.detected_at.tzinfo is not None
    assert incident.notes == "Device disabled after burst-speed input detected."


def test_incident_record_sanitises_and_limits_notes():
    dirty_notes = "line one\x00\x07" + "\x1b" + "line two" + ("!" * 20)
    incident = IncidentRecord(**_incident_kwargs(notes=dirty_notes))
    assert "\x00" not in incident.notes
    assert "\x07" not in incident.notes
    assert incident.notes == "line oneline two" + ("!" * 20)
    assert len(incident.notes) <= 280


def test_incident_record_rejects_notes_too_long_after_sanitising():
    with pytest.raises(ValidationError):
        IncidentRecord(**_incident_kwargs(notes="x" * 281))


def test_incident_record_rejects_naive_detected_at():
    with pytest.raises(ValidationError):
        IncidentRecord(**_incident_kwargs(detected_at=datetime(2026, 1, 1, 12, 0, 0)))


def test_incident_record_rejects_bad_attack_pattern():
    with pytest.raises(ValidationError):
        IncidentRecord(**_incident_kwargs(attack_pattern="hacker_man"))


def test_incident_record_rejects_bad_action_taken():
    with pytest.raises(ValidationError):
        IncidentRecord(**_incident_kwargs(action_taken="shrugged"))


def test_incident_record_rejects_bad_recommended_followup():
    with pytest.raises(ValidationError):
        IncidentRecord(**_incident_kwargs(recommended_followups=["call_the_police"]))


def test_incident_record_dedupes_recommended_followups():
    incident = IncidentRecord(
        **_incident_kwargs(
            recommended_followups=[
                RecommendedFollowup.ISOLATE_DEVICE,
                RecommendedFollowup.ISOLATE_DEVICE,
            ]
        )
    )
    assert incident.recommended_followups == [RecommendedFollowup.ISOLATE_DEVICE]


def test_incident_record_rejects_bool_feature_summary_value():
    with pytest.raises(ValidationError):
        IncidentRecord(**_incident_kwargs(features_summary={"is_attack": True}))


def test_incident_record_rejects_negative_time_to_detect():
    with pytest.raises(ValidationError):
        IncidentRecord(**_incident_kwargs(time_to_detect_ms=-5))


def test_incident_record_rejects_unknown_field():
    with pytest.raises(ValidationError):
        IncidentRecord(**_incident_kwargs(raw_keystrokes="hello"))


@pytest.mark.parametrize("forbidden_field", ["key", "char", "vk", "scan_code"])
def test_incident_record_rejects_key_content_fields(forbidden_field):
    kwargs = _incident_kwargs()
    kwargs[forbidden_field] = "a"
    with pytest.raises(ValidationError):
        IncidentRecord(**kwargs)
