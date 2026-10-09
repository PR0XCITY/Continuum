"""Pydantic v2 schemas shared across Continuum.

Responsibility: define the validated data shapes that cross module and
process boundaries, including:

    KeyEvent        A single capture-thread event: timestamp, event type
                    (down/up), per-session press counter and device
                    identifier. Deliberately has no field for which key or
                    character was involved; see CLAUDE.md, "never a
                    keylogger".
    DeviceInfo      Stable identifier and metadata for a physical HID device
                    (vendor id, product id, interface path, display name).
    FeatureWindow   One windowed batch of per-device cadence features.
    DetectionResult Output of the detection pipeline for a device/window:
                    score, threshold, decision and the feature snapshot that
                    produced it.
    IncidentRecord  The schema-validated record written by the connector
                    for every block/unblock action. This is the only shape
                    that may enter the RAG corpus.

No business logic lives here, only schema definitions and validators.
Every model inherits StrictModel, which rejects unknown fields outright,
so a typo or an attempted extra field, including an attempt to smuggle in
key content, fails validation instead of being silently accepted or
dropped. Everything written to disk, to SQLite or into the RAG corpus
must round-trip through one of these models; free text from outside the
system is never accepted unvalidated.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import Enum
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Field names that would let key content leak into a model. Rejected
# explicitly, in addition to the generic "extra = forbid" rule, so the
# error message is specific about why the request was refused.
_FORBIDDEN_KEY_CONTENT_FIELDS = frozenset(
    {
        "key",
        "keys",
        "char",
        "character",
        "chars",
        "text",
        "vk",
        "vk_code",
        "virtual_key",
        "scan_code",
        "scancode",
        "key_code",
        "keycode",
    }
)

# Matches ASCII control characters (C0 and DEL), but not the printable
# range. Used to sanitise free text before it is persisted anywhere.
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

EventType = Literal["down", "up"]
Verdict = Literal["normal", "suspicious", "blocked"]
BusType = Literal["USB", "PS2", "Bluetooth", "Unknown"]

_HEX_ID_PATTERN = r"^[0-9A-Fa-f]{4}$"


class AttackPattern(str, Enum):
    """Shape of a confirmed injection attack, for incident triage."""

    BURST_INJECTION = "burst_injection"
    SLOWED_INJECTION = "slowed_injection"
    RANDOMIZED_INJECTION = "randomized_injection"
    UNKNOWN = "unknown"


class ActionTaken(str, Enum):
    """What the response layer actually did about an incident."""

    DEVICE_DISABLED = "device_disabled"
    WORKSTATION_LOCKED = "workstation_locked"
    LOCKED_AND_DISABLED = "locked_and_disabled"
    ALERT_ONLY = "alert_only"
    NONE = "none"


class RecommendedFollowup(str, Enum):
    """Fixed, allowed set of short incident-response follow-up actions."""

    ISOLATE_DEVICE = "isolate_device"
    INSPECT_USB_PORTS = "inspect_usb_ports"
    ROTATE_CREDENTIALS = "rotate_credentials"
    REVIEW_PHYSICAL_ACCESS_LOGS = "review_physical_access_logs"
    CAPTURE_FORENSIC_IMAGE = "capture_forensic_image"
    NOTIFY_SECURITY_TEAM = "notify_security_team"
    UPDATE_DEVICE_ALLOWLIST = "update_device_allowlist"
    NO_ACTION_REQUIRED = "no_action_required"


class StrictModel(BaseModel):
    """Base model: unknown fields are always rejected, never ignored."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class KeyEvent(StrictModel):
    """One capture-thread event. Carries no key identity, ever.

    Only a timestamp, event type, per-session press counter and device
    identifier may appear here. There is no field for a key code, scan
    code, character or virtual-key value, and none may be added; see
    CLAUDE.md, "never a keylogger".
    """

    device_id: str = Field(min_length=1, max_length=256)
    timestamp_ns: int = Field(ge=0, description="Monotonic clock reading, in nanoseconds.")
    event_type: EventType
    press_id: int = Field(
        ge=0,
        description="Monotonic, in-memory counter pairing a key-down with its key-up.",
    )
    is_repeat: bool = Field(description="True for an OS auto-repeat key-down.")

    @model_validator(mode="before")
    @classmethod
    def _reject_key_content_fields(cls, data: object) -> object:
        if isinstance(data, dict):
            offending = sorted(_FORBIDDEN_KEY_CONTENT_FIELDS & data.keys())
            if offending:
                raise ValueError(
                    "KeyEvent must never carry key content; "
                    f"rejected field(s): {offending}"
                )
        return data


class DeviceInfo(StrictModel):
    """Stable identity and metadata for one physical HID device."""

    device_id: str = Field(min_length=1, max_length=256)
    vendor_id: str = Field(pattern=_HEX_ID_PATTERN, description="4 hex digits, e.g. 046D.")
    product_id: str = Field(pattern=_HEX_ID_PATTERN, description="4 hex digits, e.g. C52B.")
    name: str = Field(min_length=1, max_length=256)
    bus_type: BusType
    is_usb: bool
    instance_id: str = Field(
        min_length=1,
        max_length=512,
        description="Windows PnP device instance id, used to disable/enable via pnputil.",
    )
    first_seen: datetime

    @field_validator("first_seen")
    @classmethod
    def _require_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("first_seen must be timezone-aware (UTC)")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _check_bus_type_matches_is_usb(self) -> DeviceInfo:
        if self.bus_type == "USB" and not self.is_usb:
            raise ValueError("is_usb must be True when bus_type is 'USB'")
        if self.bus_type != "USB" and self.is_usb:
            raise ValueError("is_usb must be False when bus_type is not 'USB'")
        return self


class FeatureWindow(StrictModel):
    """One windowed batch of per-device cadence features."""

    device_id: str = Field(min_length=1, max_length=256)
    window_start_ns: int = Field(ge=0)
    n_events: int = Field(ge=1)
    features: dict[str, float] = Field(default_factory=dict)

    @field_validator("features", mode="before")
    @classmethod
    def _reject_bool_values(cls, value: object) -> object:
        if isinstance(value, dict):
            for name, number in value.items():
                if not name:
                    raise ValueError("feature names must be non-empty")
                if isinstance(number, bool):
                    raise ValueError(f"feature {name!r} must be numeric, not bool")
        return value


class DetectionResult(StrictModel):
    """Output of the detection pipeline for one device/window pair."""

    device_id: str = Field(min_length=1, max_length=256)
    anomaly_score: float = Field(description="Higher means more anomalous.")
    threshold: float
    verdict: Verdict
    window: FeatureWindow
    model_version: str = Field(min_length=1, max_length=64)


class IncidentRecord(StrictModel):
    """The contract between the HID Firewall and IncidentRAG.

    This is the only shape that may enter the RAG corpus. Free text from
    outside the system is never accepted here unvalidated; notes is
    sanitised and length-limited, and every enum field is restricted to
    its fixed, allowed set of values.
    """

    incident_id: UUID = Field(default_factory=uuid4)
    detected_at: datetime
    device: DeviceInfo
    anomaly_score: float
    threshold: float
    verdict: Verdict
    attack_pattern: AttackPattern
    features_summary: dict[str, float] = Field(default_factory=dict)
    action_taken: ActionTaken
    time_to_detect_ms: int = Field(ge=0)
    mitre_technique: str = Field(default="T1200 Hardware Additions", max_length=128)
    recommended_followups: list[RecommendedFollowup] = Field(default_factory=list)
    notes: str = Field(default="", max_length=280)

    @field_validator("detected_at")
    @classmethod
    def _require_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("detected_at must be timezone-aware (UTC)")
        return value.astimezone(UTC)

    @field_validator("features_summary", mode="before")
    @classmethod
    def _reject_bool_values(cls, value: object) -> object:
        if isinstance(value, dict):
            for name, number in value.items():
                if isinstance(number, bool):
                    raise ValueError(f"features_summary {name!r} must be numeric, not bool")
        return value

    @field_validator("notes", mode="before")
    @classmethod
    def _sanitise_notes(cls, value: object) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            raise ValueError("notes must be a string")
        return _CONTROL_CHAR_PATTERN.sub("", value).strip()

    @field_validator("recommended_followups")
    @classmethod
    def _dedupe_followups(
        cls, value: list[RecommendedFollowup]
    ) -> list[RecommendedFollowup]:
        deduped: list[RecommendedFollowup] = []
        for item in value:
            if item not in deduped:
                deduped.append(item)
        return deduped
