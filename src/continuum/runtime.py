"""Runtime entry point: wires capture, detection and response together.

Responsibility: construct the capture backend via capture.factory, turn
its queued KeyEvent stream into FeatureWindow objects per device, score
each window with detection.scorer, and on a "blocked" verdict call into
response (lock first, then disable), build an IncidentRecord and get it
to the connector API, retrying through a local SQLite outbox when that
API is unreachable. This is the process meant to run elevated,
continuously, as the HID Firewall.

Usage:
    python -m continuum.runtime                 # run the HID Firewall
    python -m continuum.runtime --release-all    # kill switch; exits

Intentionally kept separate from connector.app and dashboard.app so the
elevated runtime process never needs to run a web server, and the web
processes never need elevation.
"""

from __future__ import annotations

import argparse
import dataclasses
import getpass
import json
import os
import queue
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from continuum.capture.base import CaptureSource
from continuum.capture.factory import create_capture_source
from continuum.common.config import Settings, get_settings
from continuum.common.logging import configure_logging, get_logger
from continuum.common.schemas import (
    SOFTWARE_INPUT_DEVICE_ID,
    TRIAL_MS_TO_BLOCK,
    TRIAL_MS_TO_LOCK,
    TRIAL_MS_TO_RESPONSE,
    TRIAL_PRESSES_TO_BLOCK,
    ActionTaken,
    AttackPattern,
    DetectionResult,
    DeviceInfo,
    IncidentRecord,
    KeyEvent,
    RecommendedFollowup,
)
from continuum.connector.db import (
    COMMANDS_TABLE,
    LIVE_SNAPSHOTS_TABLE,
    RUNTIME_STATUS_ROW_ID,
    RUNTIME_STATUS_TABLE,
    resolve_database_path,
)
from continuum.detection.features import (
    DEFAULT_PAUSE_SPLIT_SECONDS,
    DEFAULT_WINDOW_SIZE,
    DEFAULT_WINDOW_STEP,
    iter_feature_windows,
)
from continuum.detection.model import CadenceModel, model_path
from continuum.detection.scorer import Scorer, threshold_offset_for_sensitivity
from continuum.recording import (
    BaselineRecorder,
    fail_abandoned_sessions,
    poll_baseline_commands,
    save_active_recording,
)
from continuum.remote_guard import RemoteGuard
from continuum.response.alerts import notify
from continuum.response.blocker_windows import (
    DEFAULT_DISABLED_DEVICES_PATH,
    BlockResult,
    DeviceBlocker,
    is_elevated,
)
from continuum.response.lockscreen import lock_workstation

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_OUTBOX_PATH = _REPO_ROOT / "data" / "db" / "incident_outbox.sqlite3"

# `tasks.ps1 stop-all` creates this file to ask a running runtime to shut
# down cleanly. A file works across the elevation boundary, where an
# ordinary window cannot signal or kill an elevated process.
STOP_REQUEST_PATH = _REPO_ROOT / "data" / "run" / "runtime.stop"

MAX_BUFFER_EVENTS = 2000
TRIM_TO_EVENTS = 500
MAINTENANCE_INTERVAL_SECONDS = 5.0
# Training commands from the dashboard are polled faster than maintenance,
# so Start and Stop on the Train page take effect within about a second.
COMMAND_POLL_INTERVAL_SECONDS = 1.0
NO_MODEL_VERSION = "none"
CAPTURE_POLL_TIMEOUT_SECONDS = 0.5

OUTBOX_BASE_BACKOFF_SECONDS = 5.0
OUTBOX_MAX_BACKOFF_SECONDS = 300.0
OUTBOX_BATCH_LIMIT = 20

HTTP_TIMEOUT_SECONDS = 5.0
INCIDENTS_ENDPOINT = "/incidents"

logger = get_logger("runtime")


# --- per-device streaming window state ---------------------------------------


@dataclass
class _DeviceBuffer:
    events: list[KeyEvent] = field(default_factory=list)
    n_windows_emitted: int = 0
    # Since this device's first key press (or its last block): counts and
    # clock readings only, for the timing figures recorded on an incident.
    first_press_ns: int | None = None
    presses_seen: int = 0


def _trim_buffer_if_needed(buffer: _DeviceBuffer, device_id: str) -> None:
    if len(buffer.events) <= MAX_BUFFER_EVENTS:
        return
    buffer.events = buffer.events[-TRIM_TO_EVENTS:]
    buffer.n_windows_emitted = len(list(iter_feature_windows(buffer.events, device_id)))


# --- incident building ---------------------------------------------------------


def classify_attack_pattern(features: dict[str, float]) -> AttackPattern:
    """A simple, documented heuristic for incident triage, not detection.

    Detection already happened (the scorer flagged this window); this
    only picks a human-readable label for the incident record.
    """
    burst_score = features.get("burst_score", 0.0)
    flight_cv = features.get("flight_cv", 1.0)
    regularity = features.get("regularity_ratio", 0.0)

    if burst_score > 0.8:
        return AttackPattern.BURST_INJECTION
    if flight_cv < 0.05 and regularity > 0.8:
        return AttackPattern.SLOWED_INJECTION
    if flight_cv < 0.4:
        return AttackPattern.RANDOMIZED_INJECTION
    return AttackPattern.UNKNOWN


def build_incident(
    result: DetectionResult,
    device: DeviceInfo,
    *,
    action_taken: ActionTaken,
    time_to_detect_ms: int,
    trial_timings: dict[str, float] | None = None,
) -> IncidentRecord:
    pattern = classify_attack_pattern(result.window.features)

    followups = [
        RecommendedFollowup.ISOLATE_DEVICE,
        RecommendedFollowup.REVIEW_PHYSICAL_ACCESS_LOGS,
    ]
    if action_taken in (
        ActionTaken.DEVICE_DISABLED,
        ActionTaken.LOCKED_AND_DISABLED,
        ActionTaken.LOCKED_AND_QUARANTINED,
    ):
        followups.append(RecommendedFollowup.NOTIFY_SECURITY_TEAM)

    notes = (
        f"Device {device.name!r} flagged with anomaly_score="
        f"{result.anomaly_score:.3f} (threshold {result.threshold:.3f}); "
        f"pattern classified as {pattern.value}."
    )

    # window_n_events rides along in features_summary (a free-form numeric
    # dict already) rather than as a new schema field, so hardware trials
    # (see tools/run_hardware_trial.py) have a "keystrokes at detection"
    # figure: the number of events in the window that triggered the block.
    features_summary = dict(result.window.features)
    features_summary["window_n_events"] = float(result.window.n_events)
    # Measured from this device's first key press: see trial_timing_summary.
    features_summary.update(trial_timings or {})

    return IncidentRecord(
        detected_at=datetime.now(UTC),
        device=device,
        anomaly_score=result.anomaly_score,
        threshold=result.threshold,
        verdict=result.verdict,
        attack_pattern=pattern,
        features_summary=features_summary,
        action_taken=action_taken,
        time_to_detect_ms=max(time_to_detect_ms, 0),
        recommended_followups=followups,
        notes=notes,
    )


# --- response (lock first, then disable) -------------------------------------


def other_enabled_keyboard_count(
    capture: CaptureSource, blocker: DeviceBlocker, exclude_device_id: str
) -> int:
    disabled_ids = set(blocker.disabled_instance_ids)
    return sum(
        1
        for device in capture.list_devices()
        if device.device_id != exclude_device_id and device.instance_id not in disabled_ids
    )


def respond_to_block(
    device: DeviceInfo,
    result: DetectionResult,
    *,
    effective_mode: str,
    blocker: DeviceBlocker,
    allowlist: list[str],
    other_enabled_keyboard_count_value: int,
    timings: dict[str, float] | None = None,
) -> ActionTaken:
    """Contain the device according to the response mode.

    lock_and_disable locks first, then disables: fastest containment,
    but the device keeps typing into the lock screen's password box
    until the disable lands. disable_only disables the device and leaves
    the session unlocked, locking only as a fallback when the disable
    fails or a safety rail refuses it, so an attack is never left
    running unchecked.

    Windows refuses to disable a keyboard in use, so the disable usually
    ends as a quarantine (see DeviceBlocker.disable): the device stays
    connected but Continuum treats it as blocked, locking on any further
    keystroke from it. A quarantine always comes with a lock, since the
    device can still type.

    If timings is given, the wall time spent locking and disabling, in
    milliseconds from the start of this call, is written into it.
    """
    locked = False
    disabled = False
    quarantined = False
    started = time.perf_counter()

    def lock() -> bool:
        done = lock_workstation()
        if timings is not None:
            timings["lock_done_ms"] = (time.perf_counter() - started) * 1000
        return done

    def disable() -> BlockResult:
        return blocker.disable(
            device.instance_id,
            is_usb=device.is_usb,
            allowlist=allowlist,
            other_enabled_keyboard_count=other_enabled_keyboard_count_value,
            reason=f"anomaly_score={result.anomaly_score:.3f} threshold={result.threshold:.3f}",
        )

    if effective_mode in ("lock_only", "lock_and_disable"):
        locked = lock()
    if effective_mode in ("lock_and_disable", "disable_only"):
        block = disable()
        quarantined = block.success and block.quarantined
        disabled = block.success and not block.quarantined
    if effective_mode == "disable_only" and not disabled:
        if quarantined:
            logger.warning(
                "Windows would not disable %s; locking and keeping it blocked", device.device_id
            )
        else:
            logger.warning(
                "could not disable %s; locking the workstation instead", device.device_id
            )
        locked = lock()

    if timings is not None:
        timings["response_done_ms"] = (time.perf_counter() - started) * 1000

    if locked and disabled:
        return ActionTaken.LOCKED_AND_DISABLED
    if locked and quarantined:
        return ActionTaken.LOCKED_AND_QUARANTINED
    if locked:
        return ActionTaken.WORKSTATION_LOCKED
    if disabled:
        return ActionTaken.DEVICE_DISABLED
    return ActionTaken.ALERT_ONLY


# --- incident outbox: SQLite queue with retry and backoff --------------------


class IncidentOutbox:
    """A durable local queue for incidents the connector has not accepted yet.

    Used whenever posting to the connector fails for any reason
    (connector down, network error, non-2xx response): the incident is
    never dropped, just queued here and retried with exponential
    backoff by the runtime's maintenance pass.
    """

    def __init__(self, path: Path = DEFAULT_OUTBOX_PATH) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_retry_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def enqueue(self, incident: IncidentRecord) -> None:
        now = datetime.now(UTC)
        self._conn.execute(
            "INSERT INTO outbox (incident_json, created_at, attempts, next_retry_at) "
            "VALUES (?, ?, 0, ?)",
            (incident.model_dump_json(), now.isoformat(), now.isoformat()),
        )
        self._conn.commit()

    def due_entries(
        self, *, now: datetime | None = None, limit: int = OUTBOX_BATCH_LIMIT
    ) -> list[tuple[int, IncidentRecord, int]]:
        current = now if now is not None else datetime.now(UTC)
        cursor = self._conn.execute(
            "SELECT id, incident_json, attempts FROM outbox WHERE next_retry_at <= ? "
            "ORDER BY id LIMIT ?",
            (current.isoformat(), limit),
        )
        return [
            (row[0], IncidentRecord.model_validate_json(row[1]), row[2])
            for row in cursor.fetchall()
        ]

    def mark_sent(self, row_id: int) -> None:
        self._conn.execute("DELETE FROM outbox WHERE id = ?", (row_id,))
        self._conn.commit()

    def mark_retry(self, row_id: int, *, attempts: int) -> None:
        delay_seconds = min(OUTBOX_MAX_BACKOFF_SECONDS, OUTBOX_BASE_BACKOFF_SECONDS * (2**attempts))
        next_retry_at = datetime.now(UTC) + timedelta(seconds=delay_seconds)
        self._conn.execute(
            "UPDATE outbox SET attempts = ?, next_retry_at = ? WHERE id = ?",
            (attempts, next_retry_at.isoformat(), row_id),
        )
        self._conn.commit()

    def __len__(self) -> int:
        cursor = self._conn.execute("SELECT COUNT(*) FROM outbox")
        return int(cursor.fetchone()[0])

    def close(self) -> None:
        self._conn.close()


def post_incident(
    client: httpx.Client, base_url: str, token: str, incident: IncidentRecord
) -> bool:
    """Try once to POST an incident to the connector. True on a 2xx response."""
    try:
        response = client.post(
            f"{base_url}{INCIDENTS_ENDPOINT}",
            content=incident.model_dump_json(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
    except httpx.HTTPError:
        return False
    return 200 <= response.status_code < 300


def post_or_queue_incident(
    outbox: IncidentOutbox,
    client: httpx.Client,
    base_url: str,
    token: str,
    incident: IncidentRecord,
) -> None:
    if post_incident(client, base_url, token, incident):
        logger.info("posted incident %s to the connector", incident.incident_id)
        return
    logger.warning(
        "connector unreachable, queueing incident %s in the outbox", incident.incident_id
    )
    outbox.enqueue(incident)


def drain_outbox(outbox: IncidentOutbox, client: httpx.Client, base_url: str, token: str) -> None:
    for row_id, incident, attempts in outbox.due_entries():
        if post_incident(client, base_url, token, incident):
            outbox.mark_sent(row_id)
            logger.info("outbox: posted queued incident %s", incident.incident_id)
        else:
            outbox.mark_retry(row_id, attempts=attempts + 1)
            logger.debug(
                "outbox: retry %d failed for incident %s", attempts + 1, incident.incident_id
            )


def poll_unblock_commands(connector_db_path: Path, blocker: DeviceBlocker) -> None:
    """Act on pending unblock commands the connector wrote, then mark them done.

    Incidents flow to the connector over HTTP (see post_incident above),
    but unblock commands flow the other way through a table in the
    connector's own SQLite file, written by POST /devices/{id}/unblock
    and read here with plain sqlite3, not SQLAlchemy, so this elevated
    process never needs FastAPI or the rest of the web stack; see
    continuum.connector.db's docstring for the shared schema this must
    match.
    """
    try:
        conn = sqlite3.connect(str(connector_db_path))
    except sqlite3.OperationalError:
        logger.debug("could not open connector db at %s for command polling", connector_db_path)
        return

    try:
        cursor = conn.execute(
            f"SELECT id, device_id FROM {COMMANDS_TABLE} "
            "WHERE command_type = 'unblock' AND status = 'pending'"
        )
        pending = cursor.fetchall()

        for command_id, device_id in pending:
            if blocker.enable(device_id):
                logger.info("released %s on command from the connector", device_id)
            else:
                logger.info("unblock command for %s had nothing to release", device_id)
            conn.execute(
                f"UPDATE {COMMANDS_TABLE} SET status = 'done', completed_at = ? WHERE id = ?",
                (datetime.now(UTC).isoformat(), command_id),
            )
        if pending:
            conn.commit()
    except sqlite3.OperationalError:
        logger.debug("connector db at %s not ready for command polling", connector_db_path)
    finally:
        conn.close()


def update_live_snapshot(connector_db_path: Path, device_id: str, result: DetectionResult) -> None:
    """UPSERT this device's latest status into the connector's shared table.

    Called after every scored window, not just a blocked one, so
    GET /live always reflects current status. Best-effort: a failure
    here (for example the connector has not created its tables yet)
    must never break detection or response.
    """
    try:
        conn = sqlite3.connect(str(connector_db_path))
    except sqlite3.OperationalError:
        logger.debug("could not open connector db at %s for a live snapshot", connector_db_path)
        return

    try:
        conn.execute(
            f"""
            INSERT INTO {LIVE_SNAPSHOTS_TABLE}
                (device_id, verdict, anomaly_score, threshold, features_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                verdict = excluded.verdict,
                anomaly_score = excluded.anomaly_score,
                threshold = excluded.threshold,
                features_json = excluded.features_json,
                updated_at = excluded.updated_at
            """,
            (
                device_id,
                result.verdict,
                result.anomaly_score,
                result.threshold,
                json.dumps(result.window.features),
                datetime.now(UTC).isoformat(),
            ),
        )
        conn.commit()
    except sqlite3.OperationalError:
        logger.debug("connector db at %s not ready for a live snapshot", connector_db_path)
    finally:
        conn.close()


@dataclass(frozen=True)
class RuntimeIdentity:
    """What this runtime process is running with; fixed for its lifetime."""

    started_at: str
    pid: int
    elevated: bool
    configured_mode: str
    effective_mode: str
    dry_run: bool
    model_version: str
    calibrated_threshold: float
    base_threshold: float
    sensitivity: int


def describe_devices(capture: CaptureSource, blocker: DeviceBlocker) -> list[dict[str, object]]:
    """Attached keyboards for the status heartbeat. Identity only, never key content."""
    try:
        devices = capture.list_devices()
    except Exception:
        logger.debug("could not list devices for the status heartbeat", exc_info=True)
        return []
    return [
        {
            "device_id": device.device_id,
            "name": device.name,
            "vendor_id": device.vendor_id,
            "product_id": device.product_id,
            "bus_type": device.bus_type,
            "is_usb": device.is_usb,
            "disabled": blocker.is_disabled(device.instance_id),
            "quarantined": blocker.is_quarantined(device.instance_id),
        }
        for device in devices
    ]


def write_runtime_status(
    connector_db_path: Path,
    identity: RuntimeIdentity,
    *,
    state: str,
    devices: list[dict[str, object]],
) -> None:
    """UPSERT the single runtime_status row: the runtime's heartbeat.

    Best-effort, like update_live_snapshot: a failure here must never
    break detection or response.
    """
    try:
        conn = sqlite3.connect(str(connector_db_path))
    except sqlite3.OperationalError:
        logger.debug("could not open connector db at %s for status", connector_db_path)
        return

    try:
        conn.execute(
            f"""
            INSERT INTO {RUNTIME_STATUS_TABLE}
                (id, state, started_at, heartbeat_at, pid, elevated, configured_mode,
                 effective_mode, dry_run, model_version, calibrated_threshold,
                 base_threshold, sensitivity, devices_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                state = excluded.state,
                started_at = excluded.started_at,
                heartbeat_at = excluded.heartbeat_at,
                pid = excluded.pid,
                elevated = excluded.elevated,
                configured_mode = excluded.configured_mode,
                effective_mode = excluded.effective_mode,
                dry_run = excluded.dry_run,
                model_version = excluded.model_version,
                calibrated_threshold = excluded.calibrated_threshold,
                base_threshold = excluded.base_threshold,
                sensitivity = excluded.sensitivity,
                devices_json = excluded.devices_json
            """,
            (
                RUNTIME_STATUS_ROW_ID,
                state,
                identity.started_at,
                datetime.now(UTC).isoformat(),
                identity.pid,
                identity.elevated,
                identity.configured_mode,
                identity.effective_mode,
                identity.dry_run,
                identity.model_version,
                identity.calibrated_threshold,
                identity.base_threshold,
                identity.sensitivity,
                json.dumps(devices),
            ),
        )
        conn.commit()
    except sqlite3.OperationalError:
        logger.debug("connector db at %s not ready for a status heartbeat", connector_db_path)
    finally:
        conn.close()


def reload_model_if_changed(
    path: Path, loaded_mtime: float | None
) -> tuple[CadenceModel | None, float | None]:
    """A freshly trained model, if the file is new or changed since loaded_mtime.

    Returns (model, its mtime), or (None, mtime) when there is nothing new
    to load. A file that fails to load is logged once and not retried
    until it changes again.
    """
    try:
        mtime = path.stat().st_mtime
    except FileNotFoundError:
        return None, loaded_mtime
    if mtime == loaded_mtime:
        return None, loaded_mtime
    try:
        return CadenceModel.load(path), mtime
    except Exception:
        logger.exception("could not load the model at %s; keeping the current one", path)
        return None, mtime


def consume_stop_request(path: Path | None = None) -> bool:
    """True, and the request file removed, if a clean shutdown was requested."""
    path = STOP_REQUEST_PATH if path is None else path
    if not path.exists():
        return False
    path.unlink(missing_ok=True)
    return True


def trial_timing_summary(
    buffer: _DeviceBuffer, blocking_event: KeyEvent, response_timings: dict[str, float]
) -> dict[str, float]:
    """Timing figures for hardware trials, measured from the device's first press.

    The first press and the blocking event share the capture clock, so
    the block figure excludes any queueing delay before this process saw
    the event; lock and response figures add the measured wall time of
    respond_to_block on top. Lock is omitted when no lock was attempted.
    """
    if buffer.first_press_ns is None:
        return {}
    ms_to_block = (blocking_event.timestamp_ns - buffer.first_press_ns) / 1_000_000
    summary = {
        TRIAL_PRESSES_TO_BLOCK: float(buffer.presses_seen),
        TRIAL_MS_TO_BLOCK: round(ms_to_block, 3),
        TRIAL_MS_TO_RESPONSE: round(
            ms_to_block + response_timings.get("response_done_ms", 0.0), 3
        ),
    }
    if "lock_done_ms" in response_timings:
        summary[TRIAL_MS_TO_LOCK] = round(ms_to_block + response_timings["lock_done_ms"], 3)
    return summary


# --- the main loop ---------------------------------------------------------


# A blocked device mashing keys would otherwise call LockWorkStation
# hundreds of times a second; once per interval is enough to keep the
# session locked.
QUARANTINE_RELOCK_INTERVAL_SECONDS = 2.0


def enforce_quarantine(
    event: KeyEvent,
    locked_at: dict[str, float],
    *,
    now: float | None = None,
) -> bool:
    """Lock the workstation when a quarantined device presses a key.

    Raw Input cannot hold a keystroke back, so the key still arrives,
    but the session locks at once and anything further lands in the
    lock screen's password box. Returns True if a lock was requested.
    """
    if event.event_type != "down" or event.is_repeat:
        return False
    current = time.monotonic() if now is None else now
    last = locked_at.get(event.device_id)
    if last is not None and current - last < QUARANTINE_RELOCK_INTERVAL_SECONDS:
        return False
    locked_at[event.device_id] = current
    logger.warning("blocked device %s typed; locking the workstation", event.device_id)
    lock_workstation()
    return True


def process_event(
    event: KeyEvent,
    *,
    device_buffers: dict[str, _DeviceBuffer],
    pending_since: dict[str, datetime],
    scorer: Scorer | None,
    capture: CaptureSource,
    blocker: DeviceBlocker,
    outbox: IncidentOutbox,
    http_client: httpx.Client,
    base_url: str,
    token: str,
    effective_mode: str,
    allowlist: list[str],
    connector_db_path: Path,
    recorder: BaselineRecorder | None = None,
    quarantine_locked_at: dict[str, float] | None = None,
    remote_guard: RemoteGuard | None = None,
) -> None:
    if quarantine_locked_at is None:
        quarantine_locked_at = {}
    # Typing with no physical keyboard behind it (a remote-access tool or a
    # macro): never scored or recorded as cadence, only checked for
    # remote-access use.
    if event.device_id == SOFTWARE_INPUT_DEVICE_ID:
        if remote_guard is not None:
            incident = remote_guard.handle(event)
            if incident is not None:
                notify(
                    "Continuum: remote typing blocked",
                    f"{incident.device.name}: {incident.action_taken.value}.",
                    device_id=SOFTWARE_INPUT_DEVICE_ID,
                    event_type="remote_access",
                    details={
                        "incident_id": str(incident.incident_id),
                        "action_taken": incident.action_taken.value,
                    },
                )
                post_or_queue_incident(outbox, http_client, base_url, token, incident)
        return
    # Recording a training baseline: collect the typing, never score it, so
    # fast training typing can never trigger a lock or a disable.
    if recorder is not None and recorder.active:
        recorder.record(event)
        return
    if blocker.is_quarantined(event.device_id):
        enforce_quarantine(event, quarantine_locked_at)
        return
    if scorer is None:  # no trained model yet: nothing to detect against
        return

    buffer = device_buffers.setdefault(event.device_id, _DeviceBuffer())
    buffer.events.append(event)
    if event.event_type == "down" and not event.is_repeat:
        if buffer.first_press_ns is None:
            buffer.first_press_ns = event.timestamp_ns
        buffer.presses_seen += 1
    _trim_buffer_if_needed(buffer, event.device_id)

    windows = list(
        iter_feature_windows(
            buffer.events,
            event.device_id,
            window_size=DEFAULT_WINDOW_SIZE,
            window_step=DEFAULT_WINDOW_STEP,
            pause_split_seconds=DEFAULT_PAUSE_SPLIT_SECONDS,
        )
    )
    new_windows = windows[buffer.n_windows_emitted :]
    buffer.n_windows_emitted = len(windows)

    for window in new_windows:
        result = scorer.score_window(window)
        update_live_snapshot(connector_db_path, event.device_id, result)

        if result.verdict == "normal":
            pending_since.pop(event.device_id, None)
            continue

        pending_since.setdefault(event.device_id, datetime.now(UTC))

        if result.verdict == "suspicious":
            logger.info(
                "suspicious window on %s: score=%.3f", event.device_id, result.anomaly_score
            )
            continue

        # verdict == "blocked"
        device = next(
            (d for d in capture.list_devices() if d.device_id == event.device_id), None
        )
        if device is None:
            logger.error(
                "blocked verdict for unknown device %s, cannot respond fully", event.device_id
            )
            continue

        response_timings: dict[str, float] = {}
        action_taken = respond_to_block(
            device,
            result,
            effective_mode=effective_mode,
            blocker=blocker,
            allowlist=allowlist,
            other_enabled_keyboard_count_value=other_enabled_keyboard_count(
                capture, blocker, event.device_id
            ),
            timings=response_timings,
        )

        started_at = pending_since.pop(event.device_id, datetime.now(UTC))
        time_to_detect_ms = int((datetime.now(UTC) - started_at).total_seconds() * 1000)

        trial_timings = trial_timing_summary(buffer, event, response_timings)
        buffer.first_press_ns = None
        buffer.presses_seen = 0

        incident = build_incident(
            result,
            device,
            action_taken=action_taken,
            time_to_detect_ms=time_to_detect_ms,
            trial_timings=trial_timings,
        )

        notify(
            "Continuum: device blocked",
            f"{device.name} was blocked ({action_taken.value}).",
            device_id=device.device_id,
            event_type="blocked",
            details={"incident_id": str(incident.incident_id), "action_taken": action_taken.value},
        )

        post_or_queue_incident(outbox, http_client, base_url, token, incident)
        scorer.reset_device(event.device_id)


def run_maintenance(
    blocker: DeviceBlocker,
    outbox: IncidentOutbox,
    http_client: httpx.Client,
    base_url: str,
    token: str,
    connector_db_path: Path,
) -> None:
    blocker.forget_released_elsewhere()
    released = blocker.check_auto_release()
    for instance_id in released:
        logger.info("auto-released %s after its timeout", instance_id)
        notify(
            "Continuum: device released",
            f"Device {instance_id} was automatically re-enabled.",
            event_type="auto_release",
        )

    drain_outbox(outbox, http_client, base_url, token)
    poll_unblock_commands(connector_db_path, blocker)


def determine_effective_mode(settings: Settings, elevated: bool) -> str:
    """The response mode actually used this run, degraded if not elevated."""
    mode = settings.response.mode
    if mode == "disable_only" and not elevated:
        print(
            "WARNING: not running elevated; disabling a device requires "
            "Administrator. Falling back to lock-only response until Continuum "
            "is restarted from an elevated session."
        )
        return "lock_only"
    if mode == "lock_and_disable" and not elevated:
        print(
            "WARNING: not running elevated; disabling a device requires "
            "Administrator. Degrading to lock-only response until Continuum "
            "is restarted from an elevated session."
        )
        return "lock_only"
    return mode


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--release-all",
        action="store_true",
        help="Re-enable every device in data/disabled_devices.json and exit.",
    )
    parser.add_argument(
        "--user", default=None, help="Whose trained model to load. Defaults to the OS user."
    )
    return parser.parse_args(argv)


def release_all_and_exit(settings: Settings) -> None:
    blocker = DeviceBlocker(
        dry_run=False,
        allow_non_usb=settings.response.allow_non_usb_disable,
        auto_release_timeout_seconds=settings.response.auto_release_timeout_seconds,
        disabled_devices_path=DEFAULT_DISABLED_DEVICES_PATH,
    )
    released = blocker.release_all()
    print(f"Released {len(released)} device(s).")


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    settings = get_settings()
    configure_logging(level=settings.logging.level, directory=settings.logging.directory)

    if args.release_all:
        release_all_and_exit(settings)
        return

    elevated = is_elevated()
    effective_mode = determine_effective_mode(settings, elevated)
    print(f"Continuum runtime starting. Response mode: {effective_mode}. Elevated: {elevated}.")
    logger.info("starting: mode=%s elevated=%s", effective_mode, elevated)

    user = args.user or getpass.getuser()
    threshold_offset = threshold_offset_for_sensitivity(settings.detection.sensitivity)
    model_file = model_path(user)
    model, model_mtime = reload_model_if_changed(model_file, None)
    scorer = Scorer(model, threshold_offset=threshold_offset) if model else None
    if model is None:
        print(
            "No trained model yet: recording only, no protection. Train one on the "
            "dashboard's Train page; it is picked up automatically."
        )
        logger.info("no model at %s: recording only until one is trained", model_file)
    else:
        logger.info(
            "loaded model %s trained on device %s", model.version, model.baseline_device_id
        )
        logger.info(
            "sensitivity %d: threshold %.4f (calibrated %.4f)",
            settings.detection.sensitivity,
            scorer.base_threshold,
            model.threshold,
        )

    capture = create_capture_source()
    recorder = BaselineRecorder()
    blocker = DeviceBlocker(
        dry_run=settings.response.dry_run,
        allow_non_usb=settings.response.allow_non_usb_disable,
        auto_release_timeout_seconds=settings.response.auto_release_timeout_seconds,
        disabled_devices_path=DEFAULT_DISABLED_DEVICES_PATH,
    )
    outbox = IncidentOutbox(DEFAULT_OUTBOX_PATH)
    http_client = httpx.Client()
    token = os.environ.get(settings.connector.auth_token_env_var, "")
    base_url = f"http://{settings.connector.host}:{settings.connector.port}"
    connector_db_path = resolve_database_path(settings)

    consume_stop_request()  # a stale request from an earlier run must not stop this one
    fail_abandoned_sessions(connector_db_path)
    released_on_start = blocker.release_all()
    if released_on_start:
        logger.info(
            "released %d device(s) left disabled from a previous run", len(released_on_start)
        )

    device_buffers: dict[str, _DeviceBuffer] = {}
    pending_since: dict[str, datetime] = {}
    quarantine_locked_at: dict[str, float] = {}
    remote_guard = RemoteGuard(
        settings=settings.remote,
        connector_db_path=connector_db_path,
        dry_run=settings.response.dry_run,
    )
    if settings.remote.enabled:
        logger.info(
            "remote-access typing guard on: trigger=%s response=%s",
            settings.remote.trigger,
            settings.remote.response,
        )
        remote_guard.refresh_status()

    identity = RuntimeIdentity(
        started_at=datetime.now(UTC).isoformat(),
        pid=os.getpid(),
        elevated=elevated,
        configured_mode=settings.response.mode,
        effective_mode=effective_mode,
        dry_run=settings.response.dry_run,
        model_version=model.version if model else NO_MODEL_VERSION,
        calibrated_threshold=model.threshold if model else 0.0,
        base_threshold=scorer.base_threshold if scorer else 0.0,
        sensitivity=settings.detection.sensitivity,
    )

    capture.start()
    logger.info("capture started")
    if scorer is not None:
        print("Capture started. Watching for injection attacks. Press Ctrl+C to stop.")
    else:
        print("Capture started. Waiting for a trained model. Press Ctrl+C to stop.")
    write_runtime_status(
        connector_db_path, identity, state="running", devices=describe_devices(capture, blocker)
    )

    try:
        last_maintenance = time.monotonic()
        last_command_poll = 0.0
        blocked_ids = set(blocker.blocked_instance_ids)
        while True:
            try:
                event = capture.events.get(timeout=CAPTURE_POLL_TIMEOUT_SECONDS)
            except queue.Empty:
                event = None

            if event is not None:
                process_event(
                    event,
                    device_buffers=device_buffers,
                    pending_since=pending_since,
                    scorer=scorer,
                    capture=capture,
                    blocker=blocker,
                    outbox=outbox,
                    http_client=http_client,
                    base_url=base_url,
                    token=token,
                    effective_mode=effective_mode,
                    allowlist=settings.response.allowlist,
                    connector_db_path=connector_db_path,
                    recorder=recorder,
                    quarantine_locked_at=quarantine_locked_at,
                    remote_guard=remote_guard,
                )

            now_monotonic = time.monotonic()
            if now_monotonic - last_command_poll >= COMMAND_POLL_INTERVAL_SECONDS:
                was_recording = recorder.active
                poll_baseline_commands(connector_db_path, recorder, user=user)
                poll_unblock_commands(connector_db_path, blocker)
                if recorder.active != was_recording:
                    print("Training: recording typing." if recorder.active
                          else "Training: session saved; detection resumed.")
                # Show a block or an unblock on the dashboard within a
                # second rather than at the next heartbeat.
                now_blocked = set(blocker.blocked_instance_ids)
                if now_blocked != blocked_ids:
                    for instance_id in sorted(now_blocked - blocked_ids):
                        print(f"Blocked {instance_id}. Unblock it from the dashboard.")
                    for instance_id in sorted(blocked_ids - now_blocked):
                        print(f"Unblocked {instance_id}.")
                    blocked_ids = now_blocked
                    write_runtime_status(
                        connector_db_path,
                        identity,
                        state="running",
                        devices=describe_devices(capture, blocker),
                    )
                last_command_poll = now_monotonic
            if now_monotonic - last_maintenance >= MAINTENANCE_INTERVAL_SECONDS:
                if consume_stop_request():
                    print("\nStop requested (stop-all). Stopping.")
                    break
                new_model, model_mtime = reload_model_if_changed(model_file, model_mtime)
                if new_model is not None:
                    model = new_model
                    scorer = Scorer(model, threshold_offset=threshold_offset)
                    pending_since.clear()
                    identity = dataclasses.replace(
                        identity,
                        model_version=model.version,
                        calibrated_threshold=model.threshold,
                        base_threshold=scorer.base_threshold,
                    )
                    logger.info("loaded new model %s", model.version)
                    print(f"Loaded model {model.version}. Watching for injection attacks.")
                run_maintenance(blocker, outbox, http_client, base_url, token, connector_db_path)
                if settings.remote.enabled:
                    remote_guard.refresh_status()
                write_runtime_status(
                    connector_db_path,
                    identity,
                    state="running",
                    devices=describe_devices(capture, blocker),
                )
                last_maintenance = now_monotonic
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        save_active_recording(connector_db_path, recorder, user=user)
        logger.info("shutting down, releasing all disabled devices")
        released = blocker.release_all()
        if released:
            print(f"Released {len(released)} device(s).")
        write_runtime_status(
            connector_db_path, identity, state="stopped", devices=describe_devices(capture, blocker)
        )
        capture.stop()
        outbox.close()
        http_client.close()
        print("Continuum runtime stopped.")


if __name__ == "__main__":
    main()
