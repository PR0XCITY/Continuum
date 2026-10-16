"""Remote-access typing guard: lock when someone types through a remote tool.

Responsibility: the runtime-side glue for remote-access detection.
Software-generated keystrokes (tagged SOFTWARE_INPUT_DEVICE_ID by the
capture layer) go to a RemoteInputMonitor; when a run of them crosses
the threshold, this module checks which remote-access tools are running
and whether the dashboard has allowed remote typing, then responds
(alert, lock, or lock and end the tool's session) and builds the
incident. Typing timing is all it ever sees; never which keys.

Talks to the connector's SQLite file with plain sqlite3, like
continuum.recording, through the remote_status table (see
continuum.connector.db for the shared schema).
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from continuum.common.config import RemoteSettings
from continuum.common.schemas import (
    SOFTWARE_INPUT_DEVICE_ID,
    ActionTaken,
    AttackPattern,
    DeviceInfo,
    IncidentRecord,
    KeyEvent,
    RecommendedFollowup,
)
from continuum.connector.db import REMOTE_STATUS_ROW_ID, REMOTE_STATUS_TABLE
from continuum.detection.remote_input import RemoteInputMonitor, RemoteInputTrigger
from continuum.response import remote_session
from continuum.response.lockscreen import lock_workstation

logger = logging.getLogger(__name__)

REMOTE_MITRE_TECHNIQUE = "T1219 Remote Access Software"


# --- the shared remote_status row ----------------------------------------------


def read_remote_allowance(connector_db_path: Path, *, now: datetime | None = None) -> bool:
    """True while the dashboard's "Allow remote access" window is open."""
    current = now or datetime.now(UTC)
    try:
        conn = sqlite3.connect(str(connector_db_path))
    except sqlite3.OperationalError:
        return False
    try:
        row = conn.execute(
            f"SELECT allowed_until FROM {REMOTE_STATUS_TABLE} WHERE id = ?",
            (REMOTE_STATUS_ROW_ID,),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    finally:
        conn.close()
    if row is None or not row[0]:
        return False
    try:
        return datetime.fromisoformat(row[0]) > current
    except ValueError:
        return False


def write_remote_status(
    connector_db_path: Path,
    *,
    tools_running: list[str],
    detection: tuple[str, list[str]] | None = None,
) -> None:
    """UPSERT the runtime's half of the remote_status row. Never touches allowed_until.

    detection, when given, is (action taken, tools running at the time).
    Best-effort: a failure is logged and ignored.
    """
    now = datetime.now(UTC).isoformat()
    detected_at = now if detection else None
    action, tools_then = detection if detection else (None, [])
    try:
        conn = sqlite3.connect(str(connector_db_path))
    except sqlite3.OperationalError:
        return
    try:
        conn.execute(
            f"""
            INSERT INTO {REMOTE_STATUS_TABLE}
                (id, allowed_until, tools_running_json, last_detected_at, last_action,
                 last_tools_json, updated_at)
            VALUES (?, NULL, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                tools_running_json = excluded.tools_running_json,
                last_detected_at = COALESCE(excluded.last_detected_at, last_detected_at),
                last_action = COALESCE(excluded.last_action, last_action),
                last_tools_json = CASE WHEN excluded.last_detected_at IS NULL
                    THEN last_tools_json ELSE excluded.last_tools_json END,
                updated_at = excluded.updated_at
            """,
            (
                REMOTE_STATUS_ROW_ID,
                json.dumps(tools_running),
                detected_at,
                action,
                json.dumps(tools_then),
                now,
            ),
        )
        conn.commit()
    except sqlite3.OperationalError:
        logger.debug("connector db at %s not ready for remote status", connector_db_path)
    finally:
        conn.close()


# --- the incident ------------------------------------------------------------


def software_input_device(tools: list[str]) -> DeviceInfo:
    label = ", ".join(tools) if tools else "no remote-access tool detected"
    return DeviceInfo(
        device_id=SOFTWARE_INPUT_DEVICE_ID,
        vendor_id="0000",
        product_id="0000",
        name=f"Software-generated input ({label})"[:256],
        bus_type="Unknown",
        is_usb=False,
        instance_id=SOFTWARE_INPUT_DEVICE_ID,
        first_seen=datetime.now(UTC),
    )


def build_remote_incident(
    trigger: RemoteInputTrigger,
    *,
    tools: list[str],
    settings: RemoteSettings,
    action_taken: ActionTaken,
) -> IncidentRecord:
    context = (
        f"while remote-access software was running: {', '.join(tools)}."
        if tools
        else "with no configured remote-access tool running."
    )
    notes = (
        f"{trigger.presses} software-generated key presses within "
        f"{settings.window_seconds:g} s, with no physical keyboard behind them, {context}"
    )[:280]
    return IncidentRecord(
        detected_at=datetime.now(UTC),
        device=software_input_device(tools),
        anomaly_score=float(trigger.presses),
        threshold=float(settings.min_presses),
        verdict="blocked",
        attack_pattern=AttackPattern.REMOTE_ACCESS_INPUT,
        features_summary={
            "software_presses": float(trigger.presses),
            "window_seconds": float(settings.window_seconds),
            "remote_tools_running": float(len(tools)),
        },
        action_taken=action_taken,
        time_to_detect_ms=trigger.time_to_detect_ms,
        mitre_technique=REMOTE_MITRE_TECHNIQUE,
        recommended_followups=[
            RecommendedFollowup.NOTIFY_SECURITY_TEAM,
            RecommendedFollowup.ROTATE_CREDENTIALS,
            RecommendedFollowup.CAPTURE_FORENSIC_IMAGE,
        ],
        notes=notes,
    )


# --- the guard ---------------------------------------------------------------


@dataclass
class RemoteGuard:
    """Watches software-generated typing and responds to remote-access use."""

    settings: RemoteSettings
    connector_db_path: Path
    dry_run: bool = False
    # Seconds for the sliding window. None: the keystroke's own capture
    # timestamp, so a backlog in the runtime cannot stretch or squash it.
    clock: Callable[[], float] | None = None
    list_tools: Callable[[list[str]], list[str]] = remote_session.running_remote_tools
    lock: Callable[[], bool] = lock_workstation
    end_sessions: Callable[[list[str]], list[str]] = remote_session.end_remote_sessions
    monitor: RemoteInputMonitor = field(init=False)

    def __post_init__(self) -> None:
        self.monitor = RemoteInputMonitor(
            min_presses=self.settings.min_presses,
            window_seconds=self.settings.window_seconds,
        )

    def running_tools(self) -> list[str]:
        try:
            return self.list_tools(self.settings.tools)
        except Exception:
            logger.debug("could not list remote-access tools", exc_info=True)
            return []

    def refresh_status(self) -> None:
        """Report which remote-access tools are running, for the dashboard."""
        write_remote_status(self.connector_db_path, tools_running=self.running_tools())

    def handle(self, event: KeyEvent) -> IncidentRecord | None:
        """Process one software-generated event. Returns an incident when it responded."""
        if not self.settings.enabled:
            return None
        now_s = self.clock() if self.clock is not None else event.timestamp_ns / 1e9
        trigger = self.monitor.observe(event, now_s)
        if trigger is None:
            return None

        tools = self.running_tools()
        if self.settings.trigger == "remote_tool_running" and not tools:
            logger.info(
                "%d software-generated key presses with no remote-access tool running; "
                "ignored (an on-screen keyboard or auto-type, most likely)",
                trigger.presses,
            )
            return None
        if read_remote_allowance(self.connector_db_path):
            logger.info("remote typing through %s allowed from the dashboard", tools or "software")
            return None

        action = self._respond(tools)
        write_remote_status(
            self.connector_db_path, tools_running=tools, detection=(action.value, tools)
        )
        return build_remote_incident(
            trigger, tools=tools, settings=self.settings, action_taken=action
        )

    def _respond(self, tools: list[str]) -> ActionTaken:
        response = self.settings.response
        if response == "alert_only":
            return ActionTaken.ALERT_ONLY
        if self.dry_run:
            logger.info("dry_run: would lock%s", " and end remote sessions"
                        if response == "lock_and_end_session" else "")
            return ActionTaken.ALERT_ONLY

        locked = self.lock()
        logger.warning("remote typing detected (%s); locked: %s", ", ".join(tools), locked)
        if response == "lock_and_end_session" and tools:
            ended = self.end_sessions(tools)
            if ended:
                return ActionTaken.LOCKED_AND_ENDED_REMOTE
        return ActionTaken.WORKSTATION_LOCKED if locked else ActionTaken.ALERT_ONLY
