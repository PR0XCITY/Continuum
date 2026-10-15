"""Record a typing baseline from inside the runtime, for the dashboard's Train page.

Responsibility: while the analyst types a paragraph shown on the Train
page, collect that typing through the runtime's own Raw Input capture,
the exact path detection later scores, and save it as baseline windows.
Recording through the runtime rather than in the browser means the
model learns from the same timing source and the same physical keyboard
(device_id) it will be judged against.

Only KeyEvent records ever reach this module: timestamps, down/up, a
press counter and a device id. There is no key identity anywhere, so
nothing here can record what was typed. The paragraph the analyst types
into stays in their browser.

Control flows through the connector's shared SQLite file, like unblock
commands do (see continuum.connector.db): POST /training/start inserts a
baseline_sessions row and a baseline_start command, POST /training/stop
a baseline_stop command. The runtime polls them with plain sqlite3, so
this elevated process never imports the web stack.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from continuum.common.logging import get_logger
from continuum.common.schemas import FeatureWindow, KeyEvent
from continuum.connector.db import (
    BASELINE_SESSIONS_TABLE,
    COMMAND_BASELINE_START,
    COMMAND_BASELINE_STOP,
    COMMANDS_TABLE,
    SESSION_FAILED,
    SESSION_RECORDING,
    SESSION_REQUESTED,
    SESSION_SAVED,
)
from continuum.detection.baseline import (
    DEFAULT_BASELINE_DIR,
    append_feature_windows,
    baseline_path,
)
from continuum.detection.features import DEFAULT_WINDOW_SIZE, iter_feature_windows

logger = get_logger("recording")

# A forgotten session must not leave detection switched off for long.
MAX_RECORDING_SECONDS = 15 * 60


@dataclass
class BaselineRecorder:
    """The typing collected for the session currently being recorded, if any."""

    session_id: int | None = None
    started_monotonic: float = 0.0
    events: dict[str, list[KeyEvent]] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return self.session_id is not None

    def start(self, session_id: int) -> None:
        self.session_id = session_id
        self.started_monotonic = time.monotonic()
        self.events = {}

    def reset(self) -> None:
        self.session_id = None
        self.events = {}

    def record(self, event: KeyEvent) -> None:
        self.events.setdefault(event.device_id, []).append(event)

    def presses_by_device(self) -> dict[str, int]:
        return {
            device_id: sum(1 for e in events if e.event_type == "down" and not e.is_repeat)
            for device_id, events in self.events.items()
        }

    def main_device(self) -> tuple[str | None, int]:
        """The keyboard that did most of the typing, and its press count."""
        presses = self.presses_by_device()
        if not presses:
            return None, 0
        device_id = max(presses, key=presses.__getitem__)
        return device_id, presses[device_id]


def windows_with_times(
    events: Sequence[KeyEvent], device_id: str, *, now: datetime
) -> tuple[list[FeatureWindow], list[datetime]]:
    """Feature windows for one device's typing, each with its own wall-clock time."""
    windows = list(iter_feature_windows(events, device_id))
    if not windows:
        return [], []
    last_ns = max(e.timestamp_ns for e in events)
    captured_at = [
        now - timedelta(microseconds=(last_ns - w.window_start_ns) / 1000) for w in windows
    ]
    return windows, captured_at


def _set_session(conn: sqlite3.Connection, session_id: int, **fields: object) -> None:
    fields["updated_at"] = datetime.now(UTC).isoformat()
    assignments = ", ".join(f"{name} = ?" for name in fields)
    conn.execute(
        f"UPDATE {BASELINE_SESSIONS_TABLE} SET {assignments} WHERE id = ?",
        (*fields.values(), session_id),
    )


def finish_recording(
    conn: sqlite3.Connection,
    recorder: BaselineRecorder,
    *,
    user: str,
    baseline_dir: Path = DEFAULT_BASELINE_DIR,
) -> None:
    """Save the session's windows to the user's baseline and record the outcome."""
    session_id = recorder.session_id
    if session_id is None:
        return
    device_id, presses = recorder.main_device()
    try:
        if device_id is None:
            _set_session(conn, session_id, state=SESSION_FAILED, presses=0,
                         message="No typing was recorded. Type on a physical keyboard.")
            return
        windows, captured_at = windows_with_times(
            recorder.events[device_id], device_id, now=datetime.now(UTC)
        )
        if not windows:
            _set_session(
                conn, session_id, state=SESSION_FAILED, device_id=device_id, presses=presses,
                message=(
                    f"Not enough continuous typing: Continuum needs at least "
                    f"{DEFAULT_WINDOW_SIZE} key presses without a pause longer than 2 seconds."
                ),
            )
            return
        try:
            append_feature_windows(
                baseline_path(user, baseline_dir=baseline_dir),
                user=user,
                device_id=device_id,
                windows=windows,
                captured_at=captured_at,
            )
        except ValueError as error:
            _set_session(conn, session_id, state=SESSION_FAILED, device_id=device_id,
                         presses=presses, message=str(error)[:300])
            return
        _set_session(conn, session_id, state=SESSION_SAVED, device_id=device_id,
                     presses=presses, windows_saved=len(windows), message="")
        logger.info("baseline session %d saved: %d windows from %s", session_id,
                    len(windows), device_id)
    finally:
        recorder.reset()


def poll_baseline_commands(
    connector_db_path: Path,
    recorder: BaselineRecorder,
    *,
    user: str,
    baseline_dir: Path = DEFAULT_BASELINE_DIR,
) -> None:
    """Act on baseline_start and baseline_stop commands and keep progress current.

    Best-effort, like every shared-table access in the runtime: a failure
    here never breaks detection.
    """
    try:
        conn = sqlite3.connect(str(connector_db_path))
    except sqlite3.OperationalError:
        return
    try:
        pending = conn.execute(
            f"SELECT id, command_type, device_id FROM {COMMANDS_TABLE} "
            "WHERE command_type IN (?, ?) AND status = 'pending' ORDER BY id",
            (COMMAND_BASELINE_START, COMMAND_BASELINE_STOP),
        ).fetchall()
        for command_id, command_type, raw_session_id in pending:
            session_id = int(raw_session_id)
            if command_type == COMMAND_BASELINE_START:
                _start(conn, recorder, session_id, user=user, baseline_dir=baseline_dir)
            elif recorder.session_id == session_id:
                finish_recording(conn, recorder, user=user, baseline_dir=baseline_dir)
            conn.execute(
                f"UPDATE {COMMANDS_TABLE} SET status = 'done', completed_at = ? WHERE id = ?",
                (datetime.now(UTC).isoformat(), command_id),
            )

        if recorder.active:
            if time.monotonic() - recorder.started_monotonic > MAX_RECORDING_SECONDS:
                logger.info("baseline session %s ran too long; saving it", recorder.session_id)
                finish_recording(conn, recorder, user=user, baseline_dir=baseline_dir)
            else:
                device_id, presses = recorder.main_device()
                _set_session(conn, recorder.session_id, device_id=device_id, presses=presses)
        conn.commit()
    except sqlite3.OperationalError:
        logger.debug("connector db at %s not ready for baseline commands", connector_db_path)
    finally:
        conn.close()


def _start(
    conn: sqlite3.Connection,
    recorder: BaselineRecorder,
    session_id: int,
    *,
    user: str,
    baseline_dir: Path,
) -> None:
    row = conn.execute(
        f"SELECT state FROM {BASELINE_SESSIONS_TABLE} WHERE id = ?", (session_id,)
    ).fetchone()
    if row is None or row[0] != SESSION_REQUESTED:
        return  # cancelled before the runtime saw it
    if recorder.active:
        finish_recording(conn, recorder, user=user, baseline_dir=baseline_dir)
    recorder.start(session_id)
    _set_session(conn, session_id, state=SESSION_RECORDING)
    logger.info("baseline session %d: recording; detection paused", session_id)


def save_active_recording(
    connector_db_path: Path,
    recorder: BaselineRecorder,
    *,
    user: str,
    baseline_dir: Path = DEFAULT_BASELINE_DIR,
) -> None:
    """At shutdown: keep whatever was typed in a session still recording."""
    if not recorder.active:
        return
    try:
        conn = sqlite3.connect(str(connector_db_path))
    except sqlite3.OperationalError:
        return
    try:
        finish_recording(conn, recorder, user=user, baseline_dir=baseline_dir)
        conn.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        conn.close()


def fail_abandoned_sessions(connector_db_path: Path) -> None:
    """At startup: a session left recording by a previous run can never finish."""
    try:
        conn = sqlite3.connect(str(connector_db_path))
    except sqlite3.OperationalError:
        return
    try:
        # Only sessions that were mid-recording: a session merely requested
        # while the runtime was down starts normally once it is up.
        conn.execute(
            f"UPDATE {BASELINE_SESSIONS_TABLE} SET state = ?, message = ?, updated_at = ? "
            "WHERE state = ?",
            (
                SESSION_FAILED,
                "The runtime restarted before this session was saved.",
                datetime.now(UTC).isoformat(),
                SESSION_RECORDING,
            ),
        )
        conn.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        conn.close()
