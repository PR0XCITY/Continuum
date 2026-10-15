"""Tests for continuum.recording: baseline sessions recorded through the runtime.

Runs against a real SQLite file with the connector's schema, so the
shared-table contract between the connector and the runtime is checked
for real; typing comes from the human-cadence simulator.
"""

from __future__ import annotations

import sqlite3

import numpy as np
import pytest
from tools.simulate_attacks import generate_human

from continuum.connector import db
from continuum.detection.baseline import baseline_path, load_baseline
from continuum.recording import (
    BaselineRecorder,
    fail_abandoned_sessions,
    finish_recording,
    poll_baseline_commands,
    save_active_recording,
)

KEYBOARD = r"HID\VID_0B05&PID_19B6&COL03\7&2D1C04E0&0&0002"
USER = "tester"


@pytest.fixture
def connector_db(tmp_path):
    path = tmp_path / "connector.sqlite3"
    engine = db.create_db_engine(path)
    return path, db.make_session_factory(engine)


def _new_session(session_factory, paragraph_index=0) -> int:
    session = session_factory()
    try:
        row = db.create_baseline_session(session, paragraph_index=paragraph_index)
        session.commit()
        return row.id
    finally:
        session.close()


def _session_row(session_factory, session_id):
    session = session_factory()
    try:
        return session.get(db.BaselineSessionRow, session_id)
    finally:
        session.close()


def _stop(path, session_id):
    conn = sqlite3.connect(str(path))
    conn.execute(
        f"INSERT INTO {db.COMMANDS_TABLE} (command_type, device_id, status, created_at) "
        "VALUES (?, ?, 'pending', '2026-01-01T00:00:00+00:00')",
        (db.COMMAND_BASELINE_STOP, str(session_id)),
    )
    conn.commit()
    conn.close()


def _type(recorder, n_presses, seed=1, device=KEYBOARD):
    for event in generate_human(device, n_presses, seed=seed, wpm_range=(50, 70)):
        recorder.record(event)


# --- the recorder itself -------------------------------------------------------


def test_recorder_counts_presses_per_device_and_picks_the_main_one():
    recorder = BaselineRecorder()
    recorder.start(1)
    _type(recorder, 40, device="a")
    _type(recorder, 5, device="b", seed=2)

    assert recorder.active
    assert recorder.presses_by_device() == {"a": 40, "b": 5}
    assert recorder.main_device() == ("a", 40)

    recorder.reset()
    assert not recorder.active
    assert recorder.main_device() == (None, 0)


# --- a full session through the shared tables -------------------------------------


def test_start_record_stop_saves_windows_to_the_baseline(connector_db, tmp_path):
    path, session_factory = connector_db
    session_id = _new_session(session_factory)
    recorder = BaselineRecorder()

    poll_baseline_commands(path, recorder, user=USER, baseline_dir=tmp_path)
    assert recorder.session_id == session_id
    assert _session_row(session_factory, session_id).state == db.SESSION_RECORDING

    _type(recorder, 300)
    poll_baseline_commands(path, recorder, user=USER, baseline_dir=tmp_path)
    progress = _session_row(session_factory, session_id)
    assert progress.presses == 300
    assert progress.device_id == KEYBOARD

    _stop(path, session_id)
    poll_baseline_commands(path, recorder, user=USER, baseline_dir=tmp_path)

    row = _session_row(session_factory, session_id)
    assert row.state == db.SESSION_SAVED
    assert row.windows_saved > 0
    assert not recorder.active
    baseline = load_baseline(baseline_path(USER, baseline_dir=tmp_path))
    assert baseline.device_id == KEYBOARD
    assert baseline.n_windows == row.windows_saved
    # Each window has its own time, spaced through the typing, not one per sitting.
    assert len(set(baseline.captured_at)) == baseline.n_windows


def test_too_little_typing_fails_with_a_message(connector_db, tmp_path):
    path, session_factory = connector_db
    session_id = _new_session(session_factory)
    recorder = BaselineRecorder()
    poll_baseline_commands(path, recorder, user=USER, baseline_dir=tmp_path)
    _type(recorder, 12)
    _stop(path, session_id)

    poll_baseline_commands(path, recorder, user=USER, baseline_dir=tmp_path)

    row = _session_row(session_factory, session_id)
    assert row.state == db.SESSION_FAILED
    assert "at least 30 key presses" in row.message
    assert not baseline_path(USER, baseline_dir=tmp_path).exists()


def test_typing_on_a_different_keyboard_than_the_baseline_fails(connector_db, tmp_path):
    path, session_factory = connector_db
    recorder = BaselineRecorder()
    for device in (KEYBOARD, "another-keyboard"):
        session_id = _new_session(session_factory)
        poll_baseline_commands(path, recorder, user=USER, baseline_dir=tmp_path)
        _type(recorder, 120, device=device)
        _stop(path, session_id)
        poll_baseline_commands(path, recorder, user=USER, baseline_dir=tmp_path)

    row = _session_row(session_factory, session_id)
    assert row.state == db.SESSION_FAILED
    assert "recorded on device" in row.message


def test_a_cancelled_session_is_never_recorded(connector_db, tmp_path):
    path, session_factory = connector_db
    session_id = _new_session(session_factory)
    session = session_factory()
    session.get(db.BaselineSessionRow, session_id).state = db.SESSION_CANCELLED
    session.commit()
    session.close()
    recorder = BaselineRecorder()

    poll_baseline_commands(path, recorder, user=USER, baseline_dir=tmp_path)

    assert not recorder.active


def test_a_runaway_session_is_saved_automatically(connector_db, tmp_path, monkeypatch):
    path, session_factory = connector_db
    session_id = _new_session(session_factory)
    recorder = BaselineRecorder()
    poll_baseline_commands(path, recorder, user=USER, baseline_dir=tmp_path)
    _type(recorder, 200)
    recorder.started_monotonic -= 3600  # an hour ago: past MAX_RECORDING_SECONDS

    poll_baseline_commands(path, recorder, user=USER, baseline_dir=tmp_path)

    assert not recorder.active
    assert _session_row(session_factory, session_id).state == db.SESSION_SAVED


def test_shutdown_saves_an_active_session(connector_db, tmp_path):
    path, session_factory = connector_db
    session_id = _new_session(session_factory)
    recorder = BaselineRecorder()
    poll_baseline_commands(path, recorder, user=USER, baseline_dir=tmp_path)
    _type(recorder, 150)

    save_active_recording(path, recorder, user=USER, baseline_dir=tmp_path)

    assert _session_row(session_factory, session_id).state == db.SESSION_SAVED


def test_startup_fails_sessions_left_recording_but_keeps_requested_ones(connector_db):
    path, session_factory = connector_db
    left_recording = _new_session(session_factory)
    session = session_factory()
    session.get(db.BaselineSessionRow, left_recording).state = db.SESSION_RECORDING
    session.commit()
    session.close()
    requested = _new_session(session_factory)

    fail_abandoned_sessions(path)

    assert _session_row(session_factory, left_recording).state == db.SESSION_FAILED
    assert _session_row(session_factory, requested).state == db.SESSION_REQUESTED


def test_polling_survives_a_database_without_the_tables(tmp_path):
    recorder = BaselineRecorder()
    poll_baseline_commands(tmp_path / "empty.sqlite3", recorder, user=USER, baseline_dir=tmp_path)
    assert not recorder.active


def test_finish_with_no_typing_fails_cleanly(connector_db, tmp_path):
    path, session_factory = connector_db
    session_id = _new_session(session_factory)
    recorder = BaselineRecorder()
    recorder.start(session_id)
    conn = sqlite3.connect(str(path))

    finish_recording(conn, recorder, user=USER, baseline_dir=tmp_path)
    conn.commit()
    conn.close()

    row = _session_row(session_factory, session_id)
    assert row.state == db.SESSION_FAILED
    assert "No typing" in row.message
    assert not np.any([recorder.active])
