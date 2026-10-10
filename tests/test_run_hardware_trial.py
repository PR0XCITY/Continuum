"""Tests for tools/run_hardware_trial.py.

Exercises the pure CSV and outbox-reading pieces directly; the
interactive input() loop in main() is not covered here the same way
tools/record_baseline.py's is not, it is a thin wrapper around these.
"""

from __future__ import annotations

import csv
import json
import sqlite3

import tools.run_hardware_trial as hardware_trial_module
from tools.run_hardware_trial import (
    CSV_FIELDS,
    append_row,
    ensure_csv_header,
    incident_to_row,
    read_outbox_incidents,
    wait_for_new_incident,
)

SAMPLE_INCIDENT = {
    "incident_id": "11111111-1111-1111-1111-111111111111",
    "detected_at": "2026-01-01T00:00:00+00:00",
    "device": {
        "device_id": "dev-1",
        "vendor_id": "16D0",
        "product_id": "0753",
        "name": "Digispark Test Device",
        "bus_type": "USB",
        "is_usb": True,
        "instance_id": r"HID\VID_16D0&PID_0753\0",
        "first_seen": "2026-01-01T00:00:00+00:00",
    },
    "anomaly_score": 2.5,
    "threshold": 1.0,
    "verdict": "blocked",
    "attack_pattern": "burst_injection",
    "features_summary": {"burst_score": 1.0, "window_n_events": 30.0},
    "action_taken": "locked_and_disabled",
    "time_to_detect_ms": 450,
    "mitre_technique": "T1200 Hardware Additions",
    "recommended_followups": ["isolate_device"],
    "notes": "test incident",
}


def _make_outbox(path):
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            next_retry_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def test_ensure_csv_header_creates_a_file_with_the_right_columns(tmp_path):
    path = tmp_path / "results.csv"

    ensure_csv_header(path)

    with path.open(encoding="utf-8") as handle:
        header = next(csv.reader(handle))
    assert header == CSV_FIELDS


def test_ensure_csv_header_does_not_overwrite_an_existing_file(tmp_path):
    path = tmp_path / "results.csv"
    path.write_text("not a header\n", encoding="utf-8")

    ensure_csv_header(path)

    assert path.read_text(encoding="utf-8") == "not a header\n"


def test_incident_to_row_extracts_the_expected_fields():
    row = incident_to_row("burst", SAMPLE_INCIDENT)

    assert row["payload"] == "burst"
    assert row["device_id"] == "dev-1"
    assert row["device_name"] == "Digispark Test Device"
    assert row["verdict"] == "blocked"
    assert row["action_taken"] == "locked_and_disabled"
    assert row["time_to_detect_ms"] == 450
    assert row["time_to_lock_ms"] == 450  # same moment; see the module docstring
    assert row["window_n_events"] == 30.0


def test_read_outbox_incidents_returns_empty_list_for_a_missing_file(tmp_path):
    assert read_outbox_incidents(tmp_path / "does-not-exist.sqlite3") == []


def test_read_outbox_incidents_reads_real_rows(tmp_path):
    path = tmp_path / "outbox.sqlite3"
    conn = _make_outbox(path)
    conn.execute(
        "INSERT INTO outbox (incident_json, created_at, attempts, next_retry_at) "
        "VALUES (?, ?, 0, ?)",
        (json.dumps(SAMPLE_INCIDENT), "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()

    entries = read_outbox_incidents(path)

    assert len(entries) == 1
    assert entries[0]["incident"]["device"]["device_id"] == "dev-1"


def test_append_row_writes_a_csv_line(tmp_path):
    path = tmp_path / "results.csv"
    ensure_csv_header(path)

    append_row(path, "burst", SAMPLE_INCIDENT)

    with path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["payload"] == "burst"
    assert rows[0]["device_id"] == "dev-1"


def test_wait_for_new_incident_skips_already_seen_rows_and_blocks_until_a_new_one(
    tmp_path, monkeypatch
):
    path = tmp_path / "outbox.sqlite3"
    conn = _make_outbox(path)
    conn.execute(
        "INSERT INTO outbox (incident_json, created_at, attempts, next_retry_at) "
        "VALUES (?, ?, 0, ?)",
        (json.dumps(SAMPLE_INCIDENT), "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()

    [existing] = read_outbox_incidents(path)
    seen = {existing["row_id"]}

    call_count = {"n": 0}

    def fake_sleep(_seconds):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # Simulate a second incident landing after the first poll.
            conn = sqlite3.connect(str(path))
            conn.execute(
                "INSERT INTO outbox (incident_json, created_at, attempts, next_retry_at) "
                "VALUES (?, ?, 0, ?)",
                (
                    json.dumps(SAMPLE_INCIDENT),
                    "2026-01-01T00:00:01+00:00",
                    "2026-01-01T00:00:01+00:00",
                ),
            )
            conn.commit()
            conn.close()

    monkeypatch.setattr(hardware_trial_module.time, "sleep", fake_sleep)

    new_entry = wait_for_new_incident(path, seen)

    assert new_entry["row_id"] not in seen
    assert call_count["n"] >= 1
