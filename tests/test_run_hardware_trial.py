"""Tests for tools/run_hardware_trial.py.

Exercises the pure CSV, polling and parsing pieces directly; the
interactive input() loop in main() is a thin wrapper around these.
"""

from __future__ import annotations

import csv
import json
import sqlite3

import httpx
import pytest
from tools.run_hardware_trial import (
    CSV_FIELDS,
    PAYLOAD_CHARS,
    append_row,
    ensure_csv_header,
    incident_to_row,
    parse_chars_landed,
    read_connector_incidents,
    read_outbox_incidents,
    wait_for_new_incident,
)

from continuum.runtime import (
    TRIAL_MS_TO_BLOCK,
    TRIAL_MS_TO_LOCK,
    TRIAL_MS_TO_RESPONSE,
    TRIAL_PRESSES_TO_BLOCK,
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
    "features_summary": {
        "burst_score": 1.0,
        "window_n_events": 30.0,
        TRIAL_PRESSES_TO_BLOCK: 40.0,
        TRIAL_MS_TO_BLOCK: 212.5,
        TRIAL_MS_TO_LOCK: 230.0,
        TRIAL_MS_TO_RESPONSE: 410.0,
    },
    "action_taken": "locked_and_disabled",
    "time_to_detect_ms": 45,
    "mitre_technique": "T1200 Hardware Additions",
    "recommended_followups": ["isolate_device"],
    "notes": "test incident",
}


def test_ensure_csv_header_creates_a_file_with_the_right_columns(tmp_path):
    path = tmp_path / "results.csv"

    ensure_csv_header(path)

    with path.open(encoding="utf-8") as handle:
        assert next(csv.reader(handle)) == CSV_FIELDS


def test_ensure_csv_header_accepts_an_existing_file_with_the_same_columns(tmp_path):
    path = tmp_path / "results.csv"
    ensure_csv_header(path)

    ensure_csv_header(path)


def test_ensure_csv_header_refuses_a_file_with_other_columns(tmp_path):
    path = tmp_path / "results.csv"
    path.write_text("payload,time_to_lock_ms\n", encoding="utf-8")

    with pytest.raises(ValueError):
        ensure_csv_header(path)
    assert path.read_text(encoding="utf-8") == "payload,time_to_lock_ms\n"


def test_incident_to_row_extracts_trial_timings():
    row = incident_to_row("burst", SAMPLE_INCIDENT, chars_landed=41)

    assert row["detected"] == 1
    assert row["payload"] == "burst"
    assert row["presses_to_block"] == 40.0
    assert row["ms_to_block"] == 212.5
    assert row["ms_to_lock"] == 230.0
    assert row["ms_to_response"] == 410.0
    assert row["time_to_detect_ms"] == 45
    assert row["payload_chars"] == PAYLOAD_CHARS
    assert row["chars_landed"] == 41


def test_incident_to_row_for_an_undetected_run():
    row = incident_to_row("randomized", None, chars_landed=PAYLOAD_CHARS)

    assert row["detected"] == 0
    assert row["incident_id"] == ""
    assert row["ms_to_block"] == ""
    assert row["chars_landed"] == PAYLOAD_CHARS


def test_incident_to_row_leaves_missing_timings_blank():
    incident = dict(SAMPLE_INCIDENT, features_summary={"window_n_events": 30.0})

    row = incident_to_row("burst", incident, chars_landed=None)

    assert row["ms_to_lock"] == ""
    assert row["presses_to_block"] == ""
    assert row["chars_landed"] == ""


def test_append_row_writes_a_csv_line(tmp_path):
    path = tmp_path / "results.csv"
    ensure_csv_header(path)

    append_row(path, incident_to_row("burst", SAMPLE_INCIDENT, chars_landed=None))

    with path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["payload"] == "burst"
    assert rows[0]["presses_to_block"] == "40.0"


@pytest.mark.parametrize(("answer", "expected"), [("", None), (" 12 ", 12), ("0", 0)])
def test_parse_chars_landed(answer, expected):
    assert parse_chars_landed(answer) == expected


@pytest.mark.parametrize("answer", ["-1", str(PAYLOAD_CHARS + 1), "many"])
def test_parse_chars_landed_rejects_bad_input(answer):
    with pytest.raises(ValueError):
        parse_chars_landed(answer)


def test_read_outbox_incidents_returns_empty_list_for_a_missing_file(tmp_path):
    assert read_outbox_incidents(tmp_path / "does-not-exist.sqlite3") == []


def test_read_outbox_incidents_reads_real_rows(tmp_path):
    path = tmp_path / "outbox.sqlite3"
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE outbox (id INTEGER PRIMARY KEY, incident_json TEXT)")
    conn.execute("INSERT INTO outbox (incident_json) VALUES (?)", (json.dumps(SAMPLE_INCIDENT),))
    conn.commit()
    conn.close()

    [incident] = read_outbox_incidents(path)

    assert incident["device"]["device_id"] == "dev-1"


def test_read_connector_incidents_returns_items_and_survives_failures():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"items": [SAMPLE_INCIDENT], "total": 1})

    ok = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    down = httpx.Client(
        transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x"))),
        base_url="http://test",
    )

    assert read_connector_incidents(ok) == [SAMPLE_INCIDENT]
    assert read_connector_incidents(down) == []
    assert read_connector_incidents(None) == []


def test_wait_for_new_incident_skips_seen_ids_until_a_new_one_appears():
    old = dict(SAMPLE_INCIDENT)
    new = dict(SAMPLE_INCIDENT, incident_id="22222222-2222-2222-2222-222222222222")
    polls = iter([[old], [old], [old, new]])
    sleeps = []

    found = wait_for_new_incident(
        lambda: next(polls), {old["incident_id"]}, timeout_seconds=60, sleep=sleeps.append
    )

    assert found["incident_id"] == new["incident_id"]
    assert len(sleeps) == 2


def test_wait_for_new_incident_times_out():
    now = {"t": 0.0}

    def clock():
        return now["t"]

    def sleep(seconds):
        now["t"] += seconds

    found = wait_for_new_incident(
        lambda: [SAMPLE_INCIDENT],
        {SAMPLE_INCIDENT["incident_id"]},
        timeout_seconds=5,
        sleep=sleep,
        clock=clock,
    )

    assert found is None
    assert now["t"] >= 5
