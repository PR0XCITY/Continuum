"""Record real-hardware detection timing into a CSV.

Run this in its own terminal WHILE src/continuum/runtime.py is already
running elsewhere (elevated, if you want lock_and_disable to actually
disable the test device). It watches the local incident outbox, the
only place incidents land today since connector.app is not
implemented yet (see continuum.runtime.IncidentOutbox), for new
incidents, and appends one CSV row per incident to
docs/hardware_trial_results.csv.

For each of the 5 runs per payload in docs/hardware_results.md: type
the payload name at the prompt and press Enter, then plug the
Digispark in. This script blocks until a new incident appears, prints
and records it, then prompts again for the next run. Leave the prompt
blank and press Enter to stop.

Columns recorded:
    time_to_detect_ms  straight from IncidentRecord.time_to_detect_ms:
                        wall clock time from the first suspicious
                        window for that device to the "blocked"
                        verdict.
    time_to_lock_ms     the same value as time_to_detect_ms. In this
                        architecture, lock_workstation() is called
                        synchronously, before anything else (building
                        the incident included), the instant the
                        "blocked" verdict fires; there is no
                        measurable gap between detecting and locking
                        to record separately.
    window_n_events     how many keystroke events made up the window
                        that triggered the block: a proxy for "time to
                        detect in keystrokes", alongside the
                        millisecond figure.

Usage:
    python tools/run_hardware_trial.py
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path

from continuum.runtime import DEFAULT_OUTBOX_PATH

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS_CSV_PATH = REPO_ROOT / "docs" / "hardware_trial_results.csv"
POLL_INTERVAL_SECONDS = 1.0

CSV_FIELDS = [
    "recorded_at",
    "payload",
    "incident_id",
    "device_id",
    "device_name",
    "verdict",
    "action_taken",
    "attack_pattern",
    "anomaly_score",
    "threshold",
    "time_to_detect_ms",
    "time_to_lock_ms",
    "window_n_events",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outbox-path", type=Path, default=DEFAULT_OUTBOX_PATH)
    parser.add_argument("--results-csv", type=Path, default=DEFAULT_RESULTS_CSV_PATH)
    return parser.parse_args()


def ensure_csv_header(path: Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        csv.writer(handle).writerow(CSV_FIELDS)


def read_outbox_incidents(path: Path) -> list[dict]:
    """Every (row_id, incident dict) currently queued in the outbox."""
    if not path.exists():
        return []
    conn = sqlite3.connect(str(path))
    try:
        cursor = conn.execute("SELECT id, incident_json FROM outbox ORDER BY id")
        return [
            {"row_id": row_id, "incident": json.loads(incident_json)}
            for row_id, incident_json in cursor.fetchall()
        ]
    finally:
        conn.close()


def incident_to_row(payload: str, incident: dict) -> dict[str, object]:
    device = incident.get("device") or {}
    features_summary = incident.get("features_summary") or {}
    time_to_detect_ms = incident.get("time_to_detect_ms")

    return {
        "recorded_at": datetime.now(UTC).isoformat(),
        "payload": payload,
        "incident_id": incident.get("incident_id"),
        "device_id": device.get("device_id"),
        "device_name": device.get("name"),
        "verdict": incident.get("verdict"),
        "action_taken": incident.get("action_taken"),
        "attack_pattern": incident.get("attack_pattern"),
        "anomaly_score": incident.get("anomaly_score"),
        "threshold": incident.get("threshold"),
        "time_to_detect_ms": time_to_detect_ms,
        "time_to_lock_ms": time_to_detect_ms,
        "window_n_events": features_summary.get("window_n_events"),
    }


def append_row(path: Path, payload: str, incident: dict) -> dict[str, object]:
    row = incident_to_row(payload, incident)
    with path.open("a", newline="", encoding="utf-8") as handle:
        csv.DictWriter(handle, fieldnames=CSV_FIELDS).writerow(row)
    return row


def wait_for_new_incident(outbox_path: Path, seen_row_ids: set[int]) -> dict:
    while True:
        for entry in read_outbox_incidents(outbox_path):
            if entry["row_id"] not in seen_row_ids:
                return entry
        time.sleep(POLL_INTERVAL_SECONDS)


def main() -> None:
    args = parse_args()
    ensure_csv_header(args.results_csv)

    print(f"Watching the incident outbox at {args.outbox_path}")
    print(f"Results will be appended to {args.results_csv}")
    print("Make sure src/continuum/runtime.py is already running elsewhere.\n")

    # Pre-seed with whatever is already queued so only new incidents
    # from this session get recorded.
    seen_row_ids = {entry["row_id"] for entry in read_outbox_incidents(args.outbox_path)}

    try:
        while True:
            try:
                payload = input(
                    "Payload about to test (burst/slowed/randomized/staged), "
                    "or leave blank to stop: "
                ).strip()
            except EOFError:
                break
            if not payload:
                break

            print(f"Watching for a new incident labelled {payload!r}. Plug the board in now.")
            entry = wait_for_new_incident(args.outbox_path, seen_row_ids)
            seen_row_ids.add(entry["row_id"])

            row = append_row(args.results_csv, payload, entry["incident"])
            print(
                f"Recorded: verdict={row['verdict']} action={row['action_taken']} "
                f"time_to_detect_ms={row['time_to_detect_ms']}\n"
            )
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
