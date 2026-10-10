"""Record real-hardware detection timing into a CSV.

Run this in its own terminal WHILE the runtime is already running
(elevated, if you want lock_and_disable to actually disable the test
device) and the connector is up. For each run: type the payload name at
the prompt, press Enter, then plug the Digispark in. The script waits
for a new incident, from the connector API or, if the connector is
down, from the runtime's local outbox. If none appears within
--timeout seconds the run is recorded as not detected, so detection
rate can be computed later. Either way it then asks how many payload
characters actually appeared in the editor: Continuum never records
which keys were typed, so counting what landed on screen is the only
way to measure it. Leave the payload prompt blank to stop.

Columns, one row per run, in docs/hardware_trial_results.csv:
    detected            1 if an incident appeared within the timeout.
    presses_to_block    key presses from the device's first press to the
                        blocking window (incident features_summary).
    ms_to_block         milliseconds from the device's first press to the
                        blocking window, on the capture clock.
    ms_to_lock          ms_to_block plus the time LockWorkStation took;
                        empty when the response mode does not lock.
    ms_to_response      ms_to_block plus the whole lock-and-disable call.
    time_to_detect_ms   the incident's own figure: first suspicious window
                        to the blocking verdict.
    payload_chars       characters the sketch types (PAYLOAD_CHARS).
    chars_landed        characters the operator saw in the editor, or
                        empty if not counted.

tools/evaluate_all.py reads this file for docs/EVALUATION.md.

Usage:
    python tools/run_hardware_trial.py [--timeout 60]
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sqlite3
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx

from continuum.common.config import get_settings
from continuum.runtime import (
    DEFAULT_OUTBOX_PATH,
    TRIAL_MS_TO_BLOCK,
    TRIAL_MS_TO_LOCK,
    TRIAL_MS_TO_RESPONSE,
    TRIAL_PRESSES_TO_BLOCK,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS_CSV_PATH = REPO_ROOT / "docs" / "hardware_trial_results.csv"
POLL_INTERVAL_SECONDS = 1.0
DEFAULT_TIMEOUT_SECONDS = 60.0

# Every sketch in tools/attacks types the same 137-character string.
PAYLOAD_CHARS = 137
PAYLOADS = ("burst", "slowed", "randomized", "staged")

CSV_FIELDS = [
    "recorded_at",
    "payload",
    "detected",
    "incident_id",
    "device_id",
    "device_name",
    "verdict",
    "action_taken",
    "attack_pattern",
    "anomaly_score",
    "threshold",
    "presses_to_block",
    "ms_to_block",
    "ms_to_lock",
    "ms_to_response",
    "time_to_detect_ms",
    "window_n_events",
    "payload_chars",
    "chars_landed",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--outbox-path", type=Path, default=DEFAULT_OUTBOX_PATH)
    parser.add_argument("--results-csv", type=Path, default=DEFAULT_RESULTS_CSV_PATH)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    return parser.parse_args()


def ensure_csv_header(path: Path) -> None:
    """Create the CSV with a header, or refuse an existing file with other columns."""
    if path.exists():
        with path.open(encoding="utf-8", newline="") as handle:
            header = next(csv.reader(handle), None)
        if header != CSV_FIELDS:
            raise ValueError(
                f"{path} has different columns than this version of the script writes; "
                "move it aside and start a new file"
            )
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        csv.writer(handle).writerow(CSV_FIELDS)


def read_outbox_incidents(path: Path) -> list[dict]:
    """Every incident currently queued in the runtime's outbox (connector was down)."""
    if not path.exists():
        return []
    conn = sqlite3.connect(str(path))
    try:
        cursor = conn.execute("SELECT incident_json FROM outbox ORDER BY id")
        return [json.loads(incident_json) for (incident_json,) in cursor.fetchall()]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def read_connector_incidents(client: httpx.Client | None) -> list[dict]:
    """The newest incidents from the connector API; empty if it is unreachable."""
    if client is None:
        return []
    try:
        response = client.get("/incidents", params={"limit": 50})
    except httpx.HTTPError:
        return []
    if response.status_code != 200:
        return []
    return response.json()["items"]


def wait_for_new_incident(
    poll: Callable[[], list[dict]],
    seen_ids: set[str],
    *,
    timeout_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> dict | None:
    """The first incident poll() returns whose id is not in seen_ids, or None on timeout."""
    deadline = clock() + timeout_seconds
    while True:
        for incident in poll():
            if str(incident.get("incident_id")) not in seen_ids:
                return incident
        if clock() >= deadline:
            return None
        sleep(POLL_INTERVAL_SECONDS)


def _blank_if_none(value: object) -> object:
    return "" if value is None else value


def incident_to_row(
    payload: str, incident: dict | None, *, chars_landed: int | None
) -> dict[str, object]:
    """One CSV row; incident None means the run was not detected."""
    row: dict[str, object] = {field: "" for field in CSV_FIELDS}
    row.update(
        recorded_at=datetime.now(UTC).isoformat(),
        payload=payload,
        detected=0 if incident is None else 1,
        payload_chars=PAYLOAD_CHARS,
        chars_landed=_blank_if_none(chars_landed),
    )
    if incident is None:
        return row

    device = incident.get("device") or {}
    summary = incident.get("features_summary") or {}
    row.update(
        incident_id=incident.get("incident_id"),
        device_id=device.get("device_id"),
        device_name=device.get("name"),
        verdict=incident.get("verdict"),
        action_taken=incident.get("action_taken"),
        attack_pattern=incident.get("attack_pattern"),
        anomaly_score=incident.get("anomaly_score"),
        threshold=incident.get("threshold"),
        presses_to_block=_blank_if_none(summary.get(TRIAL_PRESSES_TO_BLOCK)),
        ms_to_block=_blank_if_none(summary.get(TRIAL_MS_TO_BLOCK)),
        ms_to_lock=_blank_if_none(summary.get(TRIAL_MS_TO_LOCK)),
        ms_to_response=_blank_if_none(summary.get(TRIAL_MS_TO_RESPONSE)),
        time_to_detect_ms=_blank_if_none(incident.get("time_to_detect_ms")),
        window_n_events=_blank_if_none(summary.get("window_n_events")),
    )
    return row


def append_row(path: Path, row: dict[str, object]) -> None:
    with path.open("a", newline="", encoding="utf-8") as handle:
        csv.DictWriter(handle, fieldnames=CSV_FIELDS).writerow(row)


def parse_chars_landed(answer: str) -> int | None:
    answer = answer.strip()
    if not answer:
        return None
    value = int(answer)
    if not 0 <= value <= PAYLOAD_CHARS:
        raise ValueError(f"expected a number from 0 to {PAYLOAD_CHARS}")
    return value


def _ask_chars_landed() -> int | None:
    while True:
        answer = input(
            f"How many of the {PAYLOAD_CHARS} payload characters appeared in the editor? "
            "(blank to skip): "
        )
        try:
            return parse_chars_landed(answer)
        except ValueError as error:
            print(f"  {error}")


def main() -> int:
    args = parse_args()
    ensure_csv_header(args.results_csv)

    settings = get_settings()
    token = os.environ.get(settings.connector.auth_token_env_var, "")
    client = None
    if token:
        client = httpx.Client(
            base_url=f"http://{settings.connector.host}:{settings.connector.port}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0,
        )
    else:
        print(
            f"warning: {settings.connector.auth_token_env_var} is not set; only the outbox "
            "will be watched",
            file=sys.stderr,
        )

    def poll() -> list[dict]:
        return read_connector_incidents(client) + read_outbox_incidents(args.outbox_path)

    print(f"Results will be appended to {args.results_csv}")
    print("Make sure the runtime and the connector are already running.\n")
    seen_ids = {str(incident.get("incident_id")) for incident in poll()}

    try:
        while True:
            try:
                payload = input(
                    f"Payload about to test ({'/'.join(PAYLOADS)}), or blank to stop: "
                ).strip()
            except EOFError:
                break
            if not payload:
                break

            print(f"Waiting up to {args.timeout:.0f} s for an incident. Plug the board in now.")
            incident = wait_for_new_incident(poll, seen_ids, timeout_seconds=args.timeout)
            if incident is None:
                print("No incident appeared: recording this run as not detected.")
            else:
                seen_ids.add(str(incident.get("incident_id")))
                print(
                    f"Incident: verdict={incident.get('verdict')} "
                    f"action={incident.get('action_taken')}"
                )
            row = incident_to_row(payload, incident, chars_landed=_ask_chars_landed())
            append_row(args.results_csv, row)
            print(f"Recorded. presses_to_block={row['presses_to_block'] or 'n/a'}\n")
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        if client is not None:
            client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
