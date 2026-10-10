"""Guided baseline recording session.

Run this, pick your keyboard, and type a few paragraphs of your own
text for about 3 minutes. Run it again on 2 or 3 separate occasions
(fast typing, normal typing, different times of day) to build up a
baseline with enough windows to be reliable.

What you type appears on your own terminal as you type it, because
that is just the terminal echoing your input; this script never reads,
stores or logs that text. It only ever sees KeyEvent records from the
capture layer, which carry a timestamp, down/up, a press counter and a
device id, nothing else. Only the numeric FeatureWindow statistics
computed from those events are written to disk, as
data/baselines/<user>.npz.

Usage:
    python tools/record_baseline.py [user]

user defaults to your OS account name if not given. For the false
positive study in docs/EVALUATION.md, also record one deliberately fast
typing session under the name "<user>_fast"; tools/evaluate_all.py
replays it against the model trained on your normal baseline.
"""

from __future__ import annotations

import getpass
import queue
import sys
import time
from datetime import UTC, datetime, timedelta

from continuum.capture.factory import create_capture_source
from continuum.common.schemas import DeviceInfo, KeyEvent
from continuum.detection.baseline import append_feature_windows, baseline_path, print_quality_report
from continuum.detection.features import DEFAULT_WINDOW_SIZE, iter_feature_windows

DEVICE_DISCOVERY_SECONDS = 1.0

SITTING_INSTRUCTIONS = """
Type a few paragraphs of your own text below, at whatever pace feels
natural for this sitting. Press Enter after each paragraph. Type DONE
on its own line when you want to stop (about 3 minutes total for this
sitting is plenty).
"""


def _choose_device(devices: list[DeviceInfo]) -> DeviceInfo:
    print("Keyboards seen so far:")
    for index, device in enumerate(devices, start=1):
        print(f"  {index}. {device.name} ({device.bus_type}, {device.device_id})")

    while True:
        choice = input("Pick the keyboard to record a baseline for (number): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(devices):
            return devices[int(choice) - 1]
        print("Not a valid choice, try again.")


def _collect_sitting_events(capture, device_id: str) -> list[KeyEvent]:
    collected: list[KeyEvent] = []

    def drain() -> None:
        while True:
            try:
                event = capture.events.get_nowait()
            except queue.Empty:
                return
            if event.device_id == device_id:
                collected.append(event)

    print(SITTING_INSTRUCTIONS)
    while True:
        try:
            line = input("> ")
        except EOFError:
            break
        drain()
        if line.strip().upper() == "DONE":
            break
    drain()

    return collected


def main() -> None:
    user = sys.argv[1] if len(sys.argv) > 1 else getpass.getuser()

    capture = create_capture_source()
    capture.start()
    print("Capture started. Waiting a moment for device discovery...")
    time.sleep(DEVICE_DISCOVERY_SECONDS)

    devices = capture.list_devices()
    if not devices:
        print("No keyboard-class devices seen yet. Press a key on your keyboard and rerun.")
        capture.stop()
        return

    try:
        device = _choose_device(devices)
        events = _collect_sitting_events(capture, device.device_id)
    finally:
        capture.stop()

    windows = list(iter_feature_windows(events, device.device_id))
    if not windows:
        print(
            f"Not enough keystrokes for even one window (need {DEFAULT_WINDOW_SIZE} "
            "key-downs without a long pause). Nothing saved this sitting; "
            "try typing a bit more next time."
        )
        return

    # One wall-clock time per window, from each window's offset on the
    # capture clock, so a later replay (tools/evaluate_all.py's false
    # positive study) sees real spacing between windows.
    sitting_end = datetime.now(UTC)
    last_ns = events[-1].timestamp_ns
    captured_at = [
        sitting_end - timedelta(microseconds=(last_ns - window.window_start_ns) / 1000)
        for window in windows
    ]

    path = baseline_path(user)
    baseline = append_feature_windows(
        path,
        user=user,
        device_id=device.device_id,
        windows=windows,
        captured_at=captured_at,
    )

    print(f"Saved {len(windows)} windows from this sitting to {path}")
    print_quality_report(baseline)


if __name__ == "__main__":
    main()
