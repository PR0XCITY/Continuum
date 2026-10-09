"""Live demo of Continuum's capture layer.

Run this to see that Continuum can tell physical keyboards apart and is
timing their cadence, without printing or storing anything about which
keys were pressed. Prints only device_id, device name, events per
second and the median inter-key interval per device, refreshed about
once a second.

Usage:
    python tools/capture_demo.py

Stop with Ctrl+C.
"""

from __future__ import annotations

import os
import queue
import statistics
import time
from collections import defaultdict, deque

from continuum.capture.factory import create_capture_source
from continuum.common.schemas import DeviceInfo, KeyEvent

REFRESH_SECONDS = 1.0
INTERVAL_WINDOW = 50


class _DeviceStats:
    """Running per-device counters. Holds no key content, ever."""

    def __init__(self) -> None:
        self.total_events = 0
        self.events_this_second = 0
        self._last_down_timestamp_ns: int | None = None
        self._recent_intervals_ms: deque[float] = deque(maxlen=INTERVAL_WINDOW)

    def record(self, event: KeyEvent) -> None:
        self.total_events += 1
        self.events_this_second += 1

        if event.event_type == "down" and not event.is_repeat:
            if self._last_down_timestamp_ns is not None:
                delta_ns = event.timestamp_ns - self._last_down_timestamp_ns
                if delta_ns > 0:
                    self._recent_intervals_ms.append(delta_ns / 1_000_000)
            self._last_down_timestamp_ns = event.timestamp_ns

    def median_interval_ms(self) -> float | None:
        if not self._recent_intervals_ms:
            return None
        return statistics.median(self._recent_intervals_ms)


def _clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")  # noqa: S605, S607


def _render(devices: dict[str, DeviceInfo], stats: dict[str, _DeviceStats]) -> None:
    _clear_screen()
    print("Continuum capture demo. No key content is shown. Press Ctrl+C to stop.\n")

    header = f"{'device_id':<40} {'name':<32} {'events/sec':>10} {'median interval ms':>20}"
    print(header)
    print("-" * len(header))

    for device_id in sorted(stats):
        stat = stats[device_id]
        device = devices.get(device_id)
        name = device.name if device is not None else "(device info pending)"
        median = stat.median_interval_ms()
        median_text = f"{median:.1f}" if median is not None else "-"
        print(f"{device_id:<40} {name:<32} {stat.events_this_second:>10} {median_text:>20}")

    if not stats:
        print("(no keyboard activity seen yet)")


def main() -> None:
    capture = create_capture_source()
    capture.start()
    print("Capture started. Type on any keyboard to see it appear below.")

    stats: dict[str, _DeviceStats] = defaultdict(_DeviceStats)
    last_refresh = time.monotonic()

    try:
        while True:
            try:
                event = capture.events.get(timeout=0.1)
            except queue.Empty:
                event = None

            if event is not None:
                stats[event.device_id].record(event)

            now = time.monotonic()
            if now - last_refresh >= REFRESH_SECONDS:
                devices = {device.device_id: device for device in capture.list_devices()}
                _render(devices, stats)
                for stat in stats.values():
                    stat.events_this_second = 0
                last_refresh = now
    except KeyboardInterrupt:
        print("\nStopping capture.")
    finally:
        capture.stop()


if __name__ == "__main__":
    main()
