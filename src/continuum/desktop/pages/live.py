"""Live status: runtime health, keyboards and their verdicts, remote access, cadence."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QWidget,
)

from continuum.dashboard import helpers
from continuum.desktop.context import AppContext
from continuum.desktop.widgets import (
    Badge,
    Card,
    LineChart,
    Page,
    StatCard,
    breakable,
    clear_layout,
    plain_label,
    verdict_badge,
)
from continuum.desktop.worker import run_async


class LivePage(Page):
    refresh_ms = 2000

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(
            "Live status",
            "What the HID Firewall is doing right now: runtime health, attached keyboards and "
            "their latest verdicts, remote access, and typing cadence over the last minute.",
        )
        self.ctx = ctx
        self.history: list[dict[str, Any]] = []
        self._loading = False

        self.error = Card(title="Could not reach Continuum", amber=True)
        self.error_text = self.error.add_text("")
        self.error.hide()
        self.content.addWidget(self.error)

        self.not_running = Card(title="Protection is off", amber=True)
        self.not_running.add_text(
            "The HID Firewall runtime is not running, so nothing is being watched. Starting it "
            "shows one Windows administrator prompt."
        )
        start = QPushButton("Start protection")
        start.setObjectName("Primary")
        start.clicked.connect(ctx.start_protection)
        self.not_running.body.addWidget(start, alignment=Qt.AlignmentFlag.AlignLeft)
        self.not_running.hide()
        self.content.addWidget(self.not_running)

        stats = QHBoxLayout()
        self.runtime_card = StatCard("Runtime")
        self.elevated_card = StatCard("Elevated")
        self.mode_card = StatCard("Response mode")
        self.threshold_card = StatCard("Threshold")
        for card in (self.runtime_card, self.elevated_card, self.mode_card, self.threshold_card):
            stats.addWidget(card, 1)
        self.content.addLayout(stats)

        self.section("Keyboards")
        self.devices_grid = QGridLayout()
        self.devices_grid.setSpacing(12)
        self.content.addLayout(self.devices_grid)

        self.section("Remote access")
        remote_row = QHBoxLayout()
        self.remote_card = Card()
        title_row = QHBoxLayout()
        title_row.addWidget(
            plain_label("Typing through remote-access tools", name="CardTitle"), 1
        )
        self.remote_badge = Badge("...", "gray")
        title_row.addWidget(self.remote_badge)
        self.remote_card.body.addLayout(title_row)
        self.remote_hint = self.remote_card.add_text("", name="Hint")
        self.remote_last = self.remote_card.add_text("", name="Hint")
        remote_row.addWidget(self.remote_card, 3)
        self.remote_button = QPushButton("Allow for 30 min")
        self.remote_button.setToolTip(
            "Use this when you are controlling this PC remotely yourself."
        )
        self.remote_button.clicked.connect(self._toggle_remote)
        remote_row.addWidget(self.remote_button, 1, Qt.AlignmentFlag.AlignTop)
        self.content.addLayout(remote_row)
        self._remote_allowed = False

        self.section("Inter-key interval, last 60 seconds")
        self.chart = LineChart(window_seconds=60, y_label="mean inter-key interval (ms)")
        self.content.addWidget(self.chart)
        self.content.addWidget(
            plain_label(
                "A point appears each time the runtime scores a window of typing on a keyboard.",
                name="Hint",
            )
        )
        self.content.addStretch(1)

    # --- data ----------------------------------------------------------------

    def refresh(self) -> None:
        if self._loading:
            return
        self._loading = True
        client = self.ctx.client

        def load() -> tuple[dict, list, dict | None]:
            runtime = client.runtime()
            snapshots = client.live()
            try:
                remote = client.remote()
            except Exception:  # noqa: BLE001 - the card says so; the page still works
                remote = None
            return runtime, snapshots, remote

        run_async(load, self._show, self._fail)

    def _fail(self, message: str) -> None:
        self._loading = False
        self.error_text.setText(message)
        self.error.show()

    def _show(self, data: tuple[dict, list, dict | None]) -> None:
        self._loading = False
        self.error.hide()
        runtime, snapshots, remote = data
        now = datetime.now(UTC)
        self.history = helpers.update_interval_history(self.history, snapshots, now=now)

        if runtime["state"] == "never_started":
            self.runtime_card.set("Never started", "No heartbeat recorded yet")
        else:
            self.runtime_card.set(
                "Running" if runtime["running"] else "Stopped",
                "Last heartbeat "
                + helpers.format_relative_age(runtime["last_heartbeat"], now=now),
            )
        self.not_running.setVisible(not runtime["running"])
        elevated = runtime.get("elevated")
        self.elevated_card.set(
            "unknown" if elevated is None else ("Yes" if elevated else "No"),
            "Needed to disable devices" if elevated is False else "",
        )
        hints = []
        if runtime.get("configured_mode") and runtime["configured_mode"] != runtime.get(
            "effective_mode"
        ):
            hints.append(f"configured: {helpers.mode_label(runtime['configured_mode'])}")
        if runtime.get("dry_run"):
            hints.append("dry run, no real actions")
        self.mode_card.set(helpers.mode_label(runtime.get("effective_mode")), ", ".join(hints))
        if runtime.get("model_version") == "none":
            self.threshold_card.set("not trained", "Record your typing on the Train page")
        else:
            threshold = runtime.get("threshold")
            sensitivity = runtime.get("sensitivity")
            self.threshold_card.set(
                "unknown" if threshold is None else f"{threshold:.4f}",
                f"sensitivity {sensitivity}" if sensitivity else "",
            )

        devices = helpers.merge_devices(runtime.get("devices") or [], snapshots)
        self._show_devices(devices, now=now, runtime_running=bool(runtime["running"]))
        self._show_remote(remote, now=now)

        names = {device["device_id"]: device["name"] for device in devices}
        series: dict[str, list[tuple[datetime, float]]] = {}
        for point in self.history:
            label = helpers.short_device_label(point["device_id"], names)
            series.setdefault(label, []).append((point["time"], point["interval_ms"]))
        self.chart.set_data(series, now)

    def _show_devices(self, devices: list[dict], *, now: datetime, runtime_running: bool) -> None:
        clear_layout(self.devices_grid)
        if not devices:
            card = Card()
            card.add_text(
                "No keyboards reported yet. Start protection; attached keyboards appear here "
                "within seconds."
            )
            self.devices_grid.addWidget(card, 0, 0, 1, 3)
            return
        for index, device in enumerate(devices):
            self.devices_grid.addWidget(
                self._device_card(device, now=now, runtime_running=runtime_running),
                index // 3,
                index % 3,
            )

    def _device_card(self, device: dict, *, now: datetime, runtime_running: bool) -> QWidget:
        card = Card()
        title = QHBoxLayout()
        title.addWidget(plain_label(breakable(device["name"]), name="CardTitle"), 1)
        title.addWidget(verdict_badge(device["badge"]))
        card.body.addLayout(title)
        card.add_text(breakable(f"{device['vendor_product']} {device['bus_type']}".strip()),
                      name="Mono")
        score, limit = device.get("anomaly_score"), device.get("threshold")
        card.add_text(
            f"score {score:.3f} against {limit:.3f}"
            if score is not None and limit is not None
            else "no window scored yet",
            name="Hint",
        )
        notes = []
        if device["disabled"]:
            notes.append(helpers.blocked_note(device))
        if not device["attached"]:
            notes.append("no longer attached")
        age = helpers.format_relative_age(device.get("updated_at"), now=now)
        card.add_text(f"last window {age}" + (", " + ", ".join(notes) if notes else ""),
                      name="Hint")
        if device["disabled"]:
            button = QPushButton("Unblock device")
            button.setObjectName("Primary")
            button.setToolTip("Only once the device has been examined and is known to be safe.")
            button.clicked.connect(
                lambda _=False, d=device, r=runtime_running: self._unblock(d, r)
            )
            card.body.addWidget(button, alignment=Qt.AlignmentFlag.AlignLeft)
        return card

    def _unblock(self, device: dict, runtime_running: bool) -> None:
        answer = QMessageBox.question(
            self,
            "Unblock device",
            f"Lift the block on {device['name']} now?\n\nOnly do this once the device has been "
            "examined and is known to be safe.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        message = (
            "Unblock queued. The runtime applies it within a second."
            if runtime_running
            else "Unblock queued. The runtime is not running, so it applies when it starts."
        )
        run_async(
            lambda: self.ctx.client.unblock(device["device_id"]),
            lambda _: (QMessageBox.information(self, "Unblock device", message), self.refresh()),
            lambda error: QMessageBox.warning(self, "Unblock device", error),
        )

    def _show_remote(self, remote: dict | None, *, now: datetime) -> None:
        if remote is None:
            self.remote_badge.set_badge("unknown", "gray")
            self.remote_hint.setText("Remote-access status unavailable.")
            self.remote_last.setText("")
            self.remote_button.hide()
            return
        summary = helpers.remote_summary(remote, now=now)
        self.remote_badge.set_badge(summary["badge"], summary["colour"])
        self.remote_hint.setText(summary["hint"])
        last = remote.get("last_detected_at")
        if last:
            tools = remote.get("last_tools") or []
            self.remote_last.setText(
                f"Last remote typing blocked {helpers.format_relative_age(last, now=now)}"
                + (f" ({', '.join(tools)})" if tools else "")
                + "."
            )
        else:
            self.remote_last.setText("No remote typing blocked yet.")
        self._remote_allowed = bool(remote.get("allowed"))
        self.remote_button.setVisible(bool(remote.get("enabled")))
        self.remote_button.setText(
            "Stop allowing"
            if self._remote_allowed
            else f"Allow for {remote.get('allow_minutes', 30)} min"
        )

    def _toggle_remote(self) -> None:
        client = self.ctx.client
        call = client.remote_end_allowance if self._remote_allowed else client.remote_allow
        run_async(
            call,
            lambda _: self.refresh(),
            lambda error: QMessageBox.warning(self, "Remote access", error),
        )

