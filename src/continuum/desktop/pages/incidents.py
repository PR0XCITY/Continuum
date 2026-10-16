"""Incidents: filters, incidents per day, the list, and one incident in detail."""

from __future__ import annotations

import contextlib
from datetime import date

from PySide6.QtCore import QDate, Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDateEdit,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from continuum.common.schemas import SOFTWARE_INPUT_DEVICE_ID
from continuum.dashboard import helpers
from continuum.desktop.context import AppContext
from continuum.desktop.widgets import (
    Badge,
    BarChart,
    Card,
    Page,
    StatCard,
    breakable,
    clear_layout,
    fill_table,
    key_values,
    make_table,
    plain_label,
    style_calendar,
    verdict_badge,
)
from continuum.desktop.worker import run_async

DEFAULT_WINDOW_DAYS = 90
VERDICTS = ("All verdicts", "blocked", "suspicious", "normal")
TABLE_HEADERS = ("Detected (UTC)", "Device", "Verdict", "Pattern", "Score", "Action",
                 "Detect (ms)", "Notes")


def _labelled(text: str, widget: QWidget) -> QWidget:
    box = QWidget()
    layout = QVBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(3)
    layout.addWidget(plain_label(text, name="Hint"))
    layout.addWidget(widget)
    return box


class IncidentsPage(Page):
    refresh_ms = 10000

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(
            "Incidents",
            "Every blocked or suspicious device and every blocked remote session, as recorded "
            "by the connector. Select a row for details, to unblock the device, or to ask "
            "IncidentRAG about it.",
        )
        self.ctx = ctx
        self.items: list[dict] = []
        self.runtime_running = False
        self._loading = False

        self.error = Card(title="Could not load incidents", amber=True)
        self.error_text = self.error.add_text("")
        self.error.hide()
        self.content.addWidget(self.error)

        stats = QHBoxLayout()
        self.total_card = StatCard("Incidents recorded")
        self.score_card = StatCard("Mean anomaly score")
        self.ttd_card = StatCard("Mean time to detect")
        for card in (self.total_card, self.score_card, self.ttd_card):
            stats.addWidget(card, 1)
        self.content.addLayout(stats)

        filters = QHBoxLayout()
        today = QDate.currentDate()
        self.start = QDateEdit(today.addDays(-DEFAULT_WINDOW_DAYS))
        self.end = QDateEdit(today)
        for edit in (self.start, self.end):
            edit.setCalendarPopup(True)
            style_calendar(edit.calendarWidget())
            edit.setDisplayFormat("yyyy-MM-dd")
            edit.setMaximumDate(today)
            edit.dateChanged.connect(self.refresh)
        self.verdict = QComboBox()
        self.verdict.addItems(VERDICTS)
        self.verdict.currentIndexChanged.connect(self.refresh)
        self.pattern = QComboBox()
        self.pattern.addItem("All patterns", None)
        for key, label in helpers.ATTACK_PATTERN_LABELS.items():
            self.pattern.addItem(label, key)
        self.pattern.currentIndexChanged.connect(self.refresh)
        self.search = QLineEdit()
        self.search.setPlaceholderText("device name, device id, notes or incident id")
        self.search.textChanged.connect(self._apply_search)
        filters.addWidget(_labelled("From", self.start))
        filters.addWidget(_labelled("To", self.end))
        filters.addWidget(_labelled("Verdict", self.verdict))
        filters.addWidget(_labelled("Attack pattern", self.pattern))
        filters.addWidget(_labelled("Search", self.search), 2)
        self.content.addLayout(filters)

        self.section("Incidents per day")
        self.chart = BarChart()
        self.content.addWidget(self.chart)
        self.truncated = plain_label("", name="Hint")
        self.content.addWidget(self.truncated)

        self.count_label = self.section("Incidents")
        self.table = make_table(selectable=True)
        self.table.setMinimumHeight(280)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.content.addWidget(self.table)

        self.detail = QVBoxLayout()
        self.content.addLayout(self.detail)
        self.content.addStretch(1)
        self._listing: dict = {"items": [], "total": 0}
        self._selected_id: str | None = None

    # --- data ----------------------------------------------------------------

    def _range(self) -> tuple[date, date]:
        return self.start.date().toPython(), self.end.date().toPython()

    def refresh(self) -> None:
        if self._loading:
            return
        self._loading = True
        start, end = self._range()
        verdict = self.verdict.currentText()
        params = helpers.build_incident_params(
            start=start,
            end=end,
            verdict=None if verdict == VERDICTS[0] else verdict,
            attack_pattern=self.pattern.currentData(),
            device_id=None,
        )
        client = self.ctx.client

        def load() -> tuple[dict, dict, bool]:
            running = False
            with contextlib.suppress(Exception):  # only affects a hint
                running = bool(client.runtime()["running"])
            return client.stats(), client.incidents(params), running

        run_async(load, self._show, self._fail)

    def _fail(self, message: str) -> None:
        self._loading = False
        self.error_text.setText(message)
        self.error.show()

    def _show(self, data: tuple[dict, dict, bool]) -> None:
        self._loading = False
        self.error.hide()
        stats, listing, self.runtime_running = data
        self.total_card.set(str(stats["total_incidents"]))
        mean_score = stats.get("mean_anomaly_score")
        self.score_card.set("none" if mean_score is None else f"{mean_score:.3f}")
        mean_ttd = stats.get("mean_time_to_detect_ms")
        self.ttd_card.set("none" if mean_ttd is None else f"{mean_ttd:.0f} ms")
        self._listing = listing
        self._apply_search()

    def _apply_search(self) -> None:
        listing = self._listing
        self.items = helpers.filter_by_text(listing["items"], self.search.text())
        start, end = self._range()
        timeline = helpers.daily_counts(self.items, start=start, end=end)
        self.chart.set_data(
            (row.day.date(), row.verdict, int(row.count)) for row in timeline.itertuples()
        )
        self.truncated.setText(
            f"Showing the most recent {len(listing['items'])} of {listing['total']} matching "
            "incidents."
            if listing["total"] > len(listing["items"])
            else ""
        )
        self.count_label.setText(f"{len(self.items)} incidents")

        frame = helpers.incidents_frame(self.items)
        rows = [
            (
                r.detected_at.strftime("%Y-%m-%d %H:%M") if r.detected_at else "",
                r.device,
                r.verdict,
                r.attack_pattern,
                f"{r.anomaly_score:.3f}",
                r.action_taken,
                r.time_to_detect_ms,
                "yes" if r.has_notes else "",
            )
            for r in frame.itertuples()
        ]
        previous = self._selected_id
        self.table.blockSignals(True)
        fill_table(self.table, TABLE_HEADERS, rows)
        index = next(
            (i for i, item in enumerate(self.items) if item["incident_id"] == previous), 0
        )
        if self.items:
            self.table.selectRow(index)
        self.table.blockSignals(False)
        self._show_detail(self.items[index] if self.items else None)

    def _selection_changed(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if rows and rows[0].row() < len(self.items):
            self._show_detail(self.items[rows[0].row()])

    # --- detail --------------------------------------------------------------

    def _show_detail(self, incident: dict | None) -> None:
        clear_layout(self.detail)
        if incident is None:
            self._selected_id = None
            self.detail.addWidget(plain_label("Nothing matches these filters.", name="Hint"))
            return
        self._selected_id = incident["incident_id"]
        device = incident["device"]
        pattern = helpers.ATTACK_PATTERN_LABELS.get(
            incident["attack_pattern"], incident["attack_pattern"]
        )
        followups = ", ".join(f.replace("_", " ") for f in incident["recommended_followups"])

        card = Card(eyebrow="Selected incident")
        title = QHBoxLayout()
        title.addWidget(plain_label(breakable(device["name"]), name="CardTitle"), 1)
        title.addWidget(verdict_badge(incident["verdict"]))
        title.addWidget(Badge(pattern, "blue"))
        card.body.addLayout(title)
        card.body.addWidget(
            key_values(
                [
                    ("Incident", incident["incident_id"]),
                    ("Detected", helpers.format_timestamp(incident["detected_at"])),
                    ("Device id", device["device_id"]),
                    ("Vendor and product", f"{device['vendor_id']}:{device['product_id']}"),
                    (
                        "Anomaly score",
                        f"{incident['anomaly_score']:.3f} against threshold "
                        f"{incident['threshold']:.3f}",
                    ),
                    ("Action taken", incident["action_taken"].replace("_", " ")),
                    *helpers.detection_timing_rows(incident),
                    ("MITRE ATT&CK", incident["mitre_technique"]),
                    ("Recommended follow-ups", followups or "none"),
                ]
            )
        )
        if incident.get("notes"):
            card.body.addWidget(plain_label("NOTES", name="Eyebrow"))
            card.add_text(incident["notes"])
        self.detail.addWidget(card)

        buttons = QHBoxLayout()
        ask = QPushButton("Ask IncidentRAG about this")
        ask.setObjectName("Primary")
        ask.clicked.connect(
            lambda: self.ctx.ask_about(helpers.question_about_incident(incident))
        )
        buttons.addWidget(ask)
        if device["device_id"] == SOFTWARE_INPUT_DEVICE_ID:
            buttons.addWidget(
                plain_label("Remote typing: no physical device was blocked.", name="Hint")
            )
        else:
            unblock = QPushButton("Unblock device")
            unblock.clicked.connect(lambda: self._unblock(device))
            buttons.addWidget(unblock)
        buttons.addStretch(1)
        self.detail.addLayout(buttons)

        summary = incident.get("features_summary") or {}
        if summary:
            toggle = QPushButton("Show cadence features at detection")
            toggle.setCheckable(True)
            table = make_table()
            fill_table(
                table,
                ("feature", "value"),
                [(name, f"{value:.4g}") for name, value in sorted(summary.items())],
            )
            table.setMinimumHeight(260)
            table.hide()
            toggle.toggled.connect(table.setVisible)
            toggle.toggled.connect(
                lambda on: toggle.setText(
                    ("Hide" if on else "Show") + " cadence features at detection"
                )
            )
            self.detail.addWidget(toggle, alignment=Qt.AlignmentFlag.AlignLeft)
            self.detail.addWidget(table)

    def _unblock(self, device: dict) -> None:
        answer = QMessageBox.question(
            self,
            "Unblock device",
            f"Lift the block on {device['name']} now instead of waiting for the automatic "
            "release?\n\nOnly do this once the device has been examined and is known to be safe.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        note = (
            "" if self.runtime_running
            else " The runtime is not running, so the command waits until it starts."
        )
        run_async(
            lambda: self.ctx.client.unblock(device["device_id"]),
            lambda _: QMessageBox.information(
                self, "Unblock device", "Unblock queued. The runtime applies it within a few "
                "seconds." + note
            ),
            lambda error: QMessageBox.warning(self, "Unblock device", error),
        )

