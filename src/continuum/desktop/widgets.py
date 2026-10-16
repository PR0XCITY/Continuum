"""Small building blocks for the desktop app's pages.

Every label that can show data from outside the app (device names,
incident notes, LLM answers, retrieved snippets) is created with
plain_label, which forces Qt.PlainText: QLabel would otherwise guess
"rich text" and render HTML inside untrusted strings.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import date, datetime, timedelta

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLayout,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from continuum.desktop import theme

_BREAK_AFTER = re.compile(r"([\\&_\-/.])")
ZERO_WIDTH_SPACE = "​"


def breakable(text: str) -> str:
    """Let long ids wrap: a zero-width space after separators such as a backslash, & and _.

    Display only. Device instance ids have no spaces, so without this one
    id would force a whole page wider than the window.
    """
    return _BREAK_AFTER.sub(lambda m: m.group(1) + ZERO_WIDTH_SPACE, text)


def plain_label(text: str = "", *, name: str | None = None, wrap: bool = True) -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setText(text)
    label.setWordWrap(wrap)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    if name:
        label.setObjectName(name)
    return label


def clear_layout(layout: QLayout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()
        elif item.layout() is not None:
            clear_layout(item.layout())


class Card(QFrame):
    """A white panel with a hairline border; amber for warnings and abstentions."""

    def __init__(self, *, title: str = "", eyebrow: str = "", amber: bool = False) -> None:
        super().__init__()
        self.setObjectName("AmberCard" if amber else "Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(18, 14, 18, 16)
        self.body.setSpacing(6)
        if eyebrow:
            self.body.addWidget(plain_label(eyebrow.upper(), name="Eyebrow"))
        if title:
            self.body.addWidget(plain_label(title, name="CardTitle"))

    def add_text(self, text: str, *, name: str | None = None) -> QLabel:
        label = plain_label(text, name=name)
        self.body.addWidget(label)
        return label


class Badge(QLabel):
    """A muted pastel pill: blocked, suspicious, normal, watching, ..."""

    def __init__(self, text: str = "", colour: str = "gray") -> None:
        super().__init__()
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        self.set_badge(text, colour)

    def set_badge(self, text: str, colour: str) -> None:
        background, foreground = theme.badge_colours(colour)
        self.setText(text.upper())
        self.setStyleSheet(
            f"background:{background};color:{foreground};border-radius:9px;"
            "padding:2px 9px;font-size:8pt;font-weight:600;letter-spacing:1px;"
        )


def verdict_badge(verdict: str) -> Badge:
    return Badge(verdict, theme.VERDICT_COLOURS.get(verdict, "gray"))


class StatCard(Card):
    def __init__(self, label: str) -> None:
        super().__init__(eyebrow=label)
        self.value = plain_label("...", name="StatValue")
        self.hint = plain_label("", name="Hint")
        self.body.addWidget(self.value)
        self.body.addWidget(self.hint)
        self.body.addStretch(1)

    def set(self, value: str, hint: str = "") -> None:
        self.value.setText(breakable(value))
        self.hint.setText(breakable(hint))
        self.hint.setVisible(bool(hint))


def key_values(pairs: Iterable[tuple[str, str]]) -> QWidget:
    widget = QWidget()
    grid = QGridLayout(widget)
    grid.setContentsMargins(0, 4, 0, 0)
    grid.setHorizontalSpacing(18)
    grid.setVerticalSpacing(5)
    for row, (key, value) in enumerate(pairs):
        grid.addWidget(plain_label(key, name="Hint"), row, 0, Qt.AlignmentFlag.AlignTop)
        grid.addWidget(plain_label(value), row, 1)
    grid.setColumnStretch(1, 1)
    return widget


def fill_table(
    table: QTableWidget, headers: Sequence[str], rows: Sequence[Sequence[object]]
) -> None:
    table.clear()
    table.setColumnCount(len(headers))
    table.setRowCount(len(rows))
    table.setHorizontalHeaderLabels(list(headers))
    for r, row in enumerate(rows):
        for c, value in enumerate(row):
            item = QTableWidgetItem("" if value is None else str(value))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            table.setItem(r, c, item)
    table.resizeColumnsToContents()
    table.horizontalHeader().setStretchLastSection(True)


def make_table(*, selectable: bool = False) -> QTableWidget:
    table = QTableWidget()
    table.verticalHeader().setVisible(False)
    table.setShowGrid(False)
    table.setAlternatingRowColors(False)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    if selectable:
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    else:
        table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
    return table


class Page(QScrollArea):
    """A scrollable page with a serif title and a lede, refreshed while visible."""

    refresh_ms: int = 0

    def __init__(self, title: str, lede: str) -> None:
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        content.setObjectName("Canvas")
        self.content = QVBoxLayout(content)
        self.content.setContentsMargins(36, 28, 36, 36)
        self.content.setSpacing(12)
        self.content.addWidget(plain_label(title, name="PageTitle"))
        self.content.addWidget(plain_label(lede, name="Lede"))
        self.setWidget(content)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)

    def section(self, text: str) -> QLabel:
        label = plain_label(text, name="Section")
        self.content.addWidget(label)
        return label

    def on_show(self) -> None:
        self.refresh()
        if self.refresh_ms:
            self._timer.start(self.refresh_ms)

    def on_hide(self) -> None:
        self._timer.stop()

    def refresh(self) -> None:
        """Reload the page's data. Pages override this."""


def row(*widgets: QWidget, stretch_last: bool = False) -> QHBoxLayout:
    layout = QHBoxLayout()
    layout.setSpacing(12)
    for widget in widgets:
        layout.addWidget(widget)
    if stretch_last:
        layout.addStretch(1)
    return layout


# --- painted widgets ---------------------------------------------------------------


class ConfidenceMeter(QWidget):
    """A bar for IncidentRAG's confidence with a mark at the answer threshold."""

    def __init__(self, confidence: float, threshold: float) -> None:
        super().__init__()
        self.confidence = max(0.0, min(1.0, confidence))
        self.threshold = max(0.0, min(1.0, threshold))
        self.setFixedHeight(10)
        self.setMinimumWidth(160)

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt API name
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(0, 2, self.width(), 6)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(theme.HAIRLINE))
        painter.drawRoundedRect(rect, 3, 3)
        colour = (
            theme.PASTELS["green"][1]
            if self.confidence >= self.threshold
            else theme.PASTELS["yellow"][1]
        )
        painter.setBrush(QColor(colour))
        painter.drawRoundedRect(QRectF(0, 2, self.width() * self.confidence, 6), 3, 3)
        painter.setPen(QPen(QColor(theme.INK), 2))
        x = self.width() * self.threshold
        painter.drawLine(QPointF(x, 0), QPointF(x, 10))


def _axis_font() -> QFont:
    font = QFont(theme.SANS)
    font.setPointSize(8)
    return font


class LineChart(QWidget):
    """Lines over the last N seconds, one per series; for typing cadence."""

    def __init__(self, *, window_seconds: int = 60, y_label: str = "") -> None:
        super().__init__()
        self.window_seconds = window_seconds
        self.y_label = y_label
        self.series: dict[str, list[tuple[datetime, float]]] = {}
        self.now: datetime | None = None
        self.setMinimumHeight(240)

    def set_data(self, series: dict[str, list[tuple[datetime, float]]], now: datetime) -> None:
        self.series = series
        self.now = now
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt API name
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(_axis_font())
        left, right, top, bottom = 56, 16, 12, 40
        plot = QRectF(left, top, self.width() - left - right, self.height() - top - bottom)
        points = [value for values in self.series.values() for _, value in values]
        if self.now is None or not points or plot.width() <= 0:
            painter.setPen(QColor(theme.MUTED))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No data yet")
            return
        high = max(points) * 1.15 or 1.0
        start = self.now - timedelta(seconds=self.window_seconds)

        painter.setPen(QPen(QColor(theme.HAIRLINE), 1))
        for step in range(5):
            y = plot.bottom() - plot.height() * step / 4
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(QColor(theme.MUTED))
            painter.drawText(
                QRectF(0, y - 8, left - 8, 16),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                f"{high * step / 4:.0f}",
            )
            painter.setPen(QPen(QColor(theme.HAIRLINE), 1))
        painter.setPen(QColor(theme.MUTED))
        for seconds_ago in (60, 45, 30, 15, 0):
            if seconds_ago > self.window_seconds:
                continue
            x = plot.right() - plot.width() * seconds_ago / self.window_seconds
            label = "now" if seconds_ago == 0 else f"-{seconds_ago}s"
            painter.drawText(QRectF(x - 24, plot.bottom() + 6, 48, 16),
                             Qt.AlignmentFlag.AlignCenter, label)
        if self.y_label:
            painter.drawText(QRectF(plot.left(), plot.bottom() + 22, plot.width(), 16),
                             Qt.AlignmentFlag.AlignCenter, self.y_label)

        legend_x = plot.left() + 8
        for index, (name, values) in enumerate(sorted(self.series.items())):
            colour = QColor(theme.CHART_PALETTE[index % len(theme.CHART_PALETTE)])
            path = QPainterPath()
            for i, (moment, value) in enumerate(sorted(values)):
                x = plot.left() + plot.width() * (
                    (moment - start).total_seconds() / self.window_seconds
                )
                y = plot.bottom() - plot.height() * value / high
                if i == 0:
                    path.moveTo(x, y)
                else:
                    path.lineTo(x, y)
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(colour)
                painter.drawEllipse(QPointF(x, y), 2.6, 2.6)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(colour, 1.6))
            painter.drawPath(path)
            painter.fillRect(QRectF(legend_x, plot.top() + 2, 10, 3), colour)
            painter.setPen(QColor(theme.TEXT))
            text_width = painter.fontMetrics().horizontalAdvance(name)
            painter.drawText(QPointF(legend_x + 14, plot.top() + 7), name)
            legend_x += text_width + 30


class BarChart(QWidget):
    """Stacked bars per day, coloured by verdict; for incidents per day."""

    def __init__(self) -> None:
        super().__init__()
        self.days: list[date] = []
        self.counts: dict[tuple[date, str], int] = {}
        self.verdicts: list[str] = []
        self.setMinimumHeight(180)

    def set_data(self, rows: Iterable[tuple[date, str, int]]) -> None:
        self.counts = {}
        days: set[date] = set()
        verdicts: set[str] = set()
        for day, verdict, count in rows:
            days.add(day)
            verdicts.add(verdict)
            self.counts[(day, verdict)] = count
        self.days = sorted(days)
        self.verdicts = sorted(verdicts)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt API name
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(_axis_font())
        left, right, top, bottom = 40, 12, 10, 26
        plot = QRectF(left, top, self.width() - left - right, self.height() - top - bottom)
        totals = [sum(self.counts.get((d, v), 0) for v in self.verdicts) for d in self.days]
        if not self.days or not any(totals) or plot.width() <= 0:
            painter.setPen(QColor(theme.MUTED))
            painter.drawText(
                self.rect(), Qt.AlignmentFlag.AlignCenter, "No incidents in this range"
            )
            return
        high = max(totals)
        painter.setPen(QPen(QColor(theme.HAIRLINE), 1))
        painter.drawLine(QPointF(plot.left(), plot.bottom()), QPointF(plot.right(), plot.bottom()))
        painter.setPen(QColor(theme.MUTED))
        painter.drawText(QRectF(0, plot.top() - 6, left - 8, 14),
                         Qt.AlignmentFlag.AlignRight, str(high))
        slot = plot.width() / len(self.days)
        bar = max(2.0, min(14.0, slot * 0.6))
        label_every = max(1, int(70 / slot)) if slot else 1
        for index, day in enumerate(self.days):
            x = plot.left() + slot * index + (slot - bar) / 2
            y = plot.bottom()
            for verdict in self.verdicts:
                count = self.counts.get((day, verdict), 0)
                if not count:
                    continue
                height = plot.height() * count / high
                colour = theme.CHART_VERDICT_COLOURS.get(verdict, theme.MUTED)
                painter.fillRect(QRectF(x, y - height, bar, height), QColor(colour))
                y -= height
            if index % label_every == 0:
                painter.setPen(QColor(theme.MUTED))
                painter.drawText(QRectF(x - 30, plot.bottom() + 6, bar + 60, 14),
                                 Qt.AlignmentFlag.AlignCenter, day.strftime("%d %b"))
