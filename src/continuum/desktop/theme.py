"""The desktop app's look: the dashboard's minimalist palette as a Qt style sheet.

Warm monochrome, 1px hairline borders, a serif for page titles and muted
pastel status badges, taken from continuum.dashboard.style so the app and
the browser dashboard look like one product. System fonts only.
"""

from __future__ import annotations

from continuum.dashboard.style import (
    BONE,
    CANVAS,
    HAIRLINE,
    INK,
    MUTED,
    PASTELS,
    SURFACE,
    TEXT,
    VERDICT_COLOURS,
)

SANS = "Segoe UI"
SERIF = "Georgia"
MONO = "Cascadia Mono, Consolas"

CHART_PALETTE = ["#2F3437", "#1F6C9F", "#9F2F2D", "#346538", "#956400", "#787774"]
CHART_VERDICT_COLOURS = {
    "blocked": PASTELS["red"][1],
    "suspicious": PASTELS["yellow"][1],
    "normal": PASTELS["green"][1],
}

__all__ = [
    "BONE",
    "CANVAS",
    "CHART_PALETTE",
    "CHART_VERDICT_COLOURS",
    "HAIRLINE",
    "INK",
    "MONO",
    "MUTED",
    "PASTELS",
    "SANS",
    "SERIF",
    "STYLE_SHEET",
    "SURFACE",
    "TEXT",
    "VERDICT_COLOURS",
    "badge_colours",
]


def badge_colours(colour: str) -> tuple[str, str]:
    """(background, foreground) for a pastel name, grey if unknown."""
    return PASTELS.get(colour, PASTELS["gray"])


STYLE_SHEET = f"""
QWidget {{
    font-family: "{SANS}";
    font-size: 10pt;
    color: {TEXT};
}}
QMainWindow, QWidget#Canvas, QScrollArea, QScrollArea > QWidget > QWidget {{
    background: {CANVAS};
}}
QWidget#Sidebar {{
    background: {BONE};
    border-right: 1px solid {HAIRLINE};
}}
QLabel#Brand {{
    font-family: "{SERIF}";
    font-size: 19pt;
    color: {INK};
}}
QLabel#PageTitle {{
    font-family: "{SERIF}";
    font-size: 22pt;
    color: {INK};
}}
QLabel#Lede, QLabel#Hint {{
    color: {MUTED};
}}
QLabel#Hint {{
    font-size: 9pt;
}}
QLabel#Mono {{
    font-family: {MONO};
    font-size: 9pt;
    color: {MUTED};
}}
QLabel#Section {{
    font-family: "{SERIF}";
    font-size: 14pt;
    color: {INK};
    padding-top: 10px;
}}
QLabel#Eyebrow {{
    color: {MUTED};
    font-size: 8pt;
    letter-spacing: 1px;
}}
QLabel#CardTitle {{
    color: {INK};
    font-weight: 600;
}}
QLabel#StatValue {{
    font-family: "{SERIF}";
    font-size: 18pt;
    color: {INK};
}}
QLabel#Passage {{
    font-family: "{SERIF}";
    font-size: 12pt;
    color: {INK};
    background: {SURFACE};
    border: 1px solid {HAIRLINE};
    border-radius: 8px;
    padding: 16px 18px;
}}
QFrame#Card {{
    background: {SURFACE};
    border: 1px solid {HAIRLINE};
    border-radius: 8px;
}}
QFrame#AmberCard {{
    background: {PASTELS["yellow"][0]};
    border: 1px solid #F1E4B8;
    border-radius: 8px;
}}
QListWidget#Nav {{
    background: transparent;
    border: none;
    outline: 0;
}}
QListWidget#Nav::item {{
    padding: 8px 10px;
    border-radius: 6px;
    color: {TEXT};
}}
QListWidget#Nav::item:selected {{
    background: {SURFACE};
    color: {INK};
    border: 1px solid {HAIRLINE};
}}
QListWidget#Nav::item:hover:!selected {{
    background: #EFEEEA;
}}
QPushButton {{
    background: {SURFACE};
    border: 1px solid {HAIRLINE};
    border-radius: 6px;
    padding: 6px 14px;
    color: {INK};
}}
QPushButton:hover {{
    border-color: {MUTED};
}}
QPushButton:disabled {{
    color: #B4B3AF;
    border-color: {HAIRLINE};
}}
QPushButton#Primary {{
    background: {INK};
    border: 1px solid {INK};
    color: {SURFACE};
}}
QPushButton#Primary:hover {{
    background: {TEXT};
}}
QPushButton#Primary:disabled {{
    background: #C9C8C4;
    border-color: #C9C8C4;
    color: {SURFACE};
}}
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QDateEdit, QSpinBox {{
    background: {SURFACE};
    border: 1px solid {HAIRLINE};
    border-radius: 6px;
    padding: 5px 8px;
    selection-background-color: {PASTELS["blue"][0]};
    selection-color: {INK};
}}
QPlainTextEdit#TypingBox {{
    background: {BONE};
    font-size: 11pt;
    padding: 12px 14px;
}}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QDateEdit:focus {{
    border-color: {MUTED};
}}
QTableWidget {{
    background: {SURFACE};
    border: 1px solid {HAIRLINE};
    border-radius: 6px;
    gridline-color: {HAIRLINE};
    selection-background-color: {PASTELS["blue"][0]};
    selection-color: {INK};
}}
QHeaderView::section {{
    background: {BONE};
    color: {MUTED};
    border: none;
    border-bottom: 1px solid {HAIRLINE};
    padding: 6px 8px;
}}
QSlider::groove:horizontal {{
    height: 4px;
    background: {HAIRLINE};
    border-radius: 2px;
}}
QSlider::handle:horizontal {{
    background: {INK};
    width: 14px;
    margin: -6px 0;
    border-radius: 7px;
}}
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
}}
QScrollBar::handle:vertical {{
    background: #DAD9D5;
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{
    height: 0;
}}
QToolTip {{
    background: {SURFACE};
    color: {TEXT};
    border: 1px solid {HAIRLINE};
}}
"""
