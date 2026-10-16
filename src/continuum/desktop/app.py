"""The desktop app's window, tray icon and start-up.

On launch it makes sure the connector API is running (starting it hidden
if not), offers to start protection (the elevated runtime, one Windows
prompt), and shows the main window. Closing the window keeps Continuum
in the tray; protection keeps running either way. Only one copy of the
app runs at a time: starting it again brings the existing window back.
"""

from __future__ import annotations

import logging
import os
import sys
import time

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPainterPath, QPixmap
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QListWidget,
    QMainWindow,
    QMenu,
    QMessageBox,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from continuum.common.config import Settings, get_settings
from continuum.common.logging import configure_logging
from continuum.dashboard.api import ApiError, ConnectorClient
from continuum.desktop import backend, theme
from continuum.desktop.context import AppContext
from continuum.desktop.pages.ask import AskPage
from continuum.desktop.pages.calibration import CalibrationPage
from continuum.desktop.pages.incidents import IncidentsPage
from continuum.desktop.pages.live import LivePage
from continuum.desktop.pages.settings import SettingsPage
from continuum.desktop.pages.train import TrainPage
from continuum.desktop.widgets import Page, plain_label
from continuum.desktop.worker import run_async

logger = logging.getLogger(__name__)

APP_NAME = "Continuum"
INSTANCE_KEY = "ContinuumDesktopApp"
STATUS_POLL_MS = 3000
API_START_TIMEOUT_SECONDS = 60.0


def shield_icon(colour: str = theme.INK) -> QIcon:
    """The app and tray icon: a plain shield, drawn so no image file is needed."""
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = size / 32
        path = QPainterPath()
        path.moveTo(QPointF(16 * s, 2 * s))
        path.lineTo(QPointF(28 * s, 6.5 * s))
        path.cubicTo(QPointF(28 * s, 18 * s), QPointF(23 * s, 26 * s), QPointF(16 * s, 30 * s))
        path.cubicTo(QPointF(9 * s, 26 * s), QPointF(4 * s, 18 * s), QPointF(4 * s, 6.5 * s))
        path.closeSubpath()
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(colour))
        painter.drawPath(path)
        painter.setBrush(QColor(theme.SURFACE))
        painter.drawRoundedRect(QRectF(13.5 * s, 9 * s, 5 * s, 13 * s), 1.5 * s, 1.5 * s)
        painter.end()
        icon.addPixmap(pixmap)
    return icon


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings, client: ConnectorClient) -> None:
        super().__init__()
        self.settings = settings
        self.client = client
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(shield_icon())
        self.resize(1280, 860)
        self.setMinimumSize(980, 640)
        self.runtime_running: bool | None = None
        self._quitting = False
        self._told_about_tray = False
        # Set by "Stop protection and quit": also stop the API this app started.
        self.stop_api_on_exit = False

        self.ctx = AppContext(
            client=client,
            settings=settings,
            ask_about=self.ask_about,
            start_protection=self.start_protection,
        )
        self.pages: list[Page] = [
            LivePage(self.ctx),
            IncidentsPage(self.ctx),
            AskPage(self.ctx),
            TrainPage(self.ctx),
            CalibrationPage(self.ctx),
            SettingsPage(self.ctx),
        ]
        self.ask_page = self.pages[2]

        root = QWidget()
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(230)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(18, 22, 18, 18)
        side.addWidget(plain_label(APP_NAME, name="Brand"))
        side.addWidget(plain_label("HID Firewall console", name="Hint"))
        side.addSpacing(18)
        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        for page in ("Live status", "Incidents", "Ask IncidentRAG", "Train",
                     "Calibration and model", "Settings"):
            self.nav.addItem(page)
        self.nav.currentRowChanged.connect(self._switch)
        side.addWidget(self.nav, 1)
        self.connector_status = plain_label("Connecting...", name="Hint")
        self.runtime_status = plain_label("", name="Hint")
        side.addWidget(self.connector_status)
        side.addWidget(self.runtime_status)
        side.addWidget(plain_label(client.base_url, name="Mono"))
        layout.addWidget(sidebar)

        self.stack = QStackedWidget()
        for page in self.pages:
            self.stack.addWidget(page)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self._build_tray()
        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self.poll_status)
        self.status_timer.start(STATUS_POLL_MS)
        self.nav.setCurrentRow(0)

    # --- navigation ------------------------------------------------------------

    def _switch(self, index: int) -> None:
        for i, page in enumerate(self.pages):
            if i != index:
                page.on_hide()
        self.stack.setCurrentIndex(index)
        if 0 <= index < len(self.pages):
            self.pages[index].on_show()

    def ask_about(self, question: str) -> None:
        self.nav.setCurrentRow(self.pages.index(self.ask_page))
        self.ask_page.set_question(question)

    def bring_to_front(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    # --- status and protection -------------------------------------------------

    def poll_status(self) -> None:
        run_async(self.client.runtime, self._status_ok, self._status_failed)

    def _status_ok(self, runtime: dict) -> None:
        self.connector_status.setText("Connector reachable")
        self.runtime_running = bool(runtime["running"])
        self.runtime_status.setText(
            "Protection on" if self.runtime_running else "Protection off"
        )
        self._update_tray()

    def _status_failed(self, message: str) -> None:
        self.connector_status.setText("Connector unreachable")
        self.runtime_status.setText("Protection status unknown")
        self.runtime_running = None
        self._update_tray()
        logger.debug("status poll failed: %s", message)

    def start_protection(self) -> None:
        if not backend.start_runtime():
            QMessageBox.information(
                self,
                "Start protection",
                "The administrator prompt was declined, so protection did not start. The HID "
                "Firewall needs administrator rights to block devices.",
            )
            return
        self.tray.showMessage(
            APP_NAME, "Starting protection. It appears as on within a few seconds.",
            shield_icon(), 4000,
        )
        QTimer.singleShot(4000, self.poll_status)

    def stop_protection(self) -> None:
        backend.request_runtime_stop()
        self.tray.showMessage(
            APP_NAME, "Stopping protection. Every blocked device is released first.",
            shield_icon(), 4000,
        )
        QTimer.singleShot(4000, self.poll_status)

    def release_all(self) -> None:
        answer = QMessageBox.question(
            self,
            "Release all devices",
            "Release every device Continuum has blocked or disabled, whatever its timer says?"
            "\n\nThis needs administrator rights and opens a window with the result.",
        )
        if answer == QMessageBox.StandardButton.Yes and not backend.release_all_devices():
            QMessageBox.information(self, "Release all devices", "The prompt was declined.")

    # --- tray --------------------------------------------------------------------

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(shield_icon(), self)
        menu = QMenu()
        open_action = QAction("Open Continuum", self)
        open_action.triggered.connect(self.bring_to_front)
        self.protection_action = QAction("Start protection", self)
        self.protection_action.triggered.connect(self._toggle_protection)
        release = QAction("Release all devices", self)
        release.triggered.connect(self.release_all)
        quit_action = QAction("Quit (protection keeps running)", self)
        quit_action.triggered.connect(self.quit)
        quit_all = QAction("Stop protection and quit", self)
        quit_all.triggered.connect(self.stop_and_quit)
        menu.addAction(open_action)
        menu.addSeparator()
        menu.addAction(self.protection_action)
        menu.addAction(release)
        menu.addSeparator()
        menu.addAction(quit_action)
        menu.addAction(quit_all)
        self.tray_menu = menu
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)
        self.tray.setToolTip(APP_NAME)
        self.tray.show()

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self.bring_to_front()

    def _toggle_protection(self) -> None:
        if self.runtime_running:
            self.stop_protection()
        else:
            self.start_protection()

    def _update_tray(self) -> None:
        if self.runtime_running:
            self.protection_action.setText("Stop protection")
            self.tray.setToolTip(f"{APP_NAME}: protection on")
            self.tray.setIcon(shield_icon())
        else:
            self.protection_action.setText("Start protection")
            state = "off" if self.runtime_running is False else "unknown"
            self.tray.setToolTip(f"{APP_NAME}: protection {state}")
            self.tray.setIcon(shield_icon(theme.PASTELS["red"][1]))

    # --- closing -----------------------------------------------------------------

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt API name
        if self._quitting:
            event.accept()
            return
        event.ignore()
        self.hide()
        if not self._told_about_tray:
            self._told_about_tray = True
            self.tray.showMessage(
                APP_NAME,
                "Continuum is still running in the tray. Right-click the shield to quit.",
                shield_icon(),
                5000,
            )

    def quit(self) -> None:
        self._quitting = True
        self.tray.hide()
        QApplication.quit()

    def stop_and_quit(self) -> None:
        backend.request_runtime_stop()
        self.stop_api_on_exit = True
        self.quit()


def _already_running() -> bool:
    """True, after asking the running copy to show itself, if the app is already open."""
    socket = QLocalSocket()
    socket.connectToServer(INSTANCE_KEY)
    if socket.waitForConnected(300):
        socket.write(b"show")
        socket.waitForBytesWritten(300)
        socket.disconnectFromServer()
        return True
    return False


def _wait_for_api(client: ConnectorClient, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            client.health()
            return True
        except ApiError:
            time.sleep(0.5)
    return False


def main() -> int:
    settings = get_settings()
    configure_logging(level=settings.logging.level, directory=settings.logging.directory)

    QApplication.setApplicationName(APP_NAME)
    QApplication.setQuitOnLastWindowClosed(False)
    app = QApplication(sys.argv)
    app.setWindowIcon(shield_icon())
    theme.apply_theme(app)

    if _already_running():
        return 0
    server = QLocalServer()
    QLocalServer.removeServer(INSTANCE_KEY)
    server.listen(INSTANCE_KEY)

    token = os.environ.get(settings.connector.auth_token_env_var, "")
    if not token:
        QMessageBox.critical(
            None,
            APP_NAME,
            f"No API token found. Run .\\tasks.ps1 setup, or copy .env.example to .env and set "
            f"{settings.connector.auth_token_env_var}, then open Continuum again.",
        )
        return 1

    client = ConnectorClient(f"http://{settings.connector.host}:{settings.connector.port}", token)
    api_process = None
    try:
        client.health()
    except ApiError:
        api_process = backend.start_api(settings)

    window = MainWindow(settings, client)

    def on_connection() -> None:
        connection = server.nextPendingConnection()
        if connection is not None:
            connection.readyRead.connect(window.bring_to_front)

    server.newConnection.connect(on_connection)
    window.show()

    def api_ready(ready: bool) -> None:
        if not ready:
            QMessageBox.warning(
                window,
                APP_NAME,
                "The connector API did not start. See data\\logs\\api.log for the reason.",
            )
            return
        window.poll_status()
        window.pages[window.stack.currentIndex()].on_show()

        def offer_protection(runtime: dict) -> None:
            if not runtime["running"]:
                window.start_protection()

        run_async(client.runtime, offer_protection)

    run_async(lambda: _wait_for_api(client, API_START_TIMEOUT_SECONDS), api_ready)
    try:
        return app.exec()
    finally:
        # Quitting while protection runs leaves the API up: the runtime reports
        # incidents to it, and the app reconnects to it next time.
        if window.stop_api_on_exit:
            backend.stop_api(api_process)
        client.close()
