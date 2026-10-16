"""Settings: sensitivity, response mode, dry run and the allowlist."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSlider,
)

from continuum.dashboard import helpers
from continuum.desktop.context import AppContext
from continuum.desktop.widgets import Card, Page, plain_label
from continuum.desktop.worker import run_async
from continuum.detection.scorer import (
    MAX_SENSITIVITY,
    MIN_SENSITIVITY,
    threshold_offset_for_sensitivity,
)


class SettingsPage(Page):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__(
            "Settings",
            "Detection sensitivity, what Continuum does when it blocks a device, and which "
            "devices it must never block. Saved to config/local.yaml; the runtime applies them "
            "the next time it starts.",
        )
        self.ctx = ctx
        self.calibrated: float | None = None
        self.runtime: dict = {}
        self.saved: dict | None = None
        self._loading = False

        self.error = Card(title="Could not load settings", amber=True)
        self.error_text = self.error.add_text("")
        self.error.hide()
        self.content.addWidget(self.error)
        self.env_warning = Card(title="Environment overrides active", amber=True)
        self.env_text = self.env_warning.add_text("")
        self.env_warning.hide()
        self.content.addWidget(self.env_warning)

        self.section("Detection sensitivity")
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(MIN_SENSITIVITY, MAX_SENSITIVITY)
        self.slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.slider.setMaximumWidth(420)
        self.slider.valueChanged.connect(self._preview)
        self.sensitivity_value = plain_label("", name="CardTitle")
        self.content.addLayout(_row(self.slider, self.sensitivity_value))
        self.preview = plain_label("", name="Hint")
        self.content.addWidget(self.preview)

        self.section("Response")
        self.modes = QButtonGroup(self)
        mode_row = QHBoxLayout()
        for mode, label in helpers.RESPONSE_MODE_LABELS.items():
            button = QRadioButton(label)
            button.setProperty("mode", mode)
            self.modes.addButton(button)
            mode_row.addWidget(button)
        mode_row.addStretch(1)
        self.content.addLayout(mode_row)
        self.mode_hint = plain_label("", name="Hint")
        self.content.addWidget(self.mode_hint)
        self.modes.buttonToggled.connect(lambda *_: self._mode_hint())
        self.dry_run = QCheckBox("Dry run: log every decision but never lock or disable anything")
        self.content.addWidget(self.dry_run)

        self.section("Allowlist")
        self.content.addWidget(
            plain_label(
                "Devices listed here are never blocked. Use the full Windows device instance id, "
                "not just the vendor and product id, which any attack tool can imitate.",
                name="Hint",
            )
        )
        self.allowlist = QListWidget()
        self.allowlist.setMinimumHeight(140)
        self.content.addWidget(self.allowlist)
        self.attached = QComboBox()
        self.attached.setMinimumWidth(460)
        self.attached.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        add_attached = QPushButton("Add attached keyboard")
        add_attached.clicked.connect(self._add_attached)
        self.content.addLayout(_row(self.attached, add_attached, stretch=True))
        self.manual = QLineEdit()
        self.manual.setPlaceholderText(r"HID\VID_046D&PID_C31C\7&1A2B3C4D&0&0000")
        add_manual = QPushButton("Add id")
        add_manual.clicked.connect(self._add_manual)
        remove = QPushButton("Remove selected")
        remove.clicked.connect(self._remove_selected)
        self.content.addLayout(_row(self.manual, add_manual, remove))

        save = QPushButton("Save settings")
        save.setObjectName("Primary")
        save.clicked.connect(self._save)
        self.content.addLayout(_row(save, stretch=True))
        self.pending = Card(title="Restart the runtime to apply", amber=True)
        self.pending_text = self.pending.add_text("")
        self.pending.hide()
        self.content.addWidget(self.pending)

        rails = Card(title="Safety rails that settings cannot turn off")
        rails.add_text(
            "Whatever is saved here, Continuum never blocks the last remaining keyboard or an "
            "allowlisted device, releases every blocked device after the auto-release timeout, "
            "and releases everything at once from the tray menu's Release all devices, or with "
            ".\\tasks.ps1 release-all."
        )
        self.content.addWidget(rails)
        self.content.addStretch(1)

    # --- data ----------------------------------------------------------------

    def refresh(self) -> None:
        if self._loading:
            return
        self._loading = True
        client = self.ctx.client

        def load() -> tuple[dict, dict, float | None]:
            current = client.get_settings()
            runtime = client.runtime()
            calibrated = runtime.get("calibrated_threshold")
            if not calibrated:
                models = [m for m in client.calibration()["models"] if "error" not in m]
                if models:
                    calibrated = max(models, key=lambda m: m["modified_at"])[
                        "calibrated_threshold"
                    ]
            return current, runtime, calibrated

        run_async(load, self._show, self._fail)

    def _fail(self, message: str) -> None:
        self._loading = False
        self.error_text.setText(message)
        self.error.show()

    def _show(self, data: tuple[dict, dict, float | None]) -> None:
        self._loading = False
        self.error.hide()
        current, self.runtime, self.calibrated = data
        self.saved = current["settings"]
        overridden = current["env_overridden_fields"]
        self.env_warning.setVisible(bool(overridden))
        self.env_text.setText(
            "These values are set by environment variables, which take precedence over anything "
            "saved here: " + ", ".join(overridden)
        )
        self.slider.setValue(self.saved["sensitivity"])
        self._preview()
        for button in self.modes.buttons():
            button.setChecked(button.property("mode") == self.saved["response_mode"])
        self.dry_run.setChecked(bool(self.saved["dry_run"]))
        self.allowlist.clear()
        self.allowlist.addItems(self.saved["allowlist"])
        self._fill_attached()
        self._show_pending()

    def _fill_attached(self) -> None:
        self.attached.clear()
        listed = set(self._allowlist())
        for device in self.runtime.get("devices") or []:
            if device["device_id"] not in listed:
                self.attached.addItem(f"{device['name']}  ({device['device_id']})",
                                      device["device_id"])
        if not self.attached.count():
            self.attached.addItem("No other attached keyboards", None)

    def _allowlist(self) -> list[str]:
        return [self.allowlist.item(i).text() for i in range(self.allowlist.count())]

    def _preview(self) -> None:
        sensitivity = self.slider.value()
        self.sensitivity_value.setText(str(sensitivity))
        text = helpers.sensitivity_description(sensitivity)
        if self.calibrated is not None:
            threshold = self.calibrated + threshold_offset_for_sensitivity(sensitivity)
            text += f". Threshold {threshold:.4f}, calibrated value {self.calibrated:.4f}."
        self.preview.setText(text)

    def _selected_mode(self) -> str | None:
        button = self.modes.checkedButton()
        return button.property("mode") if button else None

    def _mode_hint(self) -> None:
        needs_admin = self._selected_mode() in ("lock_and_disable", "disable_only")
        self.mode_hint.setText(
            "The runtime is not elevated, so it will fall back to lock only until it is started "
            "with administrator rights."
            if needs_admin and self.runtime.get("elevated") is False
            else ""
        )

    def _add_attached(self) -> None:
        device_id = self.attached.currentData()
        if device_id and device_id not in self._allowlist():
            self.allowlist.addItem(device_id)
            self._fill_attached()

    def _add_manual(self) -> None:
        for device_id in helpers.parse_allowlist_text(self.manual.text()):
            if device_id not in self._allowlist():
                self.allowlist.addItem(device_id)
        self.manual.clear()
        self._fill_attached()

    def _remove_selected(self) -> None:
        for item in self.allowlist.selectedItems():
            self.allowlist.takeItem(self.allowlist.row(item))
        self._fill_attached()

    def _save(self) -> None:
        payload = {
            "sensitivity": self.slider.value(),
            "response_mode": self._selected_mode() or "lock_and_disable",
            "dry_run": self.dry_run.isChecked(),
            "allowlist": self._allowlist(),
        }

        def saved(result: dict) -> None:
            self.saved = result["settings"]
            self._show_pending()
            QMessageBox.information(
                self, "Settings", "Saved to config/local.yaml. Restart the runtime to apply."
            )

        run_async(
            lambda: self.ctx.client.put_settings(payload),
            saved,
            lambda error: QMessageBox.warning(self, "Settings", error),
        )

    def _show_pending(self) -> None:
        runtime, saved = self.runtime, self.saved
        if not runtime.get("running") or not saved:
            self.pending.hide()
            return
        pending = []
        if runtime.get("sensitivity") != saved["sensitivity"]:
            pending.append(f"sensitivity {runtime['sensitivity']} to {saved['sensitivity']}")
        if runtime.get("configured_mode") != saved["response_mode"]:
            pending.append(
                f"response mode {helpers.mode_label(runtime['configured_mode'])} to "
                f"{helpers.mode_label(saved['response_mode'])}"
            )
        if runtime.get("dry_run") != saved["dry_run"]:
            pending.append(f"dry run {runtime['dry_run']} to {saved['dry_run']}")
        self.pending.setVisible(bool(pending))
        self.pending_text.setText("Saved but not yet applied: " + "; ".join(pending) + ".")


def _row(*widgets, stretch: bool = False) -> QHBoxLayout:
    layout = QHBoxLayout()
    layout.setSpacing(10)
    for widget in widgets:
        layout.addWidget(widget)
    if stretch:
        layout.addStretch(1)
    return layout
