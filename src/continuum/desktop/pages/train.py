"""Train: record the typing baseline from a paragraph and train the model."""

from __future__ import annotations

import time

from PySide6.QtCore import QMimeData, Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
)

from continuum.dashboard import helpers
from continuum.desktop.context import AppContext
from continuum.desktop.typing_stats import typing_stats
from continuum.desktop.widgets import Card, Page, StatCard, plain_label
from continuum.desktop.worker import run_async
from continuum.rag.ingest import resolve_corpus_path


class TypingBox(QPlainTextEdit):
    """A box to type the paragraph into. Pasting is refused: it produces no keystrokes."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("TypingBox")
        self.setPlaceholderText("Click here and type the paragraph above at your usual pace.")
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        self.setMinimumHeight(150)

    def canInsertFromMimeData(self, source: QMimeData) -> bool:  # noqa: N802 - Qt API name
        return False

    def insertFromMimeData(self, source: QMimeData) -> None:  # noqa: N802 - Qt API name
        return


class TrainPage(Page):
    refresh_ms = 2000

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(
            "Train",
            "Teach Continuum your typing rhythm. Start recording, type the paragraph at your "
            "usual pace on the keyboard you normally use, then stop and save. Repeat with the "
            "next paragraph until the baseline is large enough, then train.",
        )
        self.ctx = ctx
        self.content.addWidget(
            plain_label(
                "Only key timing is recorded, through the same Raw Input capture detection uses; "
                "never which keys you press. What you type in the box stays in this app.",
                name="Hint",
            )
        )
        self.passages = helpers.typing_passages(resolve_corpus_path(ctx.settings))
        self._loading = False
        self._saved_seen: int | None = None
        self._status: dict | None = None

        self.error = Card(title="Could not reach Continuum", amber=True)
        self.error_text = self.error.add_text("")
        self.error.hide()
        self.content.addWidget(self.error)

        stats = QHBoxLayout()
        self.runtime_card = StatCard("Runtime")
        self.baseline_card = StatCard("Baseline")
        self.model_card = StatCard("Model")
        for card in (self.runtime_card, self.baseline_card, self.model_card):
            stats.addWidget(card, 1)
        self.content.addLayout(stats)

        self.runtime_warning = Card(title="Protection is off", amber=True)
        self.runtime_warning.add_text(
            "Recording needs the HID Firewall runtime, because it captures your typing from the "
            "physical keyboard exactly the way detection does. Starting it shows one Windows "
            "administrator prompt."
        )
        start_runtime = QPushButton("Start protection")
        start_runtime.setObjectName("Primary")
        start_runtime.clicked.connect(ctx.start_protection)
        self.runtime_warning.body.addWidget(start_runtime, alignment=Qt.AlignmentFlag.AlignLeft)
        self.runtime_warning.hide()
        self.content.addWidget(self.runtime_warning)

        self.session_text = plain_label("")
        self.content.addWidget(self.session_text)
        controls = QHBoxLayout()
        self.record_button = QPushButton("Start recording")
        self.record_button.setObjectName("Primary")
        self.record_button.clicked.connect(self._record_clicked)
        self.train_button = QPushButton("Train model")
        self.train_button.clicked.connect(self._train)
        self.reset_button = QPushButton("Start over")
        self.reset_button.clicked.connect(self._reset)
        controls.addWidget(self.record_button)
        controls.addWidget(self.train_button)
        controls.addWidget(self.reset_button)
        controls.addStretch(1)
        self.content.addLayout(controls)

        self.paragraph_title = self.section("Paragraph")
        self.speed_hint = plain_label("For this one, type faster than usual: fast typing is "
                                      "still you.", name="Hint")
        self.speed_hint.hide()
        self.content.addWidget(self.speed_hint)
        self.passage = plain_label("", name="Passage")
        self.content.addWidget(self.passage)
        self.box = TypingBox()
        self.box.textChanged.connect(self._typed)
        self.content.addWidget(self.box)
        self.typing_stats = plain_label("Speed and accuracy appear here as you type.",
                                        name="Hint")
        self.content.addWidget(self.typing_stats)
        self.content.addStretch(1)
        self._typing_started: float | None = None
        self._paragraph_index = 0

    # --- polling ------------------------------------------------------------

    def refresh(self) -> None:
        if self._loading:
            return
        self._loading = True
        run_async(self.ctx.client.training, self._show, self._fail)

    def _fail(self, message: str) -> None:
        self._loading = False
        self.error_text.setText(message)
        self.error.show()

    def _show(self, status: dict) -> None:
        self._loading = False
        self.error.hide()
        self._status = status
        baseline, model, session = status["baseline"], status["model"], status["session"]
        minimum, recommended = status["minimum_windows"], status["recommended_windows"]
        active = bool(session) and session["state"] in ("requested", "recording")

        self.runtime_card.set(
            "Running" if status["runtime_running"] else "Not running",
            "Records your typing through Raw Input" if status["runtime_running"]
            else "Start protection to record",
        )
        self.baseline_card.set(
            f"{baseline['n_windows']} of {recommended} windows",
            helpers.baseline_progress(baseline["n_windows"], minimum, recommended),
        )
        self.model_card.set(
            "Trained" if model["exists"] else "Not trained",
            model["version"] or "Protection starts once a model is trained",
        )
        self.runtime_warning.setVisible(not status["runtime_running"])

        if active:
            if session["state"] == "requested":
                self.session_text.setText("Waiting for the runtime to start recording...")
            else:
                self.session_text.setText(
                    f"Recording. {session['presses']} key presses so far. Type the paragraph "
                    "below at your usual pace, then stop and save. Detection is paused while you "
                    "record."
                )
            self.record_button.setText("Stop and save")
            self.record_button.setEnabled(True)
        else:
            if session and session["state"] == "saved":
                self.session_text.setText(
                    f"Last session saved: {session['windows_saved']} windows added."
                )
            elif session and session["state"] in ("failed", "cancelled") and session["message"]:
                self.session_text.setText(session["message"])
            else:
                self.session_text.setText("")
            self.record_button.setText("Start recording")
            self.record_button.setEnabled(bool(status["runtime_running"]))
        self.train_button.setEnabled(baseline["n_windows"] >= minimum and not active)
        self.reset_button.setEnabled(not active)

        if self._saved_seen != status["saved_sessions"]:
            self._saved_seen = status["saved_sessions"]
            self._next_paragraph(status["saved_sessions"])

    def _next_paragraph(self, saved_sessions: int) -> None:
        index, passage = helpers.passage_for_session(self.passages, saved_sessions)
        self._paragraph_index = index
        self.paragraph_title.setText(f"Paragraph {index + 1} of {len(self.passages)}")
        self.speed_hint.setVisible(saved_sessions == 2)
        self.passage.setText(passage)
        self.box.blockSignals(True)
        self.box.clear()
        self.box.blockSignals(False)
        self._typing_started = None
        self.typing_stats.setText("Speed and accuracy appear here as you type.")

    # --- actions ------------------------------------------------------------

    def _record_clicked(self) -> None:
        session = (self._status or {}).get("session")
        active = bool(session) and session["state"] in ("requested", "recording")
        client = self.ctx.client
        call = client.training_stop if active else (
            lambda: client.training_start(self._paragraph_index)
        )
        if not active:
            self.box.setFocus()
        self.record_button.setEnabled(False)
        run_async(call, lambda _: self.refresh(), self._action_failed)

    def _train(self) -> None:
        self.train_button.setEnabled(False)
        self.train_button.setText("Training...")

        def done(result: dict) -> None:
            self.train_button.setText("Train model")
            QMessageBox.information(
                self,
                "Train model",
                f"Model {result['model']['version']} trained. The runtime starts using it "
                "within a few seconds.",
            )
            self.refresh()

        def failed(message: str) -> None:
            self.train_button.setText("Train model")
            self._action_failed(message)

        run_async(self.ctx.client.training_train, done, failed)

    def _reset(self) -> None:
        answer = QMessageBox.question(
            self,
            "Start over",
            "Delete the recorded baseline and record from scratch, for example after switching "
            "keyboards?\n\nA trained model keeps protecting you until you retrain.",
        )
        if answer == QMessageBox.StandardButton.Yes:
            run_async(self.ctx.client.training_reset, lambda _: self.refresh(),
                      self._action_failed)

    def _action_failed(self, message: str) -> None:
        QMessageBox.warning(self, "Train", message)
        self.refresh()

    def _typed(self) -> None:
        typed = self.box.toPlainText()
        if self._typing_started is None and typed:
            self._typing_started = time.monotonic()
        elapsed = time.monotonic() - self._typing_started if self._typing_started else 0.0
        self.typing_stats.setText(typing_stats(typed, self.passage.text(), elapsed).describe())
