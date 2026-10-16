"""Calibration and model: the baseline, the model and threshold, and its evaluation."""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout

from continuum.dashboard import helpers
from continuum.desktop.context import AppContext
from continuum.desktop.widgets import (
    Card,
    Page,
    StatCard,
    clear_layout,
    fill_table,
    make_table,
)
from continuum.desktop.worker import run_async


def _table_rows(records: list[dict]) -> tuple[list[str], list[list[object]]]:
    headers: list[str] = []
    for record in records:
        for key in record:
            if key not in headers:
                headers.append(key)
    return headers, [[record.get(key, "") for key in headers] for record in records]


class CalibrationPage(Page):
    refresh_ms = 30000

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(
            "Calibration and model",
            "The typing baseline the detector was trained on, the model and threshold in use, "
            "and how that model performed against simulated attacks.",
        )
        self.ctx = ctx
        self._loading = False

        self.error = Card(title="Could not load calibration", amber=True)
        self.error_text = self.error.add_text("")
        self.error.hide()
        self.content.addWidget(self.error)

        stats = QHBoxLayout()
        self.age_card = StatCard("Baseline age")
        self.windows_card = StatCard("Baseline windows")
        self.threshold_card = StatCard("Current threshold")
        self.version_card = StatCard("Model version")
        for card in (self.age_card, self.windows_card, self.threshold_card, self.version_card):
            stats.addWidget(card, 1)
        self.content.addLayout(stats)

        self.section("Evaluation")
        self.evaluation = QVBoxLayout()
        self.content.addLayout(self.evaluation)
        self.section("Trained models")
        self.models_table = make_table()
        self.models_table.setMinimumHeight(140)
        self.content.addWidget(self.models_table)
        self.section("Recorded baselines")
        self.baselines_table = make_table()
        self.baselines_table.setMinimumHeight(120)
        self.content.addWidget(self.baselines_table)
        self.content.addStretch(1)

    def refresh(self) -> None:
        if self._loading:
            return
        self._loading = True
        client = self.ctx.client
        run_async(lambda: (client.calibration(), client.runtime()), self._show, self._fail)

    def _fail(self, message: str) -> None:
        self._loading = False
        self.error_text.setText(message)
        self.error.show()

    def _show(self, data: tuple[dict, dict]) -> None:
        self._loading = False
        self.error.hide()
        calibration, runtime = data
        now = datetime.now(UTC)
        models = [m for m in calibration["models"] if "error" not in m]
        active = next((m for m in models if m["version"] == runtime.get("model_version")), None)
        if active is None and models:
            active = max(models, key=lambda m: m["modified_at"])
        baselines = [b for b in calibration["baselines"] if "error" not in b]
        baseline = None
        if active is not None:
            baseline = next((b for b in baselines if b["user"] == active["user"]), None)
        if baseline is None and baselines:
            baseline = max(baselines, key=lambda b: b["modified_at"])

        if baseline:
            self.age_card.set(
                helpers.format_relative_age(baseline["last_captured_at"], now=now),
                f"user {baseline['user']}",
            )
            self.windows_card.set(str(baseline["n_windows"]), f"device {baseline['device_id']}")
        else:
            self.age_card.set("no baseline", "Record one on the Train page")
            self.windows_card.set("0")
        if runtime["running"] and runtime.get("threshold") is not None:
            self.threshold_card.set(
                f"{runtime['threshold']:.4f}",
                f"in use by the runtime, sensitivity {runtime['sensitivity']}",
            )
        elif active is not None:
            self.threshold_card.set(
                f"{active['threshold_at_configured_sensitivity']:.4f}",
                f"calibrated {active['calibrated_threshold']:.4f}, sensitivity "
                f"{calibration['configured_sensitivity']}",
            )
        else:
            self.threshold_card.set("none", "No trained model")
        if active:
            self.version_card.set(
                active["version"],
                f"{active['model_type'].replace('_', ' ')}, target false positive rate "
                f"{active['target_false_positive_rate']:.1%}",
            )
        else:
            self.version_card.set("none", "Train one on the Train page")

        clear_layout(self.evaluation)
        markdown = calibration.get("eval_results_markdown")
        if not markdown:
            card = Card()
            card.add_text("No evaluation yet. Run .\\tasks.ps1 evaluate to create one.")
            self.evaluation.addWidget(card)
        else:
            tables = helpers.parse_markdown_tables(markdown)
            if tables:
                frame = tables[0]
                table = make_table()
                fill_table(table, [str(c) for c in frame.columns], frame.values.tolist())
                table.setMinimumHeight(160)
                self.evaluation.addWidget(table)
            paragraphs = helpers.markdown_prose(markdown)
            if paragraphs:
                card = Card(eyebrow="From docs/eval_results.md")
                for paragraph in paragraphs:
                    card.add_text(paragraph)
                self.evaluation.addWidget(card)

        for table, records, empty in (
            (self.models_table, calibration["models"], "No models in data/models."),
            (self.baselines_table, calibration["baselines"], "No baselines in data/baselines."),
        ):
            headers, rows = _table_rows(records)
            fill_table(table, headers or [empty], rows)

