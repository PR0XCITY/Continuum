"""HID Firewall metrics: simulated attacks, feature ablation, false positive study.

The baseline is the user's recorded one (data/baselines/<user>.npz) when it
exists and is large enough. Otherwise synthetic human typing from
tools/simulate_attacks.py stands in, and every section says so: numbers
from synthetic typing describe the detector's behaviour on the
simulator, not on any real person.

Model thresholds are always calibrated on baseline windows only, before
any attack stream is scored, exactly as tools/train_model.py does.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

from continuum.common.schemas import FeatureWindow
from continuum.detection.baseline import (
    DEFAULT_BASELINE_DIR,
    baseline_path,
    feature_windows_to_matrix,
    load_baseline,
)
from continuum.detection.features import (
    DEFAULT_PAUSE_SPLIT_SECONDS,
    DEFAULT_WINDOW_SIZE,
    DEFAULT_WINDOW_STEP,
    FEATURE_NAMES,
    NANOS_PER_SECOND,
    iter_feature_windows,
)
from continuum.detection.model import CadenceModel, fit_and_calibrate
from continuum.detection.scorer import DEFAULT_DEBOUNCE_SUSPICIOUS_COUNT, Scorer
from tools.evaluate_model import (
    ATTACK_TYPES_TO_EVALUATE,
    EVAL_RANDOM_STATE,
    N_STREAMS_PER_ATTACK_TYPE,
    SEED_BASE,
    TEST_HOLDOUT_FRACTION,
    _attack_windows_and_labels,
    _compute_metrics,
    _split_baseline,
)
from tools.evaluation.common import (
    PALETTE,
    SectionResult,
    fmt,
    fmt_mean_std,
    md_table,
    new_figure,
    save_figure,
)
from tools.simulate_attacks import generate_human

MIN_RECORDED_WINDOWS = 50
SEED_STRIDE = 100_000

SYNTHETIC_DEVICE_ID = "synthetic-baseline-keyboard"
SYNTHETIC_BASELINE_STREAMS = 40
SYNTHETIC_PRESSES_PER_STREAM = 150
SYNTHETIC_BASELINE_SEED = 700_000

FP_HOLDOUT_FRACTION = 0.2
FP_SYNTHETIC_STREAMS = 40
FP_SYNTHETIC_PRESSES = 600
FP_SYNTHETIC_SEED = 800_000
FAST_TYPING_WPM = (120.0, 160.0)

ROLLOVER_AND_DWELL = tuple(
    n for n in FEATURE_NAMES if n.startswith("dwell_") or n == "rollover_ratio"
)
TIMING_ONLY = tuple(n for n in FEATURE_NAMES if n not in ROLLOVER_AND_DWELL)
FEATURE_SUBSETS: dict[str, tuple[str, ...]] = {
    "all features": FEATURE_NAMES,
    "timing only": TIMING_ONLY,
    "rollover and dwell": ROLLOVER_AND_DWELL,
}

METRIC_NAMES = ("precision", "recall", "f1", "false_positive_rate", "roc_auc")


@dataclass
class BaselineData:
    source: str  # "recorded" or "synthetic"
    user: str
    device_id: str
    features: np.ndarray
    feature_names: list[str]
    captured_at: list[datetime] | None

    @property
    def n_windows(self) -> int:
        return int(self.features.shape[0])

    def columns(self, names: Sequence[str]) -> list[int]:
        return [self.feature_names.index(name) for name in names]


def synthetic_baseline() -> BaselineData:
    windows: list[FeatureWindow] = []
    for i in range(SYNTHETIC_BASELINE_STREAMS):
        events = generate_human(
            SYNTHETIC_DEVICE_ID, SYNTHETIC_PRESSES_PER_STREAM, seed=SYNTHETIC_BASELINE_SEED + i
        )
        windows.extend(iter_feature_windows(events, SYNTHETIC_DEVICE_ID))
    return BaselineData(
        source="synthetic",
        user="synthetic",
        device_id=SYNTHETIC_DEVICE_ID,
        features=feature_windows_to_matrix(windows, FEATURE_NAMES),
        feature_names=list(FEATURE_NAMES),
        captured_at=None,
    )


def load_baseline_data(user: str, *, baseline_dir: Path = DEFAULT_BASELINE_DIR) -> BaselineData:
    """The user's recorded baseline if it has enough windows, else synthetic typing."""
    path = baseline_path(user, baseline_dir=baseline_dir)
    if path.exists():
        recorded = load_baseline(path)
        if recorded.n_windows >= MIN_RECORDED_WINDOWS:
            return BaselineData(
                source="recorded",
                user=recorded.user,
                device_id=recorded.device_id,
                features=recorded.features,
                feature_names=recorded.feature_names,
                captured_at=recorded.captured_at,
            )
    return synthetic_baseline()


def fit_model(
    baseline: BaselineData, rows: np.ndarray, feature_names: Sequence[str] = FEATURE_NAMES
) -> CadenceModel:
    return fit_and_calibrate(
        rows[:, baseline.columns(feature_names)],
        feature_names=list(feature_names),
        baseline_device_id=baseline.device_id,
    )


# --- simulated attack streams over several seeds --------------------------------


class AttackStreams:
    """Simulated attack windows per (attack type, seed), generated once and reused."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, int], tuple[list[FeatureWindow], list[int]]] = {}

    def get(self, attack_type: str, seed: int) -> tuple[list[FeatureWindow], list[int]]:
        key = (attack_type, seed)
        if key not in self._cache:
            self._cache[key] = _attack_windows_and_labels(
                attack_type,
                n_streams=N_STREAMS_PER_ATTACK_TYPE,
                window_size=DEFAULT_WINDOW_SIZE,
                window_step=DEFAULT_WINDOW_STEP,
                seed_base=SEED_BASE + seed * SEED_STRIDE,
            )
        return self._cache[key]


def evaluate_seeds(
    baseline: BaselineData,
    seeds: Sequence[int],
    streams: AttackStreams,
    feature_names: Sequence[str] = FEATURE_NAMES,
) -> tuple[dict[str, list[dict[str, float]]], dict[str, tuple[np.ndarray, np.ndarray]]]:
    """Window-level metrics per attack type and seed, plus seed 0's ROC inputs."""
    per_type: dict[str, list[dict[str, float]]] = {a: [] for a in ATTACK_TYPES_TO_EVALUATE}
    roc_inputs: dict[str, tuple[np.ndarray, np.ndarray]] = {}
    for seed in seeds:
        fit_rows, test_rows = _split_baseline(
            baseline.features, TEST_HOLDOUT_FRACTION, EVAL_RANDOM_STATE + seed
        )
        model = fit_model(baseline, fit_rows, feature_names)
        normal_scores = model.score(test_rows[:, baseline.columns(feature_names)])
        for attack_type in ATTACK_TYPES_TO_EVALUATE:
            windows, labels = streams.get(attack_type, seed)
            attack_scores = model.score(feature_windows_to_matrix(windows, feature_names))
            scores = np.concatenate([normal_scores, attack_scores])
            truth = np.concatenate([np.zeros(len(normal_scores), dtype=int), np.array(labels)])
            predicted = (scores > model.threshold).astype(int)
            per_type[attack_type].append(_compute_metrics(truth, predicted, scores))
            if seed == seeds[0]:
                roc_inputs[attack_type] = (truth, scores)
    return per_type, roc_inputs


def simulated_section(
    baseline: BaselineData, seeds: Sequence[int], streams: AttackStreams, figures_dir: Path
) -> SectionResult:
    per_type, roc_inputs = evaluate_seeds(baseline, seeds, streams)

    rows = []
    for attack_type, runs in per_type.items():
        rows.append(
            [attack_type]
            + [fmt_mean_std([run[m] for run in runs]) for m in METRIC_NAMES]
            + [str(runs[0]["n_attack_windows"])]
        )
    table = md_table(
        ["attack type", "precision", "recall", "F1", "FPR", "ROC-AUC", "attack windows per seed"],
        rows,
    )

    fig, ax = new_figure(6, 5)
    ax.grid(color="#EAEAEA", linewidth=0.8)
    for colour, (attack_type, (truth, scores)) in zip(
        PALETTE[1:], roc_inputs.items(), strict=False
    ):
        fpr, tpr, _ = roc_curve(truth, scores)
        auc = roc_auc_score(truth, scores)
        ax.plot(fpr, tpr, color=colour, linewidth=1.6, label=f"{attack_type} (AUC {auc:.2f})")
    ax.plot([0, 1], [0, 1], linestyle="--", color="#BBBBBB", linewidth=1, label="chance")
    ax.set_xlabel("false positive rate")
    ax.set_ylabel("true positive rate")
    ax.set_title(f"ROC per attack type (seed {seeds[0]})")
    ax.legend(loc="lower right", fontsize="small", frameon=False)
    roc_path = save_figure(fig, figures_dir, "detector_roc.png")

    recall = {a: float(np.mean([r["recall"] for r in runs])) for a, runs in per_type.items()}
    window_fpr = float(np.mean([r["false_positive_rate"] for r in per_type["burst_injection"]]))
    markdown = f"""Window-level detection on streams from `tools/simulate_attacks.py`:
{N_STREAMS_PER_ATTACK_TYPE} independently seeded streams per attack type per seed, scored
together with held-out baseline windows (the negative class, never used for training or
calibration). Values are mean ± standard deviation over {len(seeds)} seeds; each seed
re-splits the baseline, refits and recalibrates the model, and draws fresh attack streams.
A window counts as detected when its score exceeds the calibrated threshold; blocking
additionally needs {DEFAULT_DEBOUNCE_SUSPICIOUS_COUNT} flagged windows within the debounce
period, so block-level recall can only be lower than the window-level recall shown here.

{table}

Hybrid streams mix human typing with an injected burst; their windows are labelled by
whichever makes up most of the window, so windows straddling the boundary count as
negatives that look partly like an attack. That is why hybrid's false positive rate and
precision differ from the other rows, which all share the same held-out negatives.

![ROC curves per attack type]({roc_path})
"""
    return SectionResult(markdown, facts={"window_recall": recall, "window_fpr": window_fpr})


# --- ablation ---------------------------------------------------------------------


def ablation_section(
    baseline: BaselineData, seeds: Sequence[int], streams: AttackStreams, figures_dir: Path
) -> SectionResult:
    results: dict[str, dict[str, list[dict[str, float]]]] = {
        name: evaluate_seeds(baseline, seeds, streams, subset)[0]
        for name, subset in FEATURE_SUBSETS.items()
    }

    rows = []
    for attack_type in ATTACK_TYPES_TO_EVALUATE:
        row = [attack_type]
        for name in FEATURE_SUBSETS:
            runs = results[name][attack_type]
            row.append(
                f"{fmt_mean_std([r['recall'] for r in runs], 2)} / "
                f"{fmt_mean_std([r['roc_auc'] for r in runs], 2)}"
            )
        rows.append(row)
    table = md_table(["attack type", *FEATURE_SUBSETS], rows)

    fig, ax = new_figure(7.5, 4)
    width = 0.8 / len(FEATURE_SUBSETS)
    positions = np.arange(len(ATTACK_TYPES_TO_EVALUATE))
    for i, (name, colour) in enumerate(zip(FEATURE_SUBSETS, PALETTE, strict=False)):
        values = [
            float(np.nanmean([r["roc_auc"] for r in results[name][a]]))
            for a in ATTACK_TYPES_TO_EVALUATE
        ]
        ax.bar(positions + (i - 1) * width, values, width, color=colour, label=name)
    ax.set_xticks(positions, ATTACK_TYPES_TO_EVALUATE)
    ax.set_ylim(0, 1.05)
    ax.axhline(0.5, color="#BBBBBB", linestyle="--", linewidth=1)
    ax.set_ylabel("ROC-AUC (mean over seeds)")
    ax.set_title("Which features matter")
    ax.legend(
        fontsize="small", frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.1), ncol=3
    )
    figure = save_figure(fig, figures_dir, "detector_ablation.png")

    auc = {
        name: {
            a: float(np.nanmean([r["roc_auc"] for r in results[name][a]]))
            for a in ATTACK_TYPES_TO_EVALUATE
        }
        for name in FEATURE_SUBSETS
    }
    recall = {
        name: {
            a: float(np.mean([r["recall"] for r in results[name][a]]))
            for a in ATTACK_TYPES_TO_EVALUATE
        }
        for name in FEATURE_SUBSETS
    }
    markdown = f"""The same evaluation, refitting and recalibrating the model on three feature
subsets. Timing only is every inter-key interval feature ({len(TIMING_ONLY)} features:
`flight_*`, `burst_score`, `interval_entropy`, `autocorr_lag1`, `regularity_ratio`).
Rollover and dwell is how long keys are held and whether they overlap
({len(ROLLOVER_AND_DWELL)} features: `dwell_*`, `rollover_ratio`). Each cell is
window-level recall / ROC-AUC, mean ± standard deviation over {len(seeds)} seeds.

{table}

![ROC-AUC per feature subset]({figure})
"""
    return SectionResult(markdown, facts={"ablation_auc": auc, "ablation_recall": recall})


# --- false positive study -------------------------------------------------------------


@dataclass
class ReplayStats:
    label: str
    source: str
    windows: int
    flagged_windows: int
    blocks: int
    typing_hours: float

    @property
    def blocks_per_hour(self) -> float:
        return self.blocks / self.typing_hours if self.typing_hours else float("nan")

    @property
    def upper_bound_per_hour(self) -> float:
        """95% upper bound on the block rate (rule of three when no block was seen)."""
        if not self.typing_hours:
            return float("nan")
        if self.blocks == 0:
            return 3.0 / self.typing_hours
        return float("nan")


def _replay(model: CadenceModel, windows: Sequence[FeatureWindow]) -> tuple[int, int]:
    """(flagged windows, blocks) for windows of one device in time order."""
    scorer = Scorer(model)
    flagged = blocks = 0
    for window in windows:
        result = scorer.score_window(window)
        if result.verdict != "normal":
            flagged += 1
        if result.verdict == "blocked":
            blocks += 1
            scorer.reset_device(window.device_id)  # as the runtime does after a block
    return flagged, blocks


def recorded_windows(
    baseline: BaselineData, rows: Sequence[int], feature_names: Sequence[str]
) -> list[FeatureWindow]:
    """FeatureWindows for recorded baseline rows, in time order.

    Older recordings stored one timestamp per sitting; windows sharing a
    timestamp are spaced by their own mean inter-key interval times the
    window step, which is how far apart consecutive windows really are.
    """
    assert baseline.captured_at is not None
    ordered = sorted(rows, key=lambda r: (baseline.captured_at[r], r))
    windows: list[FeatureWindow] = []
    offset_ns = 0
    previous_time = None
    flight_mean = baseline.feature_names.index("flight_mean_ms")
    for row in ordered:
        moment = baseline.captured_at[row]
        if moment != previous_time:
            offset_ns = 0
            previous_time = moment
        start_ns = int(moment.timestamp() * NANOS_PER_SECOND) + offset_ns
        offset_ns += int(DEFAULT_WINDOW_STEP * baseline.features[row, flight_mean] * 1_000_000)
        windows.append(
            FeatureWindow(
                device_id=baseline.device_id,
                window_start_ns=start_ns,
                n_events=DEFAULT_WINDOW_SIZE,
                features={
                    name: float(baseline.features[row, baseline.feature_names.index(name)])
                    for name in feature_names
                },
            )
        )
    return windows


def _window_typing_hours(windows: Sequence[FeatureWindow]) -> float:
    # Windows overlap; each new window adds DEFAULT_WINDOW_STEP presses of typing.
    seconds = sum(DEFAULT_WINDOW_STEP * w.features["flight_mean_ms"] / 1000 for w in windows)
    return seconds / 3600


def _synthetic_session(
    label: str, model: CadenceModel, device_id: str, *, seed: int, wpm_range: tuple[float, float]
) -> ReplayStats:
    flagged = blocks = n_windows = 0
    seconds = 0.0
    for i in range(FP_SYNTHETIC_STREAMS):
        events = generate_human(device_id, FP_SYNTHETIC_PRESSES, seed=seed + i, wpm_range=wpm_range)
        presses = [e.timestamp_ns for e in events if e.event_type == "down" and not e.is_repeat]
        gaps = np.diff(presses) / NANOS_PER_SECOND
        seconds += float(gaps[gaps < DEFAULT_PAUSE_SPLIT_SECONDS].sum())
        windows = list(iter_feature_windows(events, device_id))
        n_windows += len(windows)
        stream_flagged, stream_blocks = _replay(model, windows)
        flagged += stream_flagged
        blocks += stream_blocks
    return ReplayStats(label, "synthetic", n_windows, flagged, blocks, seconds / 3600)


def false_positive_section(
    baseline: BaselineData, *, user: str, baseline_dir: Path, figures_dir: Path
) -> SectionResult:
    sessions: list[ReplayStats] = []
    notes: list[str] = []
    feature_names = list(FEATURE_NAMES)

    if baseline.source == "recorded" and baseline.captured_at is not None:
        order = sorted(range(baseline.n_windows), key=lambda r: (baseline.captured_at[r], r))
        n_holdout = max(1, round(baseline.n_windows * FP_HOLDOUT_FRACTION))
        fit_rows, holdout_rows = order[:-n_holdout], order[-n_holdout:]
        model = fit_model(baseline, baseline.features[fit_rows])
        held_out = recorded_windows(baseline, holdout_rows, feature_names)
        flagged, blocks = _replay(model, held_out)
        sessions.append(
            ReplayStats(
                "held-out recorded typing (latest 20 percent)",
                "recorded",
                len(held_out),
                flagged,
                blocks,
                _window_typing_hours(held_out),
            )
        )
        fast_path = baseline_path(f"{user}_fast", baseline_dir=baseline_dir)
        if fast_path.exists():
            fast = load_baseline(fast_path)
            fast_data = BaselineData(
                "recorded", fast.user, baseline.device_id, fast.features,
                fast.feature_names, fast.captured_at,
            )
            fast_windows = recorded_windows(fast_data, range(fast_data.n_windows), feature_names)
            flagged, blocks = _replay(model, fast_windows)
            sessions.append(
                ReplayStats(
                    "recorded fast-typing session", "recorded", len(fast_windows),
                    flagged, blocks, _window_typing_hours(fast_windows),
                )
            )
        else:
            notes.append(
                f"No fast-typing session was found at `data/baselines/{user}_fast.npz`, so the "
                "fast-typing row uses synthetic typing. Record one with "
                f"`python tools/record_baseline.py {user}_fast` while typing as fast as you can."
            )
            sessions.append(
                _synthetic_session(
                    "synthetic fast typing (120 to 160 wpm)", model, baseline.device_id,
                    seed=FP_SYNTHETIC_SEED + 50_000, wpm_range=FAST_TYPING_WPM,
                )
            )
        notes.append(
            "Recorded typing hours are estimated from each window's mean inter-key interval "
            f"times the {DEFAULT_WINDOW_STEP}-press window step, since baselines store window "
            "statistics only, never the keystrokes themselves."
        )
    else:
        model = fit_model(baseline, baseline.features)
        sessions.append(
            _synthetic_session(
                "synthetic held-out typing (40 to 120 wpm)", model, baseline.device_id,
                seed=FP_SYNTHETIC_SEED, wpm_range=(40.0, 120.0),
            )
        )
        sessions.append(
            _synthetic_session(
                "synthetic fast typing (120 to 160 wpm)", model, baseline.device_id,
                seed=FP_SYNTHETIC_SEED + 50_000, wpm_range=FAST_TYPING_WPM,
            )
        )
        notes.append(
            "No recorded baseline was available, so both rows replay synthetic typing against "
            "a model trained on synthetic typing. This shows how the debounce and threshold "
            "behave, not how often a real person would be blocked."
        )

    rows = [
        [
            s.label,
            str(s.windows),
            str(s.flagged_windows),
            str(s.blocks),
            fmt(s.typing_hours * 60, 1),
            fmt(s.blocks_per_hour, 2),
            fmt(s.upper_bound_per_hour, 2) if s.blocks == 0 else "",
        ]
        for s in sessions
    ]
    table = md_table(
        [
            "session",
            "windows",
            "flagged windows",
            "false blocks",
            "typing minutes",
            "false blocks per hour",
            "95% upper bound per hour",
        ],
        rows,
    )

    fig, ax = new_figure(7, 3.6)
    labels = [s.label.split(" (")[0] for s in sessions]
    rates = [s.flagged_windows / s.windows if s.windows else 0.0 for s in sessions]
    ax.bar(labels, rates, color=PALETTE[: len(sessions)])
    ax.set_ylabel("share of windows flagged")
    ax.set_title("Flagged windows during normal typing")
    figure = save_figure(fig, figures_dir, "false_positives.png")

    notes_md = "\n".join(f"- {note}" for note in notes)
    markdown = f"""Typing that is not an attack, replayed through the real scorer (threshold and
{DEFAULT_DEBOUNCE_SUSPICIOUS_COUNT}-window debounce), counting blocks as the runtime would,
including resetting the device after each block. A block here is a false block. When no
block happens, the upper bound column gives the rate that still cannot be ruled out at 95
percent confidence for the amount of typing replayed.

{table}

{notes_md}

![Flagged windows during normal typing]({figure})
"""
    return SectionResult(
        markdown,
        facts={
            "fp_sessions": [
                {"label": s.label, "blocks_per_hour": s.blocks_per_hour, "blocks": s.blocks}
                for s in sessions
            ],
            "fp_model_threshold": model.threshold,
        },
    )


def data_source_lines(baseline: BaselineData, user: str) -> list[str]:
    if baseline.source == "recorded":
        span = ""
        if baseline.captured_at:
            first, last = min(baseline.captured_at), max(baseline.captured_at)
            span = f", recorded {first:%Y-%m-%d} to {last:%Y-%m-%d}"
        return [
            f"Detector baseline: recorded typing for user `{baseline.user}` on device "
            f"`{baseline.device_id}`, {baseline.n_windows} windows{span}."
        ]
    return [
        f"**Detector baseline: synthetic.** No recorded baseline with at least "
        f"{MIN_RECORDED_WINDOWS} windows was found for user `{user}` in `data/baselines/`, so "
        f"{baseline.n_windows} windows of simulated human typing stand in for it. Every HID "
        "Firewall number below therefore measures the detector against the simulator, not "
        f"against real typing. Record a baseline with `python tools/record_baseline.py {user}` "
        "and rerun to replace them."
    ]


def minimum_presses_to_block() -> int:
    """The earliest key press at which any device can be blocked."""
    return DEFAULT_WINDOW_SIZE + (DEFAULT_DEBOUNCE_SUSPICIOUS_COUNT - 1) * DEFAULT_WINDOW_STEP
