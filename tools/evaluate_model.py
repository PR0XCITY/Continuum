"""Evaluate a cadence model against simulated attacks and held-out humans.

Splits the real baseline into a fit/calibration slice and a held-out
test slice (20 percent, never seen during training or calibration).
Fits and calibrates a fresh model on the fit slice only, exactly the
way tools/train_model.py does, then scores:

    - the held-out real baseline windows (the true negative class), and
    - several independently seeded synthetic streams per attack type
      from tools/simulate_attacks.py (the positive class for that row).

Reports precision, recall, F1, false positive rate and ROC-AUC per
attack type to docs/eval_results.md, plus an ROC curve plot. The
decision threshold is fixed by baseline-only calibration before any
attack stream is generated or scored; nothing here is tuned against the
attack streams themselves.

Usage:
    python tools/evaluate_model.py [user] \
        [--model-type isolation_forest|one_class_svm] [--target-fpr 0.01]
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score, roc_curve

from continuum.detection.baseline import baseline_path, feature_windows_to_matrix, load_baseline
from continuum.detection.features import (
    DEFAULT_WINDOW_SIZE,
    DEFAULT_WINDOW_STEP,
    iter_feature_windows,
)
from continuum.detection.model import DEFAULT_TARGET_FALSE_POSITIVE_RATE, fit_and_calibrate

# tools/ is dev-only and not pip-installed, so running this file directly
# (python tools/evaluate_model.py) needs the repo root on sys.path for the
# "tools.simulate_attacks" import below to resolve; pytest already has
# this via pyproject.toml's pythonpath, but a direct run does not.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.simulate_attacks import generate, generate_hybrid  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_PATH = REPO_ROOT / "docs" / "eval_results.md"
ROC_PLOT_PATH = REPO_ROOT / "docs" / "eval_roc_curve.png"
ROC_PLOT_RELATIVE_NAME = "eval_roc_curve.png"

EVAL_RANDOM_STATE = 12345
TEST_HOLDOUT_FRACTION = 0.2
MIN_BASELINE_WINDOWS_FOR_EVAL = 20

ATTACK_DEVICE_ID = "simulated-attack-device"
ATTACK_TYPES_TO_EVALUATE = (
    "burst_injection",
    "slowed_injection",
    "randomized_injection",
    "hybrid",
)
ATTACK_TYPE_SEED_OFFSETS = {
    "burst_injection": 0,
    "slowed_injection": 10_000,
    "randomized_injection": 20_000,
    "hybrid": 30_000,
}
EXPECTED_WEAK_ATTACK_TYPES = ("slowed_injection", "randomized_injection")
WEAK_RECALL_THRESHOLD = 0.7

N_STREAMS_PER_ATTACK_TYPE = 20
N_PRESSES_PER_STREAM = 150
SEED_BASE = 1000

# Sized so that, at the default window_size/window_step, several windows
# land fully inside the injected burst and several fully outside it; a
# short, realistic burst (the simulate_attacks.py default) is too brief
# relative to one window to label any window as attack-majority.
EVAL_HYBRID_N_HUMAN_BEFORE = 80
EVAL_HYBRID_N_BURST = 60
EVAL_HYBRID_N_HUMAN_AFTER = 80


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("user", nargs="?", default=getpass.getuser())
    parser.add_argument(
        "--model-type",
        choices=["isolation_forest", "one_class_svm"],
        default="isolation_forest",
    )
    parser.add_argument("--target-fpr", type=float, default=DEFAULT_TARGET_FALSE_POSITIVE_RATE)
    return parser.parse_args()


def _split_baseline(
    features: np.ndarray, test_fraction: float, random_state: int
) -> tuple[np.ndarray, np.ndarray]:
    """Disjoint (fit_and_calibrate_slice, held_out_test_slice)."""
    n = features.shape[0]
    rng = np.random.default_rng(random_state)
    indices = rng.permutation(n)
    n_test = max(1, int(round(n * test_fraction)))
    test_idx, fit_idx = indices[:n_test], indices[n_test:]
    return features[fit_idx], features[test_idx]


def _label_hybrid_windows(n_windows: int, *, window_size: int, window_step: int) -> list[int]:
    """Ground truth label per hybrid window: 1 if attack-majority, else 0.

    A window is labelled an attack only if more than half its presses
    fall inside the injected burst segment, using the same press-index
    math iter_feature_windows uses to emit windows (no pauses in a
    hybrid stream, so there is exactly one run and windows start at
    press index 0, window_step, 2*window_step, ...).
    """
    burst_start = EVAL_HYBRID_N_HUMAN_BEFORE
    burst_end = EVAL_HYBRID_N_HUMAN_BEFORE + EVAL_HYBRID_N_BURST

    labels = []
    for k in range(n_windows):
        press_start = k * window_step
        press_end = press_start + window_size
        overlap = max(0, min(press_end, burst_end) - max(press_start, burst_start))
        labels.append(1 if overlap > window_size / 2 else 0)
    return labels


def _attack_windows_and_labels(
    attack_type: str,
    *,
    n_streams: int,
    window_size: int,
    window_step: int,
) -> tuple[list, list[int]]:
    windows: list = []
    labels: list[int] = []
    offset = ATTACK_TYPE_SEED_OFFSETS[attack_type]

    for i in range(n_streams):
        seed = SEED_BASE + offset + i

        if attack_type == "hybrid":
            events = generate_hybrid(
                ATTACK_DEVICE_ID,
                seed=seed,
                n_human_before=EVAL_HYBRID_N_HUMAN_BEFORE,
                n_burst=EVAL_HYBRID_N_BURST,
                n_human_after=EVAL_HYBRID_N_HUMAN_AFTER,
            )
            stream_windows = list(
                iter_feature_windows(
                    events, ATTACK_DEVICE_ID, window_size=window_size, window_step=window_step
                )
            )
            stream_labels = _label_hybrid_windows(
                len(stream_windows), window_size=window_size, window_step=window_step
            )
        else:
            events = generate(attack_type, ATTACK_DEVICE_ID, N_PRESSES_PER_STREAM, seed=seed)
            stream_windows = list(
                iter_feature_windows(
                    events, ATTACK_DEVICE_ID, window_size=window_size, window_step=window_step
                )
            )
            stream_labels = [1] * len(stream_windows)

        windows.extend(stream_windows)
        labels.extend(stream_labels)

    return windows, labels


def _compute_metrics(
    true_labels: np.ndarray, predicted_labels: np.ndarray, scores: np.ndarray
) -> dict[str, float]:
    precision = precision_score(true_labels, predicted_labels, zero_division=0)
    recall = recall_score(true_labels, predicted_labels, zero_division=0)
    f1 = f1_score(true_labels, predicted_labels, zero_division=0)

    normal_mask = true_labels == 0
    false_positive_rate = (
        float(predicted_labels[normal_mask].mean()) if normal_mask.any() else 0.0
    )

    has_both_classes = len(set(true_labels.tolist())) > 1
    roc_auc = float(roc_auc_score(true_labels, scores)) if has_both_classes else float("nan")

    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "false_positive_rate": false_positive_rate,
        "roc_auc": roc_auc,
        "n_attack_windows": int((true_labels == 1).sum()),
    }


def _write_results_markdown(
    path: Path,
    *,
    model_type: str,
    model_version: str,
    threshold: float,
    target_fpr: float,
    user: str,
    device_id: str,
    n_baseline_windows: int,
    n_test_normal_windows: int,
    results: list[tuple[str, dict[str, float]]],
) -> None:
    lines = [
        "# Continuum detection evaluation results",
        "",
        f"Model: {model_type}, version {model_version}",
        f"Target false positive rate: {target_fpr:.1%}",
        f"Calibrated decision threshold: {threshold:.4f}",
        f"Baseline: {n_baseline_windows} windows from user {user!r} on device {device_id}",
        "Held-out normal test windows (real baseline, never used for training or "
        f"calibration): {n_test_normal_windows}",
        "",
        "This model only ever sees keystroke timing. slowed_injection and "
        "randomized_injection are both tuned to a human-plausible absolute "
        "speed, so a detector that only looked at mean interval would likely "
        "miss both; the numbers below show whether that held up in practice. "
        "The decision threshold was calibrated against held-out baseline "
        "windows only, before any attack stream was generated or scored.",
        "",
        "| attack type | precision | recall | F1 | false positive rate | ROC-AUC "
        "| attack windows |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]

    for attack_type, metrics in results:
        lines.append(
            f"| {attack_type} | {metrics['precision']:.3f} | {metrics['recall']:.3f} | "
            f"{metrics['f1']:.3f} | {metrics['false_positive_rate']:.3f} | "
            f"{metrics['roc_auc']:.3f} | {metrics['n_attack_windows']} |"
        )

    lines.append("")
    lines.append(f"![ROC curves per attack type]({ROC_PLOT_RELATIVE_NAME})")
    lines.append("")

    results_by_type = dict(results)
    expected_weak_recalls = {
        attack_type: results_by_type[attack_type]["recall"]
        for attack_type in EXPECTED_WEAK_ATTACK_TYPES
        if attack_type in results_by_type
    }
    weak = [
        attack_type
        for attack_type, recall in expected_weak_recalls.items()
        if recall < WEAK_RECALL_THRESHOLD
    ]
    caught_anyway = [
        attack_type
        for attack_type, recall in expected_weak_recalls.items()
        if recall >= WEAK_RECALL_THRESHOLD
    ]

    if weak:
        lines.append(
            f"Recall is weak on: {', '.join(weak)}. A human-plausible mean "
            "interval with added jitter does not reliably separate from "
            "genuine human typing at this threshold; ROC-AUC above may still "
            "be well above 0.5, meaning the raw score does rank these "
            "somewhat correctly, just not enough to clear a threshold "
            "calibrated for a 1 percent false positive rate. Catching them "
            "reliably would need a signal beyond keystroke timing, which is "
            "out of scope for this detector."
        )
    if caught_anyway:
        lines.append(
            f"Despite a human-plausible absolute speed, {', '.join(caught_anyway)} "
            "was still caught reliably here: a perfectly constant interval has "
            "zero natural variance, and real human typing never does, so the "
            "variance, entropy and regularity features catch it regardless of "
            "how slow or fast it is tuned to look."
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_roc_plot(path: Path, scores_by_type: dict[str, tuple[np.ndarray, np.ndarray]]) -> None:
    fig, ax = plt.subplots(figsize=(6, 6))

    for attack_type, (labels, scores) in scores_by_type.items():
        if len(set(labels.tolist())) < 2:
            continue
        fpr, tpr, _ = roc_curve(labels, scores)
        auc = roc_auc_score(labels, scores)
        ax.plot(fpr, tpr, label=f"{attack_type} (AUC={auc:.2f})")

    ax.plot([0, 1], [0, 1], linestyle="--", color="gray", label="chance")
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("ROC curves per attack type")
    ax.legend(loc="lower right", fontsize="small")
    fig.tight_layout()

    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main() -> None:
    args = parse_args()

    baseline = load_baseline(baseline_path(args.user))
    if baseline.n_windows < MIN_BASELINE_WINDOWS_FOR_EVAL:
        raise SystemExit(
            f"Need at least {MIN_BASELINE_WINDOWS_FOR_EVAL} baseline windows to evaluate "
            f"honestly, have {baseline.n_windows}. Run tools/record_baseline.py again."
        )

    fit_matrix, test_matrix = _split_baseline(
        baseline.features, TEST_HOLDOUT_FRACTION, EVAL_RANDOM_STATE
    )

    model = fit_and_calibrate(
        fit_matrix,
        feature_names=baseline.feature_names,
        baseline_device_id=baseline.device_id,
        model_type=args.model_type,
        target_false_positive_rate=args.target_fpr,
    )

    normal_scores = model.score(test_matrix)
    normal_labels = np.zeros(len(normal_scores), dtype=int)

    results: list[tuple[str, dict[str, float]]] = []
    scores_by_type: dict[str, tuple[np.ndarray, np.ndarray]] = {}

    for attack_type in ATTACK_TYPES_TO_EVALUATE:
        windows, attack_labels = _attack_windows_and_labels(
            attack_type,
            n_streams=N_STREAMS_PER_ATTACK_TYPE,
            window_size=DEFAULT_WINDOW_SIZE,
            window_step=DEFAULT_WINDOW_STEP,
        )
        attack_matrix = feature_windows_to_matrix(windows, baseline.feature_names)
        attack_scores = model.score(attack_matrix) if windows else np.empty(0)

        combined_scores = np.concatenate([normal_scores, attack_scores])
        combined_labels = np.concatenate([normal_labels, np.array(attack_labels, dtype=int)])
        predicted = (combined_scores > model.threshold).astype(int)

        metrics = _compute_metrics(combined_labels, predicted, combined_scores)
        results.append((attack_type, metrics))
        scores_by_type[attack_type] = (combined_labels, combined_scores)

        print(
            f"{attack_type}: precision={metrics['precision']:.3f} recall={metrics['recall']:.3f} "
            f"f1={metrics['f1']:.3f} fpr={metrics['false_positive_rate']:.3f} "
            f"roc_auc={metrics['roc_auc']:.3f}"
        )

    _write_results_markdown(
        RESULTS_PATH,
        model_type=model.model_type,
        model_version=model.version,
        threshold=model.threshold,
        target_fpr=args.target_fpr,
        user=baseline.user,
        device_id=baseline.device_id,
        n_baseline_windows=baseline.n_windows,
        n_test_normal_windows=test_matrix.shape[0],
        results=results,
    )
    _write_roc_plot(ROC_PLOT_PATH, scores_by_type)

    print(f"Wrote {RESULTS_PATH}")
    print(f"Wrote {ROC_PLOT_PATH}")


if __name__ == "__main__":
    main()
