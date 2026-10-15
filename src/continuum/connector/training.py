"""Baseline and model management behind the dashboard's Train page.

Responsibility: summarise the user's recorded typing baseline and trained
model, train a model from the baseline, and start over. Recording itself
happens in the runtime (continuum.recording), through Raw Input; this
module only ever reads and writes the baseline and model files, which
hold timing statistics and never any key content.

Training here is the same fit and calibration as tools/train_model.py,
so a model trained from the dashboard behaves exactly like one trained
from the command line. The runtime notices the new model file and starts
using it within a few seconds.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from continuum.detection.baseline import MIN_RECOMMENDED_WINDOWS, baseline_path, load_baseline
from continuum.detection.model import CadenceModel, fit_and_calibrate, model_path

RECOMMENDED_WINDOWS = MIN_RECOMMENDED_WINDOWS
# Below this the calibrated threshold rests on too few held-out windows to
# mean anything; the page asks for more typing instead of training.
MIN_TRAIN_WINDOWS = 60


class TrainingError(ValueError):
    """A training request that cannot be carried out; the message is user-facing."""


def _modified_at(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()


def baseline_summary(baseline_dir: Path, user: str) -> dict[str, object]:
    path = baseline_path(user, baseline_dir=baseline_dir)
    if not path.exists():
        return {"exists": False, "n_windows": 0, "device_id": None, "updated_at": None}
    baseline = load_baseline(path)
    return {
        "exists": True,
        "n_windows": baseline.n_windows,
        "device_id": baseline.device_id,
        "updated_at": _modified_at(path),
    }


def model_summary(model_dir: Path, user: str) -> dict[str, object]:
    path = model_path(user, model_dir=model_dir)
    if not path.exists():
        return {"exists": False, "version": None, "trained_at": None, "n_training_windows": None}
    try:
        model = CadenceModel.load(path)
    except Exception:
        return {"exists": True, "version": "unreadable", "trained_at": _modified_at(path),
                "n_training_windows": None}
    return {
        "exists": True,
        "version": model.version,
        "trained_at": _modified_at(path),
        "n_training_windows": model.metadata.get("n_training_windows"),
    }


def train_model(baseline_dir: Path, model_dir: Path, user: str) -> dict[str, object]:
    """Fit and calibrate a model on the user's baseline, and save it for the runtime."""
    path = baseline_path(user, baseline_dir=baseline_dir)
    if not path.exists():
        raise TrainingError("No baseline yet. Record at least one paragraph first.")
    baseline = load_baseline(path)
    if baseline.n_windows < MIN_TRAIN_WINDOWS:
        raise TrainingError(
            f"The baseline has {baseline.n_windows} windows; at least {MIN_TRAIN_WINDOWS} are "
            f"needed to train ({RECOMMENDED_WINDOWS} recommended). Record another paragraph."
        )
    model = fit_and_calibrate(
        baseline.features,
        feature_names=baseline.feature_names,
        baseline_device_id=baseline.device_id,
    )
    model.save(model_path(user, model_dir=model_dir))
    return model_summary(model_dir, user)


def reset_baseline(baseline_dir: Path, user: str) -> None:
    """Delete the user's baseline, to start recording from scratch.

    The trained model, if any, is kept, so protection does not lapse
    while a new baseline is being recorded.
    """
    baseline_path(user, baseline_dir=baseline_dir).unlink(missing_ok=True)
