"""Describe trained models, recorded baselines and the latest evaluation.

Responsibility: read-only summaries for GET /calibration, so the
dashboard can show calibration state without touching data/ itself.
Baselines contribute only counts and timestamps here, never feature
values, and no file in data/models or data/baselines ever contained key
content in the first place.

Model files are joblib (pickle) bundles written by tools/train_model.py
on this machine; they are loaded only from the configured local model
directory, exactly as the runtime itself loads them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from continuum.detection.baseline import load_baseline
from continuum.detection.model import CadenceModel
from continuum.detection.scorer import threshold_offset_for_sensitivity


def _modified_at(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()


def describe_models(model_dir: Path, *, sensitivity: int) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    offset = threshold_offset_for_sensitivity(sensitivity)
    for path in sorted(model_dir.glob("*.joblib")):
        try:
            model = CadenceModel.load(path)
        except Exception as error:
            summaries.append({"user": path.stem, "error": f"could not load: {error}"})
            continue
        summaries.append(
            {
                "user": path.stem,
                "version": model.version,
                "model_type": model.model_type,
                "calibrated_threshold": model.threshold,
                "threshold_at_configured_sensitivity": model.threshold + offset,
                "target_false_positive_rate": model.target_false_positive_rate,
                "baseline_device_id": model.baseline_device_id,
                "n_training_windows": model.metadata.get("n_training_windows"),
                "n_calibration_windows": model.metadata.get("n_calibration_windows"),
                "modified_at": _modified_at(path),
            }
        )
    return summaries


def describe_baselines(baseline_dir: Path) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for path in sorted(baseline_dir.glob("*.npz")):
        try:
            baseline = load_baseline(path)
        except Exception as error:
            summaries.append({"user": path.stem, "error": f"could not load: {error}"})
            continue
        captured = sorted(baseline.captured_at)
        summaries.append(
            {
                "user": baseline.user,
                "device_id": baseline.device_id,
                "n_windows": baseline.n_windows,
                "first_captured_at": captured[0].isoformat() if captured else None,
                "last_captured_at": captured[-1].isoformat() if captured else None,
                "modified_at": _modified_at(path),
            }
        )
    return summaries


def read_eval_results(path: Path) -> str | None:
    return path.read_text(encoding="utf-8") if path.exists() else None
