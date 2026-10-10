"""Anomaly model wrappers.

Responsibility: a thin, swappable wrapper around the scikit-learn models
used for cadence anomaly scoring (Isolation Forest, One-Class SVM),
behind one interface: fit on baseline windows, calibrate a decision
threshold, score new windows, and persist/load everything together with
joblib. detection.scorer only ever talks to CadenceModel; it never
imports scikit-learn directly.

Both algorithms are trained in a one-class setting, on this user's
baseline only; there are no attack examples in the training data. Both
expose a decision_function() where a lower value means more anomalous,
so this module negates it once, here, so that everywhere else in
Continuum "higher anomaly_score means more anomalous" is simply true.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from continuum.detection.baseline import _sanitise_filename_component

ModelType = Literal["isolation_forest", "one_class_svm"]

DEFAULT_MODEL_TYPE: ModelType = "isolation_forest"
DEFAULT_TARGET_FALSE_POSITIVE_RATE = 0.01
DEFAULT_CALIBRATION_HOLDOUT_FRACTION = 0.2
DEFAULT_RANDOM_STATE = 0
MIN_BASELINE_WINDOWS_TO_FIT = 10

_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MODEL_DIR = _REPO_ROOT / "data" / "models"

_BUNDLE_KEYS = (
    "model_type",
    "estimator",
    "scaler",
    "threshold",
    "feature_names",
    "version",
    "target_false_positive_rate",
    "baseline_device_id",
)


def model_path(user: str, *, model_dir: Path = DEFAULT_MODEL_DIR) -> Path:
    """Where this user's trained model lives. Does not create anything."""
    return model_dir / f"{_sanitise_filename_component(user)}.joblib"


def _build_estimator(model_type: ModelType, *, random_state: int) -> object:
    if model_type == "isolation_forest":
        return IsolationForest(n_estimators=200, random_state=random_state)
    if model_type == "one_class_svm":
        return OneClassSVM(kernel="rbf", gamma="scale", nu=0.05)
    raise ValueError(f"unknown model_type: {model_type!r}")


@dataclass
class CadenceModel:
    """A fitted, calibrated one-class cadence model, ready to score windows.

    threshold is the anomaly_score above which a window is "suspicious";
    it was chosen during calibration to flag at most
    target_false_positive_rate of held-out, genuinely normal baseline
    windows. detection.scorer may still adjust the threshold it actually
    applies (for example, stricter for a brand-new device), but this is
    the model's own calibrated value.
    """

    model_type: ModelType
    estimator: object
    scaler: StandardScaler
    threshold: float
    feature_names: list[str]
    version: str
    baseline_device_id: str
    target_false_positive_rate: float = DEFAULT_TARGET_FALSE_POSITIVE_RATE
    metadata: dict[str, object] = field(default_factory=dict)

    def score(self, feature_matrix: np.ndarray) -> np.ndarray:
        """Anomaly scores for a (n_windows, n_features) matrix. Higher = worse."""
        scaled = self.scaler.transform(feature_matrix)
        raw = self.estimator.decision_function(scaled)
        return -np.asarray(raw, dtype=float)

    def score_one(self, features: dict[str, float]) -> float:
        """Anomaly score for a single FeatureWindow.features mapping."""
        vector = np.array([[features[name] for name in self.feature_names]], dtype=float)
        return float(self.score(vector)[0])

    def is_anomalous(self, anomaly_score: float, *, threshold: float | None = None) -> bool:
        return anomaly_score > (self.threshold if threshold is None else threshold)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {key: getattr(self, key) for key in _BUNDLE_KEYS}
        bundle["metadata"] = self.metadata
        joblib.dump(bundle, path)

    @classmethod
    def load(cls, path: Path) -> CadenceModel:
        bundle = joblib.load(path)
        return cls(
            model_type=bundle["model_type"],
            estimator=bundle["estimator"],
            scaler=bundle["scaler"],
            threshold=bundle["threshold"],
            feature_names=list(bundle["feature_names"]),
            version=bundle["version"],
            baseline_device_id=bundle["baseline_device_id"],
            target_false_positive_rate=bundle.get(
                "target_false_positive_rate", DEFAULT_TARGET_FALSE_POSITIVE_RATE
            ),
            metadata=dict(bundle.get("metadata", {})),
        )


def fit_and_calibrate(
    baseline_matrix: np.ndarray,
    *,
    feature_names: Sequence[str],
    baseline_device_id: str,
    model_type: ModelType = DEFAULT_MODEL_TYPE,
    target_false_positive_rate: float = DEFAULT_TARGET_FALSE_POSITIVE_RATE,
    calibration_holdout_fraction: float = DEFAULT_CALIBRATION_HOLDOUT_FRACTION,
    random_state: int = DEFAULT_RANDOM_STATE,
) -> CadenceModel:
    """Fit a one-class model on baseline windows and calibrate its threshold.

    baseline_matrix is split into a training split and a held-out
    calibration split. The scaler and estimator are fit on the training
    split only; the decision threshold is then set so that at most
    target_false_positive_rate of the held-out, genuinely normal windows
    would be flagged. Calibrating on data the estimator never trained on
    is what makes the resulting false-positive rate trustworthy.
    """
    n_windows = baseline_matrix.shape[0]
    if n_windows < MIN_BASELINE_WINDOWS_TO_FIT:
        raise ValueError(
            f"need at least {MIN_BASELINE_WINDOWS_TO_FIT} baseline windows to fit and "
            f"calibrate a model, got {n_windows}"
        )

    rng = np.random.default_rng(random_state)
    indices = rng.permutation(n_windows)
    n_holdout = max(1, int(round(n_windows * calibration_holdout_fraction)))
    holdout_idx, train_idx = indices[:n_holdout], indices[n_holdout:]

    scaler = StandardScaler()
    scaled_train = scaler.fit_transform(baseline_matrix[train_idx])

    estimator = _build_estimator(model_type, random_state=random_state)
    estimator.fit(scaled_train)

    scaled_holdout = scaler.transform(baseline_matrix[holdout_idx])
    holdout_scores = -np.asarray(estimator.decision_function(scaled_holdout), dtype=float)
    threshold = float(np.percentile(holdout_scores, 100.0 * (1.0 - target_false_positive_rate)))

    version = f"{model_type}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"

    return CadenceModel(
        model_type=model_type,
        estimator=estimator,
        scaler=scaler,
        threshold=threshold,
        feature_names=list(feature_names),
        version=version,
        baseline_device_id=baseline_device_id,
        target_false_positive_rate=target_false_positive_rate,
        metadata={
            "n_training_windows": int(len(train_idx)),
            "n_calibration_windows": int(len(holdout_idx)),
        },
    )
