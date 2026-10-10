"""Per-device typing cadence baseline.

Responsibility: persist a user's FeatureWindow history to
data/baselines/<user>.npz, load it back as a feature matrix with a
fitted StandardScaler, and report on its quality. Everything here
operates on FeatureWindow objects, which hold only numeric cadence
statistics; no code path in this module ever has access to, or stores,
the text someone typed while a baseline was recorded.

A baseline file can be built up over more than one recording sitting:
append_feature_windows() merges new windows into whatever is already on
disk for that user and device, so tools/record_baseline.py can be run
again later to add more windows to the same baseline.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.preprocessing import StandardScaler

from continuum.common.schemas import FeatureWindow
from continuum.detection.features import FEATURE_NAMES

_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BASELINE_DIR = _REPO_ROOT / "data" / "baselines"

MIN_RECOMMENDED_WINDOWS = 150

_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass
class Baseline:
    """A user's accumulated cadence baseline for one device."""

    user: str
    device_id: str
    feature_names: list[str]
    features: np.ndarray
    captured_at: list[datetime]

    @property
    def n_windows(self) -> int:
        return int(self.features.shape[0])


def _sanitise_filename_component(value: str) -> str:
    cleaned = _UNSAFE_FILENAME_CHARS.sub("_", value.strip())
    return cleaned or "default"


def baseline_path(user: str, *, baseline_dir: Path = DEFAULT_BASELINE_DIR) -> Path:
    """Where this user's baseline file lives. Does not create anything."""
    return baseline_dir / f"{_sanitise_filename_component(user)}.npz"


def feature_windows_to_matrix(
    windows: Sequence[FeatureWindow],
    feature_names: Sequence[str] = FEATURE_NAMES,
) -> np.ndarray:
    """Stack FeatureWindow.features into a (n_windows, n_features) array."""
    if not windows:
        return np.empty((0, len(feature_names)), dtype=float)
    return np.array(
        [[window.features[name] for name in feature_names] for window in windows],
        dtype=float,
    )


def save_baseline(path: Path, baseline: Baseline) -> None:
    """Write a Baseline to path, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez(
        path,
        features=baseline.features,
        feature_names=np.array(baseline.feature_names),
        captured_at=np.array([ts.astimezone(UTC).isoformat() for ts in baseline.captured_at]),
        device_id=np.array([baseline.device_id]),
        user=np.array([baseline.user]),
    )


def load_baseline(path: Path) -> Baseline:
    """Read a Baseline back from path. Raises FileNotFoundError if missing."""
    with np.load(path, allow_pickle=False) as data:
        features = np.array(data["features"], dtype=float)
        feature_names = [str(name) for name in data["feature_names"]]
        captured_at = [datetime.fromisoformat(str(value)) for value in data["captured_at"]]
        device_id = str(data["device_id"][0])
        user = str(data["user"][0])

    return Baseline(
        user=user,
        device_id=device_id,
        feature_names=feature_names,
        features=features,
        captured_at=captured_at,
    )


def append_feature_windows(
    path: Path,
    *,
    user: str,
    device_id: str,
    windows: Sequence[FeatureWindow],
    feature_names: Sequence[str] = FEATURE_NAMES,
    captured_at: Sequence[datetime] | None = None,
) -> Baseline:
    """Add windows from one recording sitting to the baseline at path.

    Creates path if it does not exist yet. Raises ValueError if path
    already holds a baseline for a different user, device or feature
    layout; a baseline file only ever accumulates one user's one device.
    """
    new_matrix = feature_windows_to_matrix(windows, feature_names)
    new_captured_at = (
        list(captured_at) if captured_at is not None else [datetime.now(UTC)] * len(windows)
    )
    if len(new_captured_at) != len(windows):
        raise ValueError("captured_at must have one entry per window")

    if path.exists():
        existing = load_baseline(path)
        if existing.user != user:
            raise ValueError(f"baseline at {path} belongs to user {existing.user!r}, not {user!r}")
        if existing.device_id != device_id:
            raise ValueError(
                f"baseline at {path} was recorded on device {existing.device_id!r}, "
                f"not {device_id!r}"
            )
        if existing.feature_names != list(feature_names):
            raise ValueError(f"baseline at {path} uses a different feature layout")

        combined_features = (
            np.vstack([existing.features, new_matrix]) if new_matrix.size else existing.features
        )
        combined_captured_at = existing.captured_at + new_captured_at
    else:
        combined_features = new_matrix
        combined_captured_at = new_captured_at

    baseline = Baseline(
        user=user,
        device_id=device_id,
        feature_names=list(feature_names),
        features=combined_features,
        captured_at=combined_captured_at,
    )
    save_baseline(path, baseline)
    return baseline


def load_feature_matrix_and_scaler(path: Path) -> tuple[np.ndarray, StandardScaler]:
    """Load a baseline and fit a StandardScaler on its feature matrix.

    Returns the raw matrix and the fitted scaler; callers that need
    scaled features should call scaler.transform(matrix) themselves, so
    the unscaled matrix is still available for reporting.
    """
    baseline = load_baseline(path)
    scaler = StandardScaler()
    if baseline.n_windows:
        scaler.fit(baseline.features)
    return baseline.features, scaler


def build_quality_report(baseline: Baseline) -> str:
    """Human-readable summary: window count, feature ranges, and warnings."""
    lines = [
        f"Baseline quality report for {baseline.user!r} ({baseline.device_id})",
        f"Windows: {baseline.n_windows}",
    ]

    if baseline.n_windows:
        lines.append("Feature ranges:")
        for index, name in enumerate(baseline.feature_names):
            column = baseline.features[:, index]
            lines.append(f"  {name:<18} min={column.min():.3f} max={column.max():.3f}")

    if baseline.n_windows < MIN_RECOMMENDED_WINDOWS:
        lines.append(
            f"WARNING: only {baseline.n_windows} windows recorded, fewer than the "
            f"recommended {MIN_RECOMMENDED_WINDOWS}. Record another sitting for a "
            "more reliable baseline."
        )

    return "\n".join(lines)


def print_quality_report(baseline: Baseline) -> None:
    print(build_quality_report(baseline))
