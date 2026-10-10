"""Train and calibrate a cadence model from a recorded baseline.

Reads data/baselines/<user>.npz (see tools/record_baseline.py), fits a
one-class model on it, calibrates its decision threshold against
held-out baseline windows, and saves the result to
data/models/<user>.joblib.

Usage:
    python tools/train_model.py [user] \
        [--model-type isolation_forest|one_class_svm] [--target-fpr 0.01]

user defaults to your OS account name if not given.
"""

from __future__ import annotations

import argparse
import getpass

from continuum.detection.baseline import baseline_path, load_baseline
from continuum.detection.model import (
    DEFAULT_TARGET_FALSE_POSITIVE_RATE,
    fit_and_calibrate,
    model_path,
)


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


def main() -> None:
    args = parse_args()

    source = baseline_path(args.user)
    baseline = load_baseline(source)
    print(f"Loaded {baseline.n_windows} baseline windows for {args.user!r} ({baseline.device_id}).")

    model = fit_and_calibrate(
        baseline.features,
        feature_names=baseline.feature_names,
        baseline_device_id=baseline.device_id,
        model_type=args.model_type,
        target_false_positive_rate=args.target_fpr,
    )

    destination = model_path(args.user)
    model.save(destination)

    print(f"Trained {model.model_type} (version {model.version}).")
    print(
        f"Calibrated threshold {model.threshold:.4f} for a "
        f"{args.target_fpr:.1%} target false-positive rate."
    )
    print(f"Saved to {destination}")


if __name__ == "__main__":
    main()
