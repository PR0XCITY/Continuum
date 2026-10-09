"""Anomaly detection over per-device keystroke timing.

Responsibility: turn queued KeyEvent records into per-device typing-cadence
features, maintain a per-device baseline of normal cadence, score new
windows of events against a trained model, and decide whether a device's
behaviour looks like human typing or machine-speed injection.

Modules:
    features.py  Turns a window of KeyEvent records into numeric features
                 (inter-key timing statistics, press/release ratios,
                 burstiness) with no key identity involved anywhere.
    baseline.py  Builds and persists a per-device baseline of normal
                 cadence to compare new windows against.
    model.py     Wraps the scikit-learn anomaly models (Isolation Forest,
                 One-Class SVM) used to score a feature window.
    scorer.py    Orchestrates features -> model -> decision, applying the
                 configured window size, thresholds and debounce so a
                 single noisy window cannot trigger a response.
"""
