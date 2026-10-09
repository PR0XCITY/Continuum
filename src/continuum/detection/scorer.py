"""Detection orchestration: features, model and decision.

Responsibility: pull windows of events per device from the capture queue,
run features.py and model.py, apply the configured threshold and debounce
rules, and emit a DetectionResult deciding whether the response layer
should act. This is the only module allowed to turn a score into a
block/no-block decision.
"""
