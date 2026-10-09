"""Per-device typing cadence baseline.

Responsibility: accumulate feature vectors for a device during a learning
period, persist a summary baseline to disk under the configured data
directory, and load that baseline back so the scorer has a per-device
frame of reference instead of one global threshold.
"""
