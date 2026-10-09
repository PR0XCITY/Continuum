"""Anomaly model wrappers.

Responsibility: thin, swappable wrappers around the scikit-learn models
used for cadence anomaly scoring (Isolation Forest, One-Class SVM),
covering fit, score and persist/load so detection.scorer does not depend
directly on scikit-learn's API.
"""
