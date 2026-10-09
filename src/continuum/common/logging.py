"""Structured logging setup for Continuum.

Responsibility: configure a single logging setup (handlers, formatting, log
level, log file location under the configured data directory) that every
entry point calls once at startup instead of configuring logging itself.

Hard rule enforced here: log records must never contain which keys were
pressed. Only timestamps, event types, per-session counters and device
identifiers may appear in any log line produced by this project.
"""
