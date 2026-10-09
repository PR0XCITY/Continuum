"""Continuum: a closed-loop cybersecurity pipeline for Windows.

Continuum detects keystroke-injection attacks (USB Rubber Ducky, Digispark,
Bash Bunny and similar HID-emulating devices) by analysing typing cadence per
physical input device, responds by locking the workstation and disabling the
offending device, records every response as a structured incident, and lets
an analyst ask incident-response questions against that incident corpus
through a local retrieval-augmented assistant.

Subpackages:
    common      Shared schemas, config loading and logging setup.
    capture     Windows Raw Input capture of keystroke timing metadata only.
    detection   Feature extraction and anomaly scoring on capture events.
    response    Workstation lock, device disable/enable, alerting.
    connector   FastAPI service that turns detections into incident records.
    rag         Local retrieval-augmented incident-response assistant.
    dashboard   Streamlit operator dashboard.

This module contains no feature logic. See CLAUDE.md for the hard design
rules that govern every subpackage, and tools/ and tests/ for simulation and
verification helpers that live outside the installable package.
"""
