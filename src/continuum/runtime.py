"""Runtime entry point: wires capture, detection and response together.

Responsibility: construct the capture backend via capture.factory, read
queued events into detection.scorer, and on a confirmed anomaly call into
response (lockscreen, blocker_windows, alerts). This is the process meant
to run elevated, continuously, as the HID Firewall.

Contains no feature logic yet. Intentionally kept separate from
connector.app and dashboard.app so the elevated runtime process never
needs to run a web server, and the web processes never need elevation.
"""
