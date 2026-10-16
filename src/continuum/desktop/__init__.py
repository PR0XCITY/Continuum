"""Continuum's native Windows desktop app (PySide6).

Replaces the browser dashboard with a window and a tray icon. It talks
to the connector API exactly as the Streamlit dashboard does, through
continuum.dashboard.api.ConnectorClient with the bearer token, and reuses
the pure helpers in continuum.dashboard.helpers. It never opens the
database, the Chroma store or the capture layer itself.

Run it with `python -m continuum.desktop` or `.\\tasks.ps1 run-app`.
"""
