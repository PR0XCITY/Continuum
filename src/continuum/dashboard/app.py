"""Streamlit dashboard entry point.

Responsibility: render the device status view, incident browser and
IncidentRAG question box described in dashboard/__init__.py, calling the
connector API for all data and never touching SQLite or ChromaDB
directly.
"""
