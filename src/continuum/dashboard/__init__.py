"""Streamlit operator dashboard.

Responsibility: a local Streamlit app for watching live detection status
per device, browsing and filtering past incidents from the connector API,
manually releasing a blocked device, and asking IncidentRAG questions
about the incident history. Talks to the connector only over its
bearer-token-protected local API, never directly to the database.

Uses the minimalist-ui design skill for layout and styling, and that
skill only, per CLAUDE.md.
"""
