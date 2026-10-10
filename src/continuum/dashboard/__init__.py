"""Streamlit operator dashboard.

Responsibility: a local Streamlit app for watching live detection status
per device, browsing and filtering past incidents from the connector API,
manually releasing a blocked device, and asking IncidentRAG questions
about the incident history. Talks to the connector only over its
bearer-token-protected local API, never directly to the database.

Modules:
    app.py      The Streamlit pages and navigation (run this file).
    api.py      ConnectorClient: the dashboard's only network code.
    helpers.py  Pure formatting, filtering and chart-shaping functions,
                unit tested without a Streamlit session.
    style.py    CSS and HTML builders that escape every value they render.
"""
