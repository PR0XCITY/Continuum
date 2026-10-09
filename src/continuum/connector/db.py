"""SQLAlchemy models and session management over SQLite.

Responsibility: define the Incident table backing common.schemas.Incident,
create the SQLite engine against the configured database path under the
data directory, and provide session helpers for app.py to use. Holds no
HTTP or business logic.
"""
