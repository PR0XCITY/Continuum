"""Connector layer: turns detections and responses into incident records.

Responsibility: a FastAPI service, local-only, that receives incident
posts from the runtime, validates them into the IncidentRecord schema,
persists them to SQLite via SQLAlchemy, enqueues a plain-text document
for later RAG ingestion, and exposes a bearer-token-protected API for
reading incidents back out (used by the dashboard and, later, by
rag.ingest).

Modules:
    app.py         FastAPI application, routes and the create_app()
                   factory. Import continuum.connector.app directly
                   (from continuum.connector.app import create_app)
                   rather than from this package, so that importing
                   continuum.connector.db alone, which continuum.runtime
                   does for its shared-table access, never has to pull
                   in FastAPI and build a real app as a side effect.
    auth.py        Bearer token verification, required on every route
                   except GET /health.
    db.py          SQLAlchemy models and session/engine setup over
                   SQLite, including the two tables shared file-level
                   with continuum.runtime (commands, live_snapshots).
    document.py    Notes sanitising, suspicious-notes detection, and
                   the fixed-template plain-text document builder for
                   the RAG ingest queue.
    middleware.py  Request size and in-memory rate limiting.
"""
