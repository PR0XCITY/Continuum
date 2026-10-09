"""Connector layer: turns detections and responses into incident records.

Responsibility: a FastAPI service, local-only, that receives block/release
events from the runtime, validates them into the Incident schema, persists
them to SQLite via SQLAlchemy, and exposes a bearer-token-protected API for
reading incidents back out (used by the dashboard and by rag.ingest).

Modules:
    app.py   FastAPI application, routes and startup wiring.
    auth.py  Bearer token verification. Required on every route, including
             requests from localhost; there is no unauthenticated route.
    db.py    SQLAlchemy models and session/engine setup over SQLite.
"""
