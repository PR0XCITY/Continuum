"""FastAPI application for the connector layer.

Responsibility: wire up routes for submitting and listing incidents, apply
the auth dependency from auth.py to every route, validate incoming
payloads against common.schemas.Incident, and persist through db.py.

Runs local-only: binds to 127.0.0.1 by default, makes no outbound network
calls, and sends no telemetry anywhere.
"""
