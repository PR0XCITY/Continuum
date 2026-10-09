"""Bearer token authentication for the connector API.

Responsibility: a FastAPI dependency that checks every request, including
requests from 127.0.0.1, for a valid bearer token against the token
configured via environment variable. There is no route in this project
that may skip this check; "it's only localhost" is not an exemption.
"""
