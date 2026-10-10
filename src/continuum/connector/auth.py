"""Bearer token authentication for the connector API.

Responsibility: a FastAPI dependency that checks every request,
including requests from 127.0.0.1, for a valid bearer token against
the token configured via environment variable. There is no route in
this project that may skip this check, except GET /health; "it's only
localhost" is not an exemption.

make_bearer_token_dependency() takes the settings a particular
create_app() call was built with, rather than the dependency reading
the process-wide cached get_settings() itself; that is what lets each
test build its own isolated app (its own database file, and its own
auth_token_env_var name) without fighting a module-level cache.

The expected token is never hardcoded or cached across requests in a
way that would survive a token rotation: it is re-read from the
environment on every call, and compared with hmac.compare_digest to
avoid leaking its value through response-time timing differences.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Awaitable, Callable

from fastapi import Header, HTTPException, status

from continuum.common.config import Settings

BEARER_PREFIX = "Bearer "

BearerTokenDependency = Callable[[str | None], Awaitable[None]]


def make_bearer_token_dependency(settings: Settings) -> BearerTokenDependency:
    """Build the auth dependency for one app, bound to its own settings."""

    async def require_bearer_token(authorization: str | None = Header(default=None)) -> None:
        expected = os.environ.get(settings.connector.auth_token_env_var, "")
        if not expected:
            # Fail closed: a server with no token configured must
            # refuse every request, never accept anything as "no auth
            # needed".
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="server auth token is not configured",
            )

        if not authorization or not authorization.startswith(BEARER_PREFIX):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token"
            )

        provided = authorization[len(BEARER_PREFIX) :]
        if not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token"
            )

    return require_bearer_token
