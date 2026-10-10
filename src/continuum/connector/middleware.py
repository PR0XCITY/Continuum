"""Request-size and rate-limiting middleware for the connector API.

Responsibility: two simple, local-only safeguards. Both are
deliberately basic, matching a single-machine, localhost-bound service
with a handful of callers (the runtime, the dashboard, you), not a
public API:

    RequestSizeLimitMiddleware  Rejects a request outright if its
                                declared Content-Length exceeds
                                MAX_REQUEST_BODY_BYTES. A chunked
                                request with no Content-Length header
                                is not caught by this; that tradeoff is
                                accepted for a local service with a
                                fixed set of trusted callers.
    InMemoryRateLimitMiddleware A per-process, per-client-host sliding
                                window counter. State lives in a plain
                                dict and is lost on restart; there is
                                no cross-process or distributed limit,
                                which is fine for one connector process
                                on one machine.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

MAX_REQUEST_BODY_BYTES = 1_048_576  # 1 MiB
RATE_LIMIT_MAX_REQUESTS = 120
RATE_LIMIT_WINDOW_SECONDS = 60.0


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, max_bytes: int = MAX_REQUEST_BODY_BYTES) -> None:
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = None
            if declared_size is not None and declared_size > self._max_bytes:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)


class InMemoryRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        max_requests: int = RATE_LIMIT_MAX_REQUESTS,
        window_seconds: float = RATE_LIMIT_WINDOW_SECONDS,
    ) -> None:
        super().__init__(app)
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        client_key = request.client.host if request.client else "unknown"
        now = time.monotonic()
        timestamps = self._requests[client_key]

        while timestamps and now - timestamps[0] > self._window_seconds:
            timestamps.popleft()

        if len(timestamps) >= self._max_requests:
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)

        timestamps.append(now)
        return await call_next(request)
