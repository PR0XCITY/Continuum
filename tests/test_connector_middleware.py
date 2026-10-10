"""Tests for continuum.connector.middleware, against a minimal app.

Tested in isolation from the real connector app so the rate limit test
does not need to send 100+ real requests through the full stack (auth,
database, pydantic validation) just to prove the counter works.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

import continuum.connector.middleware as middleware_module
from continuum.connector.middleware import InMemoryRateLimitMiddleware, RequestSizeLimitMiddleware


def _minimal_app() -> FastAPI:
    app = FastAPI()

    @app.post("/echo")
    def echo() -> dict:
        return {"ok": True}

    return app


def test_request_size_limit_rejects_a_declared_oversized_body():
    app = _minimal_app()
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=100)
    client = TestClient(app)

    response = client.post("/echo", headers={"Content-Length": "1000"})

    assert response.status_code == 413


def test_request_size_limit_allows_a_small_body():
    app = _minimal_app()
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=1_000_000)
    client = TestClient(app)

    response = client.post("/echo", json={"a": 1})

    assert response.status_code == 200


def test_request_size_limit_ignores_a_non_numeric_content_length():
    app = _minimal_app()
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=100)
    client = TestClient(app)

    response = client.post("/echo", headers={"Content-Length": "not-a-number"})

    assert response.status_code == 200


def test_rate_limit_allows_requests_under_the_limit():
    app = _minimal_app()
    app.add_middleware(InMemoryRateLimitMiddleware, max_requests=5, window_seconds=60.0)
    client = TestClient(app)

    for _ in range(5):
        response = client.post("/echo")
        assert response.status_code == 200


def test_rate_limit_rejects_requests_over_the_limit():
    app = _minimal_app()
    app.add_middleware(InMemoryRateLimitMiddleware, max_requests=3, window_seconds=60.0)
    client = TestClient(app)

    for _ in range(3):
        assert client.post("/echo").status_code == 200

    response = client.post("/echo")
    assert response.status_code == 429


def test_rate_limit_resets_after_the_window_elapses(monkeypatch):
    app = _minimal_app()
    app.add_middleware(InMemoryRateLimitMiddleware, max_requests=1, window_seconds=10.0)
    client = TestClient(app)

    fake_now = [1000.0]
    monkeypatch.setattr(middleware_module.time, "monotonic", lambda: fake_now[0])

    assert client.post("/echo").status_code == 200
    assert client.post("/echo").status_code == 429

    fake_now[0] += 11.0  # past the 10 second window
    assert client.post("/echo").status_code == 200
