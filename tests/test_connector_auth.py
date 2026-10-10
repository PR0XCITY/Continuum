"""Tests for continuum.connector.auth, independent of the full app.

require_bearer_token is async but has no internal awaits, so it can be
driven directly with asyncio.run() from plain sync tests.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from continuum.connector.auth import make_bearer_token_dependency

TOKEN_ENV_VAR = "CONTINUUM_TEST_AUTH_TOKEN"
TOKEN_VALUE = "correct-token-value"


class _FakeConnectorSettings:
    auth_token_env_var = TOKEN_ENV_VAR


class _FakeSettings:
    connector = _FakeConnectorSettings()


def _dependency():
    return make_bearer_token_dependency(_FakeSettings())


def test_rejects_when_no_token_is_configured(monkeypatch):
    monkeypatch.delenv(TOKEN_ENV_VAR, raising=False)
    require_bearer_token = _dependency()

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(require_bearer_token(authorization=f"Bearer {TOKEN_VALUE}"))

    assert exc_info.value.status_code == 500


def test_rejects_missing_authorization_header(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV_VAR, TOKEN_VALUE)
    require_bearer_token = _dependency()

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(require_bearer_token(authorization=None))

    assert exc_info.value.status_code == 401


def test_rejects_a_header_without_the_bearer_prefix(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV_VAR, TOKEN_VALUE)
    require_bearer_token = _dependency()

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(require_bearer_token(authorization=TOKEN_VALUE))

    assert exc_info.value.status_code == 401


def test_rejects_the_wrong_token(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV_VAR, TOKEN_VALUE)
    require_bearer_token = _dependency()

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(require_bearer_token(authorization="Bearer wrong-token"))

    assert exc_info.value.status_code == 401


def test_accepts_the_right_token(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV_VAR, TOKEN_VALUE)
    require_bearer_token = _dependency()

    asyncio.run(require_bearer_token(authorization=f"Bearer {TOKEN_VALUE}"))  # must not raise


def test_each_app_reads_its_own_settings_independently(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV_VAR, TOKEN_VALUE)
    monkeypatch.setenv("CONTINUUM_TEST_OTHER_TOKEN", "a-different-token")

    class _OtherConnectorSettings:
        auth_token_env_var = "CONTINUUM_TEST_OTHER_TOKEN"

    class _OtherSettings:
        connector = _OtherConnectorSettings()

    dependency_a = make_bearer_token_dependency(_FakeSettings())
    dependency_b = make_bearer_token_dependency(_OtherSettings())

    asyncio.run(dependency_a(authorization=f"Bearer {TOKEN_VALUE}"))
    asyncio.run(dependency_b(authorization="Bearer a-different-token"))

    with pytest.raises(HTTPException):
        asyncio.run(dependency_a(authorization="Bearer a-different-token"))
