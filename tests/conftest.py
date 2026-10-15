"""Shared pytest fixtures: an isolated connector app per test.

Each test using these fixtures gets its own temporary SQLite file and
its own bearer token environment variable name, so connector tests
never touch the real data/db/continuum.sqlite3 or depend on a real
CONTINUUM_API_TOKEN being set.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import numpy as np
import pytest
from fastapi.testclient import TestClient

from continuum.common.config import get_settings
from continuum.connector.app import create_app

CONNECTOR_TEST_TOKEN = "test-bearer-token-0123456789abcdef"  # noqa: S105
CONNECTOR_TEST_TOKEN_ENV_VAR = "CONTINUUM_TEST_API_TOKEN"


@pytest.fixture
def connector_settings(tmp_path, monkeypatch):
    monkeypatch.setenv(CONNECTOR_TEST_TOKEN_ENV_VAR, CONNECTOR_TEST_TOKEN)
    base_settings = get_settings()
    test_connector_settings = base_settings.connector.model_copy(
        update={
            "database_path": tmp_path / "connector.sqlite3",
            "auth_token_env_var": CONNECTOR_TEST_TOKEN_ENV_VAR,
        }
    )
    test_rag_settings = base_settings.rag.model_copy(
        update={"chroma_path": tmp_path / "chroma"}
    )
    return base_settings.model_copy(
        update={"connector": test_connector_settings, "rag": test_rag_settings}
    )


@pytest.fixture
def connector_paths(tmp_path):
    paths = {
        "local_override_path": tmp_path / "config" / "local.yaml",
        "model_dir": tmp_path / "models",
        "baseline_dir": tmp_path / "baselines",
        "eval_results_path": tmp_path / "eval_results.md",
        "user": "tester",
    }
    paths["model_dir"].mkdir()
    paths["baseline_dir"].mkdir()
    return paths


@pytest.fixture
def connector_app(connector_settings, connector_paths):
    return create_app(settings=connector_settings, **connector_paths)


@pytest.fixture
def connector_client(connector_app):
    return TestClient(connector_app)


@pytest.fixture
def auth_headers():
    return {"Authorization": f"Bearer {CONNECTOR_TEST_TOKEN}"}


def sample_device(**overrides: object) -> dict:
    base = dict(
        device_id="device-under-test",
        vendor_id="046D",
        product_id="C52B",
        name="Test Keyboard",
        bus_type="USB",
        is_usb=True,
        instance_id=r"HID\VID_046D&PID_C52B\0",
        first_seen="2026-01-01T00:00:00+00:00",
    )
    base.update(overrides)
    return base


def sample_incident_payload(**overrides: object) -> dict:
    base = dict(
        detected_at=datetime.now(UTC).isoformat(),
        device=sample_device(),
        anomaly_score=2.5,
        threshold=1.0,
        verdict="blocked",
        attack_pattern="burst_injection",
        features_summary={"burst_score": 1.0},
        action_taken="locked_and_disabled",
        time_to_detect_ms=450,
        notes="",
    )
    base.update(overrides)
    return base


# --- deterministic fake embeddings for rag/ tests ----------------------------
#
# The real embedding model (sentence-transformers) needs a one-time
# download from the network, which the test suite must not depend on.
# This is a simple, deterministic bag-of-words hashing embedding: good
# enough to give rag/ tests a meaningful notion of "similar text ranks
# higher", without ever touching the network or a real model.

_FAKE_EMBEDDING_DIM = 256
_WORD_PATTERN = re.compile(r"[a-z0-9]+")


def fake_embed_texts(texts: list[str], **_kwargs: object) -> np.ndarray:
    vectors = np.zeros((len(texts), _FAKE_EMBEDDING_DIM), dtype=np.float32)
    for i, text in enumerate(texts):
        for word in _WORD_PATTERN.findall(text.lower()):
            vectors[i, hash(word) % _FAKE_EMBEDDING_DIM] += 1.0
        norm = np.linalg.norm(vectors[i])
        if norm > 0:
            vectors[i] /= norm
    return vectors


def fake_embed_one(text: str, **_kwargs: object) -> np.ndarray:
    return fake_embed_texts([text])[0]


@pytest.fixture
def fake_embeddings(monkeypatch):
    """Patch every rag/ module's embed_one/embed_texts reference with the fake."""
    for module_name in ("ingest", "retrieve", "confidence"):
        module = __import__(f"continuum.rag.{module_name}", fromlist=[module_name])
        if hasattr(module, "embed_texts"):
            monkeypatch.setattr(module, "embed_texts", fake_embed_texts)
        if hasattr(module, "embed_one"):
            monkeypatch.setattr(module, "embed_one", fake_embed_one)
