"""Tests for the connector's /training routes behind the dashboard's Train page."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import numpy as np
import pytest

from continuum.connector import db
from continuum.detection.baseline import Baseline, baseline_path, save_baseline
from continuum.detection.features import FEATURE_NAMES
from continuum.detection.model import model_path
from continuum.runtime import RuntimeIdentity, write_runtime_status

ROUTES = [
    ("get", "/training", None),
    ("post", "/training/start", {"paragraph_index": 0}),
    ("post", "/training/stop", None),
    ("post", "/training/train", None),
    ("delete", "/training/baseline", None),
]


def _call(client, method, path, body=None, headers=None):
    kwargs = {"headers": headers or {}}
    if body is not None:
        kwargs["json"] = body
    return getattr(client, method)(path, **kwargs)


@pytest.mark.parametrize(("method", "path", "body"), ROUTES)
def test_training_routes_reject_a_missing_token(connector_client, method, path, body):
    assert _call(connector_client, method, path, body).status_code == 401


@pytest.mark.parametrize(("method", "path", "body"), ROUTES)
def test_training_routes_reject_a_wrong_token(connector_client, method, path, body):
    response = _call(connector_client, method, path, body, {"Authorization": "Bearer wrong"})
    assert response.status_code == 401


def test_status_accepts_a_valid_token_and_starts_empty(connector_client, auth_headers):
    body = connector_client.get("/training", headers=auth_headers).json()

    assert body["runtime_running"] is False
    assert body["session"] is None
    assert body["saved_sessions"] == 0
    assert body["baseline"]["exists"] is False
    assert body["model"]["exists"] is False
    assert body["minimum_windows"] == 60
    assert body["recommended_windows"] == 150


def test_start_creates_a_session_and_a_start_command(
    connector_client, auth_headers, connector_app
):
    body = connector_client.post(
        "/training/start", json={"paragraph_index": 3}, headers=auth_headers
    ).json()

    assert body["session"]["state"] == db.SESSION_REQUESTED
    assert body["session"]["paragraph_index"] == 3
    session = connector_app.state.session_factory()
    try:
        commands = session.execute(db.select(db.CommandRow)).scalars().all()
    finally:
        session.close()
    assert [(c.command_type, c.device_id) for c in commands] == [
        (db.COMMAND_BASELINE_START, str(body["session"]["id"]))
    ]


def test_a_second_start_while_one_is_active_is_refused(connector_client, auth_headers):
    connector_client.post("/training/start", json={}, headers=auth_headers)

    response = connector_client.post("/training/start", json={}, headers=auth_headers)

    assert response.status_code == 409


def test_start_rejects_extra_fields(connector_client, auth_headers):
    response = connector_client.post(
        "/training/start", json={"paragraph_index": 0, "keys": "abc"}, headers=auth_headers
    )
    assert response.status_code == 422


def test_stop_cancels_a_session_the_runtime_never_picked_up(connector_client, auth_headers):
    connector_client.post("/training/start", json={}, headers=auth_headers)

    body = connector_client.post("/training/stop", headers=auth_headers).json()

    assert body["session"]["state"] == db.SESSION_CANCELLED


def test_stop_asks_the_runtime_to_save_a_recording_session(
    connector_client, auth_headers, connector_app
):
    session_id = connector_client.post(
        "/training/start", json={}, headers=auth_headers
    ).json()["session"]["id"]
    session = connector_app.state.session_factory()
    session.get(db.BaselineSessionRow, session_id).state = db.SESSION_RECORDING
    session.commit()

    connector_client.post("/training/stop", headers=auth_headers)

    stops = session.execute(
        db.select(db.CommandRow).where(db.CommandRow.command_type == db.COMMAND_BASELINE_STOP)
    ).scalars().all()
    session.close()
    assert [c.device_id for c in stops] == [str(session_id)]


def test_stop_without_a_session_is_a_conflict(connector_client, auth_headers):
    assert connector_client.post("/training/stop", headers=auth_headers).status_code == 409


def test_status_reports_a_running_runtime(connector_client, auth_headers, connector_settings):
    identity = RuntimeIdentity(
        started_at=datetime.now(UTC).isoformat(), pid=1, elevated=True,
        configured_mode="disable_only", effective_mode="disable_only", dry_run=False,
        model_version="none", calibrated_threshold=0.0, base_threshold=0.0, sensitivity=5,
    )
    write_runtime_status(
        db.resolve_database_path(connector_settings), identity, state="running", devices=[]
    )

    body = connector_client.get("/training", headers=auth_headers).json()

    assert body["runtime_running"] is True


def _write_baseline(baseline_dir, n_windows):
    rng = np.random.default_rng(0)
    now = datetime.now(UTC)
    save_baseline(
        baseline_path("tester", baseline_dir=baseline_dir),
        Baseline(
            user="tester",
            device_id="kbd-1",
            feature_names=list(FEATURE_NAMES),
            features=rng.normal(size=(n_windows, len(FEATURE_NAMES))),
            captured_at=[now - timedelta(seconds=i) for i in range(n_windows)],
        ),
    )


def test_train_refuses_without_a_baseline(connector_client, auth_headers):
    response = connector_client.post("/training/train", headers=auth_headers)

    assert response.status_code == 409
    assert "No baseline yet" in response.json()["detail"]


def test_train_refuses_too_small_a_baseline(connector_client, auth_headers, connector_paths):
    _write_baseline(connector_paths["baseline_dir"], 30)

    response = connector_client.post("/training/train", headers=auth_headers)

    assert response.status_code == 409
    assert "at least 60" in response.json()["detail"]


def test_train_saves_a_model_the_runtime_will_load(
    connector_client, auth_headers, connector_paths
):
    _write_baseline(connector_paths["baseline_dir"], 120)

    body = connector_client.post("/training/train", headers=auth_headers).json()

    assert body["model"]["exists"] is True
    assert body["baseline"]["n_windows"] == 120
    assert model_path("tester", model_dir=connector_paths["model_dir"]).exists()


def test_train_is_refused_while_recording(connector_client, auth_headers, connector_paths):
    _write_baseline(connector_paths["baseline_dir"], 120)
    connector_client.post("/training/start", json={}, headers=auth_headers)

    assert connector_client.post("/training/train", headers=auth_headers).status_code == 409


def test_reset_deletes_the_baseline_but_keeps_the_model(
    connector_client, auth_headers, connector_paths
):
    _write_baseline(connector_paths["baseline_dir"], 120)
    connector_client.post("/training/train", headers=auth_headers)

    body = connector_client.delete("/training/baseline", headers=auth_headers).json()

    assert body["baseline"]["exists"] is False
    assert body["model"]["exists"] is True
