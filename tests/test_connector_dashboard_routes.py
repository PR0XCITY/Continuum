"""Tests for the connector routes added for the dashboard.

GET /runtime, GET /calibration, GET /settings and PUT /settings, each
rejected without a valid bearer token and accepted with one, plus the
shared-file contract between continuum.runtime's status heartbeat and
GET /runtime.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import numpy as np
import pytest
import yaml

from continuum.connector import db
from continuum.detection.baseline import Baseline, save_baseline
from continuum.detection.features import FEATURE_NAMES
from continuum.detection.model import fit_and_calibrate
from continuum.runtime import RuntimeIdentity, describe_devices, write_runtime_status

ROUTES = [
    ("get", "/runtime", None),
    ("get", "/calibration", None),
    ("get", "/settings", None),
    (
        "put",
        "/settings",
        {"sensitivity": 5, "response_mode": "alert_only", "dry_run": True, "allowlist": []},
    ),
]


@pytest.mark.parametrize(("method", "path", "body"), ROUTES)
def test_new_routes_reject_a_missing_token(connector_client, method, path, body):
    response = getattr(connector_client, method)(path, **({"json": body} if body else {}))
    assert response.status_code == 401


@pytest.mark.parametrize(("method", "path", "body"), ROUTES)
def test_new_routes_reject_a_wrong_token(connector_client, method, path, body):
    response = getattr(connector_client, method)(
        path,
        headers={"Authorization": "Bearer wrong"},
        **({"json": body} if body else {}),
    )
    assert response.status_code == 401


@pytest.mark.parametrize(("method", "path", "body"), ROUTES)
def test_new_routes_accept_a_valid_token(connector_client, auth_headers, method, path, body):
    response = getattr(connector_client, method)(
        path, headers=auth_headers, **({"json": body} if body else {})
    )
    assert response.status_code == 200


# --- GET /runtime ------------------------------------------------------------


def _identity(**overrides):
    values = dict(
        started_at=datetime.now(UTC).isoformat(),
        pid=4242,
        elevated=True,
        configured_mode="lock_and_disable",
        effective_mode="lock_and_disable",
        dry_run=False,
        model_version="isolation_forest-test",
        calibrated_threshold=0.1,
        base_threshold=0.08,
        sensitivity=7,
    )
    values.update(overrides)
    return RuntimeIdentity(**values)


def _db_path(connector_settings):
    return db.resolve_database_path(connector_settings)


def test_runtime_reports_never_started_without_a_heartbeat(connector_client, auth_headers):
    body = connector_client.get("/runtime", headers=auth_headers).json()

    assert body["running"] is False
    assert body["state"] == "never_started"
    assert body["devices"] == []


def test_runtime_reads_back_what_the_runtime_heartbeat_wrote(
    connector_client, auth_headers, connector_settings
):
    devices = [
        {
            "device_id": "dev-1",
            "name": "Office Keyboard",
            "vendor_id": "046D",
            "product_id": "C31C",
            "bus_type": "USB",
            "is_usb": True,
            "disabled": False,
        }
    ]
    write_runtime_status(
        _db_path(connector_settings), _identity(), state="running", devices=devices
    )

    body = connector_client.get("/runtime", headers=auth_headers).json()

    assert body["running"] is True
    assert body["elevated"] is True
    assert body["sensitivity"] == 7
    assert body["threshold"] == pytest.approx(0.08)
    assert body["devices"][0]["name"] == "Office Keyboard"


def test_runtime_heartbeat_upserts_a_single_row(
    connector_client, auth_headers, connector_settings, connector_app
):
    path = _db_path(connector_settings)
    write_runtime_status(path, _identity(), state="running", devices=[])
    write_runtime_status(path, _identity(), state="stopped", devices=[])

    session = connector_app.state.session_factory()
    try:
        rows = session.execute(db.select(db.RuntimeStatusRow)).scalars().all()
    finally:
        session.close()
    assert len(rows) == 1
    body = connector_client.get("/runtime", headers=auth_headers).json()
    assert body["state"] == "stopped"
    assert body["running"] is False


def test_runtime_with_a_stale_heartbeat_is_not_running(
    connector_client, auth_headers, connector_settings, connector_app
):
    write_runtime_status(_db_path(connector_settings), _identity(), state="running", devices=[])
    session = connector_app.state.session_factory()
    try:
        row = db.get_runtime_status(session)
        row.heartbeat_at = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
        session.commit()
    finally:
        session.close()

    body = connector_client.get("/runtime", headers=auth_headers).json()

    assert body["running"] is False
    assert body["state"] == "stopped"
    assert body["seconds_since_heartbeat"] > 200


def test_write_runtime_status_is_best_effort_without_the_table(tmp_path):
    # No connector tables yet: must not raise.
    write_runtime_status(tmp_path / "empty.sqlite3", _identity(), state="running", devices=[])


def test_describe_devices_reports_identity_and_disabled_state():
    class _Device:
        def __init__(self, device_id, instance_id):
            self.device_id = device_id
            self.instance_id = instance_id
            self.name = f"Keyboard {device_id}"
            self.vendor_id = "046D"
            self.product_id = "C31C"
            self.bus_type = "USB"
            self.is_usb = True

    class _Capture:
        def list_devices(self):
            return [_Device("a", "inst-a"), _Device("b", "inst-b")]

    class _Blocker:
        def is_disabled(self, instance_id):
            return instance_id == "inst-b"

    devices = describe_devices(_Capture(), _Blocker())

    assert [d["disabled"] for d in devices] == [False, True]
    assert set(devices[0]) == {
        "device_id",
        "name",
        "vendor_id",
        "product_id",
        "bus_type",
        "is_usb",
        "disabled",
    }


def test_describe_devices_survives_a_capture_failure():
    class _Broken:
        def list_devices(self):
            raise OSError("raw input unavailable")

    assert describe_devices(_Broken(), object()) == []


# --- GET /calibration -----------------------------------------------------------


def test_calibration_with_nothing_trained(connector_client, auth_headers):
    body = connector_client.get("/calibration", headers=auth_headers).json()

    assert body["models"] == []
    assert body["baselines"] == []
    assert body["eval_results_markdown"] is None
    assert body["configured_sensitivity"] == 5


def test_calibration_describes_a_real_model_baseline_and_eval(
    connector_client, auth_headers, connector_paths
):
    rng = np.random.default_rng(0)
    matrix = rng.normal(size=(60, len(FEATURE_NAMES)))
    model = fit_and_calibrate(matrix, feature_names=FEATURE_NAMES, baseline_device_id="kbd-1")
    model.save(connector_paths["model_dir"] / "alice.joblib")
    now = datetime.now(UTC)
    save_baseline(
        connector_paths["baseline_dir"] / "alice.npz",
        Baseline(
            user="alice",
            device_id="kbd-1",
            feature_names=list(FEATURE_NAMES),
            features=matrix,
            captured_at=[now - timedelta(days=3), now - timedelta(days=1)],
        ),
    )
    connector_paths["eval_results_path"].write_text("# Results\n\n| a | b |\n| --- | --- |\n")

    body = connector_client.get("/calibration", headers=auth_headers).json()

    [model_summary] = body["models"]
    assert model_summary["user"] == "alice"
    assert model_summary["version"] == model.version
    assert model_summary["threshold_at_configured_sensitivity"] == pytest.approx(model.threshold)
    [baseline_summary] = body["baselines"]
    assert baseline_summary["n_windows"] == 60
    assert baseline_summary["device_id"] == "kbd-1"
    assert body["eval_results_markdown"].startswith("# Results")


def test_calibration_reports_an_unreadable_model_instead_of_failing(
    connector_client, auth_headers, connector_paths
):
    (connector_paths["model_dir"] / "broken.joblib").write_bytes(b"not a model")

    body = connector_client.get("/calibration", headers=auth_headers).json()

    assert body["models"][0]["user"] == "broken"
    assert "error" in body["models"][0]


# --- GET and PUT /settings --------------------------------------------------------


def test_get_settings_returns_the_effective_defaults(connector_client, auth_headers):
    body = connector_client.get("/settings", headers=auth_headers).json()

    assert body["settings"]["sensitivity"] == 5
    assert body["settings"]["response_mode"] == "lock_and_disable"
    assert body["applies_on"] == "runtime_restart"


def test_put_settings_writes_local_yaml_and_reads_back(
    connector_client, auth_headers, connector_paths
):
    new = {
        "sensitivity": 8,
        "response_mode": "lock_only",
        "dry_run": True,
        "allowlist": ["  HID\\VID_046D&PID_C31C\\1  ", "HID\\VID_046D&PID_C31C\\1", ""],
    }

    response = connector_client.put("/settings", json=new, headers=auth_headers)

    assert response.status_code == 200
    saved = response.json()["settings"]
    assert saved["sensitivity"] == 8
    assert saved["allowlist"] == ["HID\\VID_046D&PID_C31C\\1"]
    written = yaml.safe_load(connector_paths["local_override_path"].read_text(encoding="utf-8"))
    assert written["response"]["mode"] == "lock_only"
    assert written["detection"]["sensitivity"] == 8
    again = connector_client.get("/settings", headers=auth_headers).json()["settings"]
    assert again == saved


def test_put_settings_preserves_other_local_overrides(
    connector_client, auth_headers, connector_paths
):
    path = connector_paths["local_override_path"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("connector:\n  port: 9000\n", encoding="utf-8")

    connector_client.put(
        "/settings",
        json={"sensitivity": 4, "response_mode": "alert_only", "dry_run": False, "allowlist": []},
        headers=auth_headers,
    )

    written = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert written["connector"]["port"] == 9000
    assert written["detection"]["sensitivity"] == 4


@pytest.mark.parametrize(
    "body",
    [
        {"sensitivity": 11, "response_mode": "alert_only", "dry_run": False, "allowlist": []},
        {"sensitivity": 5, "response_mode": "nuke", "dry_run": False, "allowlist": []},
        {"sensitivity": "5", "response_mode": "alert_only", "dry_run": False, "allowlist": []},
        {"sensitivity": 5, "response_mode": "alert_only", "dry_run": False, "allowlist": ["a\x00"]},
        {
            "sensitivity": 5,
            "response_mode": "alert_only",
            "dry_run": False,
            "allowlist": [],
            "auto_release_timeout_seconds": 1,
        },
    ],
)
def test_put_settings_rejects_invalid_values_and_writes_nothing(
    connector_client, auth_headers, connector_paths, body
):
    response = connector_client.put("/settings", json=body, headers=auth_headers)

    assert response.status_code == 422
    assert not connector_paths["local_override_path"].exists()


def test_settings_report_environment_overrides(connector_client, auth_headers, monkeypatch):
    monkeypatch.setenv("CONTINUUM_RESPONSE__MODE", "alert_only")

    body = connector_client.get("/settings", headers=auth_headers).json()

    assert body["env_overridden_fields"] == ["response_mode"]
    assert body["settings"]["response_mode"] == "alert_only"
