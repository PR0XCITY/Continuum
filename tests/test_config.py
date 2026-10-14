"""Tests for continuum.common.config.

Covers loading the real default.yaml, environment variable overrides,
local override file layering, and that config.py's strict validation
rejects a typo'd or unknown override key.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from continuum.common import Settings, get_settings, load_settings
from continuum.common.config import DEFAULT_CONFIG_PATH, LOCAL_OVERRIDE_PATH


def test_load_settings_reads_the_real_default_config(tmp_path):
    # Ignore this machine's config/local.yaml: only default.yaml is under test.
    settings = load_settings(env={}, local_override_path=tmp_path / "no-local.yaml")

    assert isinstance(settings, Settings)
    assert settings.detection.window_size == 40
    assert settings.detection.anomaly_threshold == 0.65
    assert settings.response.mode == "lock_and_disable"
    assert settings.response.auto_release_timeout_seconds == 600
    assert settings.connector.port == 8731
    assert settings.rag.ollama_model == "llama3.1:8b"
    assert settings.rag.llm_provider == "groq"
    assert settings.rag.groq_model == "llama-3.1-8b-instant"
    assert settings.dashboard.port == 8501
    assert settings.logging.level == "INFO"


def test_env_override_changes_a_nested_value():
    env = {"CONTINUUM_RESPONSE__MODE": "alert_only"}
    settings = load_settings(env=env)

    assert settings.response.mode == "alert_only"
    # Everything not overridden still comes from default.yaml.
    assert settings.detection.window_size == 40


def test_env_override_coerces_numeric_types():
    env = {"CONTINUUM_DETECTION__ANOMALY_THRESHOLD": "0.9"}
    settings = load_settings(env=env)

    assert settings.detection.anomaly_threshold == 0.9
    assert isinstance(settings.detection.anomaly_threshold, float)


def test_env_override_handles_list_values():
    env = {"CONTINUUM_RESPONSE__ALLOWLIST": "[laptop-built-in-keyboard]"}
    settings = load_settings(env=env)

    assert settings.response.allowlist == ["laptop-built-in-keyboard"]


def test_flat_secret_env_var_is_ignored_by_settings():
    env = {"CONTINUUM_API_TOKEN": "super-secret-value"}
    settings = load_settings(env=env)

    assert not hasattr(settings.connector, "api_token")
    assert not hasattr(settings, "api_token")


def test_unrelated_env_vars_are_ignored():
    env = {"PATH": "/usr/bin", "HOME": "/home/someone"}
    settings = load_settings(env=env)

    assert settings.detection.window_size == 40


def test_unknown_override_key_is_rejected():
    env = {"CONTINUUM_DETECTION__NONEXISTENT_FIELD": "123"}
    with pytest.raises(ValidationError):
        load_settings(env=env)


def test_local_override_file_layers_over_defaults(tmp_path):
    local_override_path = tmp_path / "local.yaml"
    local_override_path.write_text("response:\n  mode: alert_only\n", encoding="utf-8")

    settings = load_settings(local_override_path=local_override_path, env={})

    assert settings.response.mode == "alert_only"
    assert settings.detection.window_size == 40


def test_env_overrides_a_local_override_file(tmp_path):
    local_override_path = tmp_path / "local.yaml"
    local_override_path.write_text("response:\n  mode: alert_only\n", encoding="utf-8")

    env = {"CONTINUUM_RESPONSE__MODE": "lock_only"}
    settings = load_settings(local_override_path=local_override_path, env=env)

    assert settings.response.mode == "lock_only"


def test_missing_local_override_file_is_not_an_error(tmp_path):
    missing_path = tmp_path / "does_not_exist.yaml"
    settings = load_settings(local_override_path=missing_path, env={})

    assert settings.detection.window_size == 40


def test_default_paths_point_at_the_real_repo_config():
    assert DEFAULT_CONFIG_PATH.name == "default.yaml"
    assert DEFAULT_CONFIG_PATH.exists()
    assert LOCAL_OVERRIDE_PATH.name == "local.yaml"


def test_get_settings_is_cached():
    first = get_settings()
    second = get_settings()

    assert first is second
    assert isinstance(first, Settings)
