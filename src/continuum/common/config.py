"""Configuration loading for Continuum.

Responsibility: load config/default.yaml, layer an optional local override
file and environment variables on top of it, validate the merged result
against a pydantic model, and hand back a single immutable Settings
object to every entry point (runtime, API, dashboard, tools).

Precedence, lowest to highest:

    1. config/default.yaml
    2. config/local.yaml, if it exists (gitignored, machine-specific)
    3. environment variables shaped CONTINUUM_<SECTION>__<FIELD>=value,
       matching the examples in .env.example

A .env file at the repo root, if present, is loaded first so its values
participate as ordinary environment variables; it never overrides a
variable already set in the real environment. Flat secrets such as
CONTINUUM_API_TOKEN (no "__" separator) are deliberately left out of the
Settings tree; the module that needs them, for example connector.auth,
reads them from the environment directly by the name given in
connector.auth_token_env_var.

Uses pathlib exclusively for all path handling; no hardcoded path
separators anywhere in this module or in anything it returns.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "default.yaml"
LOCAL_OVERRIDE_PATH = REPO_ROOT / "config" / "local.yaml"
DOTENV_PATH = REPO_ROOT / ".env"
ENV_PREFIX = "CONTINUUM_"
ENV_NESTING_SEPARATOR = "__"


class StrictSettingsModel(BaseModel):
    """Base model: unknown config keys are always rejected, never ignored."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class DetectionSettings(StrictSettingsModel):
    window_size: int = Field(gt=0)
    debounce_ms: int = Field(ge=0)
    anomaly_threshold: float
    debounce_windows: int = Field(gt=0)


class ResponseSettings(StrictSettingsModel):
    mode: Literal["enforce", "alert_only"]
    auto_release_timeout_seconds: int = Field(gt=0)
    allowlist: list[str] = Field(default_factory=list)


class ConnectorSettings(StrictSettingsModel):
    host: str = Field(min_length=1)
    port: int = Field(gt=0, le=65535)
    database_path: Path
    auth_token_env_var: str = Field(min_length=1)


class RagSettings(StrictSettingsModel):
    ollama_host: str = Field(min_length=1)
    ollama_model: str = Field(min_length=1)
    embedding_model: str = Field(min_length=1)
    chroma_path: Path
    chroma_collection: str = Field(min_length=1)
    min_similarity: float = Field(ge=0.0, le=1.0)
    min_supporting_passages: int = Field(ge=0)
    top_k: int = Field(gt=0)


class DashboardSettings(StrictSettingsModel):
    host: str = Field(min_length=1)
    port: int = Field(gt=0, le=65535)


class LoggingSettings(StrictSettingsModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    directory: Path


class Settings(StrictSettingsModel):
    """Top-level, validated, immutable configuration for Continuum."""

    detection: DetectionSettings
    response: ResponseSettings
    connector: ConnectorSettings
    rag: RagSettings
    dashboard: DashboardSettings
    logging: LoggingSettings


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override onto base without mutating either."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _env_overrides(env: Mapping[str, str]) -> dict:
    """Turn CONTINUUM_<SECTION>__<FIELD> environment variables into a tree.

    A variable with no "__" separator (for example CONTINUUM_API_TOKEN)
    is not a Settings override and is skipped; it is read directly, by
    name, where it is needed.
    """
    overrides: dict = {}
    for raw_key, raw_value in env.items():
        if not raw_key.startswith(ENV_PREFIX):
            continue
        remainder = raw_key[len(ENV_PREFIX) :]
        parts = remainder.split(ENV_NESTING_SEPARATOR)
        if len(parts) < 2 or not all(parts):
            continue

        try:
            value = yaml.safe_load(raw_value)
        except yaml.YAMLError:
            value = raw_value

        node = overrides
        for part in parts[:-1]:
            node = node.setdefault(part.lower(), {})
        node[parts[-1].lower()] = value
    return overrides


def load_settings(
    *,
    config_path: Path = DEFAULT_CONFIG_PATH,
    local_override_path: Path = LOCAL_OVERRIDE_PATH,
    env: Mapping[str, str] | None = None,
    dotenv_path: Path = DOTENV_PATH,
) -> Settings:
    """Load, merge, validate and return the Settings for this process.

    Pass explicit arguments in tests to avoid touching real files or the
    real environment. Production code should call get_settings() instead
    so the whole process shares one instance.
    """
    load_dotenv(dotenv_path, override=False)

    data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    if local_override_path.exists():
        local_data = yaml.safe_load(local_override_path.read_text(encoding="utf-8")) or {}
        data = _deep_merge(data, local_data)

    resolved_env = os.environ if env is None else env
    data = _deep_merge(data, _env_overrides(resolved_env))

    return Settings.model_validate(data)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached, process-wide Settings instance.

    Every entry point should call this instead of constructing its own
    Settings, so the whole process agrees on one configuration.
    """
    return load_settings()
