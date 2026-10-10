"""Read and write the operator-editable settings in config/local.yaml.

Responsibility: the only code path that lets the dashboard (through the
connector API) change configuration. Exactly four values are editable:
detection.sensitivity, response.mode, response.dry_run and
response.allowlist. Everything else in config/local.yaml is preserved
as it was, apart from YAML comments, which a rewrite does not keep.

Every write is validated twice before it lands: once against
EditableSettings, and once by loading the complete merged configuration
through common.config.load_settings from a temporary file. Only then is
the temporary file moved over config/local.yaml, atomically, so a bad
value can never leave the runtime unable to start.

Changes take effect the next time the runtime starts; the running
runtime reports the values it actually uses through GET /runtime, so a
pending change is visible rather than silent.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from continuum.common.config import Settings, load_settings

ResponseMode = Literal["alert_only", "lock_only", "lock_and_disable"]

MAX_ALLOWLIST_ENTRIES = 100
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# Environment variables that would silently win over a value saved here.
_ENV_OVERRIDE_NAMES = {
    "sensitivity": "CONTINUUM_DETECTION__SENSITIVITY",
    "response_mode": "CONTINUUM_RESPONSE__MODE",
    "dry_run": "CONTINUUM_RESPONSE__DRY_RUN",
    "allowlist": "CONTINUUM_RESPONSE__ALLOWLIST",
}

_FILE_HEADER = (
    "# Machine-specific overrides of config/default.yaml. Gitignored.\n"
    "# Last written by the Continuum dashboard (PUT /settings).\n"
)


class EditableSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    sensitivity: int = Field(ge=1, le=10)
    response_mode: ResponseMode
    dry_run: bool
    allowlist: list[str] = Field(max_length=MAX_ALLOWLIST_ENTRIES)

    @field_validator("allowlist")
    @classmethod
    def _clean_allowlist(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for entry in value:
            entry = entry.strip()
            if not entry:
                continue
            if len(entry) > 512:
                raise ValueError("allowlist entries must be at most 512 characters")
            if _CONTROL_CHAR_PATTERN.search(entry):
                raise ValueError("allowlist entries must not contain control characters")
            if entry not in cleaned:
                cleaned.append(entry)
        return cleaned


def editable_from_settings(settings: Settings) -> EditableSettings:
    return EditableSettings(
        sensitivity=settings.detection.sensitivity,
        response_mode=settings.response.mode,
        dry_run=settings.response.dry_run,
        allowlist=list(settings.response.allowlist),
    )


def env_overridden_fields(env: Mapping[str, str] | None = None) -> list[str]:
    resolved = os.environ if env is None else env
    return [field for field, name in _ENV_OVERRIDE_NAMES.items() if name in resolved]


def read_editable(local_override_path: Path) -> EditableSettings:
    """The effective values right now: defaults, then local.yaml, then env."""
    return editable_from_settings(load_settings(local_override_path=local_override_path))


def write_editable(local_override_path: Path, new: EditableSettings) -> EditableSettings:
    """Merge new into local.yaml, validate the whole config, then replace atomically."""
    existing: dict = {}
    if local_override_path.exists():
        existing = yaml.safe_load(local_override_path.read_text(encoding="utf-8")) or {}
        if not isinstance(existing, dict):
            raise ValueError(f"{local_override_path} is not a YAML mapping")

    detection = dict(existing.get("detection") or {})
    response = dict(existing.get("response") or {})
    detection["sensitivity"] = new.sensitivity
    response["mode"] = new.response_mode
    response["dry_run"] = new.dry_run
    response["allowlist"] = list(new.allowlist)
    merged = {**existing, "detection": detection, "response": response}

    local_override_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = local_override_path.with_name(local_override_path.name + ".tmp")
    temporary_path.write_text(
        _FILE_HEADER + yaml.safe_dump(merged, sort_keys=False), encoding="utf-8"
    )
    try:
        load_settings(local_override_path=temporary_path, env={})
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    os.replace(temporary_path, local_override_path)
    return read_editable(local_override_path)
