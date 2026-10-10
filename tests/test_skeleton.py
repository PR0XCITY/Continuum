"""Skeleton-stage tests.

These tests exist before any feature logic does. They guard the things
the project skeleton promises: every module imports cleanly, the default
config is valid and has the shape later code will rely on, and no
tracked text file in the repository contains an em dash.
"""

from __future__ import annotations

import importlib
import pathlib
import subprocess

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

CONTINUUM_MODULES = [
    "continuum",
    "continuum.runtime",
    "continuum.common",
    "continuum.common.schemas",
    "continuum.common.config",
    "continuum.common.logging",
    "continuum.capture",
    "continuum.capture.base",
    "continuum.capture.windows_rawinput",
    "continuum.capture.factory",
    "continuum.detection",
    "continuum.detection.features",
    "continuum.detection.baseline",
    "continuum.detection.model",
    "continuum.detection.scorer",
    "continuum.response",
    "continuum.response.blocker_windows",
    "continuum.response.lockscreen",
    "continuum.response.alerts",
    "continuum.connector",
    "continuum.connector.app",
    "continuum.connector.auth",
    "continuum.connector.db",
    "continuum.rag",
    "continuum.rag.ingest",
    "continuum.rag.embed",
    "continuum.rag.retrieve",
    "continuum.rag.confidence",
    "continuum.rag.answer",
    "continuum.dashboard",
    "continuum.dashboard.app",
]


def test_every_module_imports_cleanly():
    for module_name in CONTINUUM_MODULES:
        importlib.import_module(module_name)


def test_default_config_is_valid_yaml_with_expected_sections():
    config_path = REPO_ROOT / "config" / "default.yaml"
    loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    for section in ("detection", "response", "connector", "rag", "dashboard", "logging"):
        assert section in loaded

    assert "window_size" in loaded["detection"]
    assert "anomaly_threshold" in loaded["detection"]
    assert "debounce_ms" in loaded["detection"]
    assert "mode" in loaded["response"]
    assert "auto_release_timeout_seconds" in loaded["response"]
    assert "allowlist" in loaded["response"]
    assert "port" in loaded["connector"]
    assert "ollama_model" in loaded["rag"]
    assert "chroma_path" in loaded["rag"]


def _tracked_text_files():
    """Text files git tracks or would track: ignored and excluded paths are skipped."""
    text_suffixes = {".md", ".py", ".yaml", ".yml", ".toml", ".ps1", ".txt", ""}
    try:
        listing = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git is not available to list repository files")

    this_file = pathlib.Path(__file__).resolve()
    for name in listing.splitlines():
        path = REPO_ROOT / name
        if path.resolve() == this_file or not path.is_file():
            continue
        if path.name == "justfile" or path.suffix in text_suffixes:
            yield path


def test_no_em_dashes_anywhere_in_the_repo():
    em_dash = "—"
    offenders = []
    for path in _tracked_text_files():
        content = path.read_text(encoding="utf-8", errors="ignore")
        if em_dash in content:
            offenders.append(str(path.relative_to(REPO_ROOT)))

    assert not offenders, f"Em dash found in: {offenders}"
