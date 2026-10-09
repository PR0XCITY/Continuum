"""Skeleton-stage tests.

These tests exist before any feature logic does. They guard the things
the project skeleton promises: every module imports cleanly, the default
config is valid and has the shape later code will rely on, and the hard
design rules are actually present in CLAUDE.md and not violated by any
tracked text file in the repository.
"""

from __future__ import annotations

import importlib
import pathlib

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


def test_claude_md_contains_every_hard_design_rule():
    text = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")

    required_phrases = [
        "Never a keylogger",
        "Capture is isolated from analysis",
        "Everything runs locally",
        "structured and schema-validated",
        "always requires a bearer token",
        "valid and safe output of IncidentRAG",
        "never block the last remaining keyboard",
        "never block an allowlisted device",
        "auto-release",
        "releases every blocked device",
        "No em dashes",
    ]

    for phrase in required_phrases:
        assert phrase in text, f"CLAUDE.md is missing required rule text: {phrase!r}"


def _tracked_text_files():
    # .agents and .claude/skills hold vendored skill packages, not Continuum
    # project content; the em dash rule governs what this project authors,
    # not third-party skill docs installed alongside it.
    skip_dirs = {
        ".git",
        ".venv",
        "venv",
        "data",
        "node_modules",
        ".ruff_cache",
        ".pytest_cache",
        ".agents",
        ".claude",
    }
    text_suffixes = {".md", ".py", ".yaml", ".yml", ".toml", ".ps1", ".txt", ""}

    for path in REPO_ROOT.rglob("*"):
        if path == pathlib.Path(__file__).resolve():
            continue
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
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
