# Continuum task runner. Requires https://github.com/casey/just.
# Every recipe here has an equivalent target in tasks.ps1 for machines
# without just installed. Keep the two in sync.

set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

venv_python := ".venv\\Scripts\\python.exe"

# List available targets.
default:
    @just --list

# Create .venv and install pinned requirements, including dev tools.
setup:
    py -3.12 -m venv .venv
    {{venv_python}} -m pip install --upgrade pip
    {{venv_python}} -m pip install -e ".[dev]"

# Run the test suite. All Win32 calls are mocked, so this runs on any
# platform.
test:
    {{venv_python}} -m pytest

# Run the linter.
lint:
    {{venv_python}} -m ruff check .

# Run the capture/detection/response loop. Requires an elevated
# (Administrator) PowerShell session because pnputil device enable and
# disable needs elevation.
run-runtime:
    @Write-Host "run-runtime needs an elevated PowerShell session for pnputil."
    {{venv_python}} -m continuum.runtime

# Run the FastAPI connector, local only, on the port from config/default.yaml.
run-api:
    {{venv_python}} -m uvicorn continuum.connector.app:app --host 127.0.0.1 --port 8731

# Run the Streamlit dashboard.
run-dashboard:
    {{venv_python}} -m streamlit run src/continuum/dashboard/app.py --browser.gatherUsageStats false --server.address 127.0.0.1

# Run the connector and the dashboard together, each in its own window.
# The runtime is intentionally not included here; it is elevated and run
# separately with "just run-runtime".
run-all:
    Start-Process powershell -ArgumentList '-NoExit', '-Command', 'just run-api'
    Start-Process powershell -ArgumentList '-NoExit', '-Command', 'just run-dashboard'
