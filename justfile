# Continuum task runner. Requires https://github.com/casey/just.
# Every recipe calls the matching target in tasks.ps1, which holds the
# actual commands, so `just <target>` and `.\tasks.ps1 <target>` can never
# drift apart. See tasks.ps1 for what each target does.

set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

tasks := "powershell.exe -NoProfile -ExecutionPolicy Bypass -File tasks.ps1"

# List available targets.
default:
    @just --list

# Create .venv, install pinned packages, create .env, download the embedding model.
setup:
    {{tasks}} setup

# Run the test suite (all Win32 calls mocked).
test:
    {{tasks}} test

# Run the linter.
lint:
    {{tasks}} lint

# Record a typing baseline; pass a name to record another session, e.g. NAME_fast.
record-baseline *args:
    {{tasks}} record-baseline {{args}}

# Train and calibrate the cadence model from the baseline.
train-model *args:
    {{tasks}} train-model {{args}}

# Run the connector API in this window.
run-api:
    {{tasks}} run-api

# Run the Streamlit dashboard in this window.
run-dashboard:
    {{tasks}} run-dashboard

# Run the HID Firewall runtime in this window (elevated prompt required).
run-runtime:
    {{tasks}} run-runtime

# Start the API, the dashboard and the elevated runtime, each in its own window.
run-all:
    {{tasks}} run-all

# Stop everything cleanly; the runtime releases every disabled device first.
stop-all:
    {{tasks}} stop-all

# Show which components are running.
status:
    {{tasks}} status

# Load 200 synthetic incidents through the API.
seed-demo *args:
    {{tasks}} seed-demo {{args}}

# Re-enable every device Continuum disabled (elevated prompt required).
release-all:
    {{tasks}} release-all

# Regenerate docs/EVALUATION.md.
evaluate *args:
    {{tasks}} evaluate {{args}}
