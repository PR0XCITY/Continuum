# Continuum

Continuum is a closed-loop cybersecurity pipeline for Windows 10/11, built
as a college software engineering project. It detects keystroke-injection
attacks from HID-emulating devices (USB Rubber Ducky, Digispark, Bash
Bunny and similar), responds by locking the workstation and disabling the
offending device, records every response as a structured incident, and
lets an analyst ask incident-response questions against that incident
history through a local retrieval-augmented assistant.

See `CLAUDE.md` for the full design rules this project follows. The short
version: no key identity is ever captured or logged, everything runs
locally with no cloud calls, and there are hard safety rails around
blocking a device.

## Status

This is the project skeleton. No feature logic is implemented yet. The
layout, configuration, task runner, lint and test setup are in place so
that feature work can start from a clean, checked baseline.

## Components

- **HID Firewall** (`src/continuum/capture`, `detection`, `response`):
  reads raw keyboard input via the Windows Raw Input API, scores typing
  cadence per physical device with scikit-learn, and on a confirmed
  anomaly locks the workstation and disables the device, subject to
  safety rails (never the last keyboard, never an allowlisted device,
  always auto-release, always a one-command release-everything).
- **Connector** (`src/continuum/connector`): a local FastAPI service,
  bearer-token protected even on localhost, that turns every block or
  release into a structured, schema-validated incident record in SQLite.
- **IncidentRAG** (`src/continuum/rag`): embeds incidents with
  sentence-transformers, stores them in ChromaDB, retrieves relevant
  incidents for a question, gates the answer on retrieval confidence, and
  generates a cited answer with a local Ollama model. Refuses to answer
  when evidence is weak.
- **Dashboard** (`src/continuum/dashboard`): a Streamlit app for watching
  device status, browsing incidents, releasing a blocked device, and
  asking IncidentRAG questions.

## Requirements

- Windows 10 or 11.
- Python 3.12.
- [Ollama](https://ollama.com) running locally for IncidentRAG.
- An elevated (Administrator) terminal to run the capture/response
  runtime, because `pnputil` device enable/disable requires it.

## Setup

With [`just`](https://github.com/casey/just) installed:

```
just setup
```

Without `just`, from PowerShell:

```
.\tasks.ps1 setup
```

Both create a `.venv` and install the pinned requirements from
`pyproject.toml`.

Copy `.env.example` to `.env` and fill in a real bearer token before
running the connector API.

## Running

```
just test              # pytest, all Win32 calls mocked
just lint               # ruff check
just run-runtime        # capture + detection + response loop, elevated
just run-api            # FastAPI connector
just run-dashboard      # Streamlit dashboard
just run-all            # api + dashboard together
```

Or the PowerShell equivalents: `.\tasks.ps1 test`, `.\tasks.ps1 lint`,
`.\tasks.ps1 run-runtime`, `.\tasks.ps1 run-api`,
`.\tasks.ps1 run-dashboard`, `.\tasks.ps1 run-all`.

## Configuration

Defaults live in `config/default.yaml`: detection window size and
thresholds, debounce, response mode, auto-release timeout, API port,
Ollama model name, ChromaDB path, and the device allowlist. Override with
environment variables or a local YAML file as described in
`src/continuum/common/config.py`.

## License

Not yet decided.
