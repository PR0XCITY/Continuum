# Continuum architecture

This document describes what each part of Continuum is responsible for and
how data moves between them. Its sections follow the System Design chapter
of the project report: Capture Layer, Cadence Analysis Engine, Block and
Alert Handler, Connector/API Layer, Retrieval Engine, Confidence Scorer and
Dashboard.

## Processes and trust boundaries

Continuum runs as three local processes plus an LLM that writes
IncidentRAG's answers. Nothing leaves the machine except, with the default
`rag.llm_provider: groq`, the question and the top retrieved chunks sent to
Groq's API to write each answer. With `ollama`, nothing leaves at all.

| Process | Privilege | Contains |
| --- | --- | --- |
| Runtime (`python -m continuum.runtime`) | Administrator | Capture Layer, Cadence Analysis Engine, Block and Alert Handler |
| Connector (`uvicorn continuum.connector.app:app`) | standard user | Connector/API Layer, Retrieval Engine, Confidence Scorer |
| Dashboard (`streamlit run src/continuum/dashboard/app.py`) | standard user | Dashboard |
| LLM: Groq API (default) or Ollama on `127.0.0.1:11434` | remote service, or standard user | the model that writes answers for the Retrieval Engine (Qwen3 27B on Groq, or Llama 3.1 8B in Ollama) |

Only the runtime is elevated, because only disabling a device needs it.
Keeping the web stack out of the elevated process means a bug in an HTTP
handler can never run with Administrator rights.

```mermaid
flowchart LR
    KB[Physical keyboards] -->|WM_INPUT| CAP
    subgraph RT[Runtime, elevated]
        CAP[Capture Layer] -->|KeyEvent queue| CAE[Cadence Analysis Engine]
        CAE -->|blocked verdict| BAH[Block and Alert Handler]
    end
    BAH -->|LockWorkStation, pnputil| WIN[Windows]
    BAH -->|POST /incidents| API
    subgraph CN[Connector, user]
        API[Connector/API Layer] --> DB[(SQLite)]
        DB -->|rag_ingest_queue| RE[Retrieval Engine]
        RE --> VS[(ChromaDB)]
        RE --> CS[Confidence Scorer]
        RE <-->|prompt / answer| OL[Groq API, or Ollama on 127.0.0.1]
    end
    CAE -->|live_snapshots, runtime_status| DB
    DB -->|commands| BAH
    DASH[Dashboard] -->|bearer token, HTTP| API
```

## Capture Layer

`src/continuum/capture/`: `base.py`, `windows_rawinput.py`, `factory.py`.

- Registers for raw keyboard input with `RegisterRawInputDevices` on a
  hidden message-only window (`RIDEV_INPUTSINK`, so input is seen whatever
  window has focus, and `RIDEV_DEVNOTIFY` for arrival and removal).
- Uses Raw Input rather than a keyboard hook because Raw Input reports the
  originating device handle. A hook cannot tell which physical device typed
  a key, and that is the signal needed to block one device and leave the
  others working.
- Turns each `WM_INPUT` into a `KeyEvent`: monotonic timestamp, down or up,
  a per-session press counter, the device id and an auto-repeat flag.
  There is no field for the key itself. The virtual-key code is touched
  only inside one small class that pairs a key-down with its key-up and
  detects auto-repeat; it never leaves that class.
- Runs on its own high-priority thread and does nothing except push events
  onto a bounded queue. It never computes features or decides anything.
- Is observe-only: Raw Input delivers a copy of each keystroke and cannot
  hold one back. Every keystroke reaches the focused window whether or not
  Continuum later blocks the device.
- Tags keystrokes that arrive with no device handle (`hDevice` NULL) with
  the fixed device id `software-input`. Windows does this for input that
  software creates with `SendInput`, which is how remote-access tools such
  as AnyDesk and TeamViewer, and macros, type. Verified on Windows 11:
  every injected keystroke reported `hDevice` 0. These events carry the
  same fields as any other: timing and down/up only.

## Remote-access typing guard

`src/continuum/detection/remote_input.py`, `src/continuum/remote_guard.py`,
`src/continuum/response/remote_session.py`.

- The runtime sends every `software-input` event to the guard and never to
  the cadence engine or a baseline recording.
- `RemoteInputMonitor` counts software-generated key presses in a sliding
  window, timed by the keystrokes' own capture timestamps. `remote.min_presses`
  (3) within `remote.window_seconds` (5) is a run of typing; one trigger
  per 30-second cooldown.
- On a trigger, `remote_session.running_remote_tools` lists running
  process names with the Toolhelp API and keeps only those on
  `remote.tools`. With the default `trigger: remote_tool_running`, nothing
  happens unless one is running, so an on-screen keyboard or a password
  manager's auto-type does not lock the PC.
- If the dashboard's allow window is open (`remote_status.allowed_until`),
  the typing is let through and logged.
- Otherwise the guard responds by `remote.response`: `alert_only`, `lock`
  (default), or `lock_and_end_session`, which also ends the tool's
  processes with `taskkill`. `response.dry_run` turns any of them into an
  alert.
- The incident has attack pattern `remote_access_input`, MITRE technique
  T1219 Remote Access Software, the device `software-input` named after
  the tools that were running, and the action taken. It goes through the
  same outbox, connector validation and IncidentRAG ingestion as any other
  incident, and the `pb-remote-access-typing-response` playbook covers the
  response.
- Every maintenance tick the runtime writes which configured tools are
  running into `remote_status` for the dashboard's Remote access card.

## Cadence Analysis Engine

`src/continuum/detection/`: `features.py`, `baseline.py`, `model.py`,
`scorer.py`.

- **Windows.** Per device, a sliding window of 30 key presses, advanced
  every 10 presses. A pause longer than 2 seconds ends a run, and windows
  never span a pause.
- **Features.** 17 timing statistics per window: inter-key interval
  statistics (`flight_*`), how long keys are held (`dwell_*`), how often
  keys overlap (`rollover_ratio`), the share of intervals under 15 ms
  (`burst_score`), interval entropy, lag-1 autocorrelation and regularity.
- **Baseline.** `tools/record_baseline.py` records these statistics, never
  the typed text, while the user types normally. They are stored in
  `data/baselines/<user>.npz`.
- **Model.** A one-class Isolation Forest (or One-Class SVM) fitted on the
  baseline. Its threshold is calibrated on held-out baseline windows to a
  1 percent false positive rate, before it ever sees an attack.
- **Scorer.** The only place a score becomes a verdict:
  - `normal` if the score is below the threshold,
  - `suspicious` for a single flagged window,
  - `blocked` only when 2 windows are flagged within 3 seconds (debounce),
    so the earliest possible block is at the 40th key press.
  - A device that is not the baseline keyboard gets a stricter threshold
    (half) for its first 60 seconds, which covers a freshly plugged
    injection device.
  - `detection.sensitivity` (1 to 10, default 5) shifts the threshold.
- **Live state.** After every window the runtime writes the device's
  latest verdict and features to the connector's `live_snapshots` table,
  and every 5 seconds a heartbeat to `runtime_status`.

## Block and Alert Handler

`src/continuum/response/`: `lockscreen.py`, `blocker_windows.py`,
`alerts.py`; orchestrated by `src/continuum/runtime.py`.

On a `blocked` verdict, in this order:

1. **Lock** the workstation with `user32!LockWorkStation`. This happens
   first because anything the device types after this goes to the lock
   screen, not to a terminal.
2. **Disable** the device with `pnputil /disable-device`, unless a safety
   rule forbids it. The rules are checked in pure code before any
   `pnputil` call:
   - never an allowlisted device,
   - never a non-USB device such as a laptop's built-in keyboard (unless
     configured),
   - never the last enabled keyboard.

   The result is verified with CfgMgr32 instead of trusting the exit
   code, and the parent USB node is tried if the HID child stays
   active. Every disabled device is written to
   `data/disabled_devices.json` straight away.

   In practice Windows refuses to disable any keyboard while it is in use
   ("Cannot disable critical system device"), so against a keyboard
   injector this step fails and its pnputil output is logged. The device
   is then **quarantined** instead: it gets the same record in
   `data/disabled_devices.json`, marked `quarantined`, and from then on
   the runtime locks the workstation whenever that device presses a key
   (at most once every 2 seconds) and never scores it. A quarantine is
   lifted by the same paths as a disable: the dashboard's Unblock device
   button, the auto-release timeout, `--release-all`, or the runtime
   stopping. The allowlist and last-keyboard rails are checked before
   either. In `disable_only` mode, step 1 is skipped and a quarantine
   always comes with a lock, since the device can still type.
3. **Alert** with a Windows toast (winotify), a console line and an
   events log entry.
4. **Record** an `IncidentRecord` and POST it to the connector. If the
   connector is unreachable, it goes into a local SQLite outbox and is
   retried with exponential backoff.

Safety rails that no setting can turn off:

- every disabled device is re-enabled after `auto_release_timeout_seconds`
  (600 by default),
- `python -m continuum.runtime --release-all` re-enables everything at
  once,
- the runtime releases everything when it starts and when it stops.

The response mode (`alert_only`, `lock_only`, `lock_and_disable`) and
`dry_run` set how far the handler goes. Without elevation,
`lock_and_disable` falls back to `lock_only`.

Each incident also records, from the device's first keystroke, the
number of key presses and the milliseconds until the block and until the
lock.

## Connector/API Layer

`src/continuum/connector/`: `app.py`, `auth.py`, `db.py`, `document.py`,
`middleware.py`, `calibration.py`, `settings_store.py`.

- **Local only.** FastAPI on `127.0.0.1:8731`.
- **Always authenticated.** Every route except `/health` needs the bearer
  token from `.env`, including requests from localhost. The token is
  compared in constant time, and the service refuses all requests if no
  token is configured.
- **Request limits.** A 1 MiB body limit and a per-client rate limit.
- **Incidents.** `POST /incidents` validates the body against
  `IncidentRecord` (unknown fields are rejected), deduplicates on
  `incident_id`, sanitises and flags suspicious notes, stores the incident
  in SQLite, and queues a fixed-template text document for the Retrieval
  Engine. Raw request text never goes into the corpus.
- **Shared tables.** The runtime reads and writes three tables in the
  same SQLite file directly, so the elevated process never needs the web
  stack:
  - `commands`: unblock requests from `POST /devices/{id}/unblock`, read
    by the runtime,
  - `live_snapshots`: the runtime's latest per-device status,
  - `runtime_status`: the runtime's heartbeat.
- **Other routes.**
  - `GET /incidents` (filters and paging) and `GET /incidents/{id}`
  - `GET /live`, `GET /runtime` and `GET /stats`
  - `GET /calibration` (model, baseline and evaluation summary)
  - `GET` and `PUT /settings`: sensitivity, response mode, dry run and
    allowlist, validated and written atomically to `config/local.yaml`,
    applied when the runtime next starts
  - `POST /query`, which forwards to IncidentRAG

## Retrieval Engine

`src/continuum/rag/`: `embed.py`, `ingest.py`, `retrieve.py`, `answer.py`.

- **Corpus.** The playbooks in `data/corpus/` plus every incident. The
  connector's background thread polls the ingest queue every 3 seconds
  and ingests new incidents.
- **Poisoning defences.**
  - Incident documents must match the connector's fixed template, line
    by line, or they are rejected.
  - Playbooks are read only from `data/corpus/`, with a recorded content
    hash.
  - Every ingestion is logged.
- **Embeddings.** `all-MiniLM-L6-v2` (sentence-transformers), downloaded
  once during setup and used offline afterwards. Vectors are stored in a
  persistent ChromaDB collection, with ChromaDB's telemetry disabled.
- **Retrieval.** Hybrid: dense cosine similarity plus BM25 over the
  candidates, combined with reciprocal rank fusion. Filters by source
  type and date range.
- **Answers.** Written by the configured LLM (Qwen3 27B on Groq's API by default, or a local
  Ollama model) from only the top 5 chunks, numbered `[1]` to `[5]`:
  - every chunk, incident notes included, is wrapped in quotes as data,
    and the instructions say text inside a source is never an
    instruction,
  - temperature is 0.1,
  - every citation number in the answer is checked against the chunks
    actually sent, and invalid ones are dropped.

## Confidence Scorer

`src/continuum/rag/confidence.py`.

Confidence (0 to 1) is a weighted sum of four signals:

| Signal | Weight |
| --- | --- |
| Top similarity | 0.35 |
| Margin between the top two results | 0.15 |
| Share of chunks above the similarity floor | 0.15 |
| Answer support: share of the answer's cited sentences that are actually similar to the chunk they cite | 0.35 |

Below `rag.confidence_threshold` (0.5) the answer is withheld. The user
instead sees "Not enough evidence in the incident records to answer this
reliably" and the nearest sources to read themselves. Refusing is
treated as correct behaviour, not an error. If the LLM is unreachable (no
internet, no Groq key, or Ollama not running), the result is a clear
abstention, never a crash. Every answer records which provider and model
wrote it, and the dashboard shows it.

## Dashboard

`src/continuum/dashboard/`: `app.py`, `api.py`, `helpers.py`, `style.py`.

A Streamlit app on `127.0.0.1:8501` with six pages:

- **Live status:** runtime heartbeat, elevation, mode, attached keyboards
  with verdict badges, and a rolling 60-second inter-key interval chart.
- **Incidents:** filters, a timeline, a detail panel, "Unblock device" and
  "Ask IncidentRAG about this".
- **Ask IncidentRAG:** answers with a confidence meter and citations, or an
  amber "Insufficient evidence" card.
- **Train:** records the analyst's typing baseline and trains the model
  (see below).
- **Calibration and model.**
- **Settings.**

### Training from the dashboard

The Train page shows a paragraph (each playbook's "When to use" section)
and a box to type it in. Speed and accuracy are computed in the browser
and shown there only; the page has no network code, so the text never
leaves the browser. The timing itself is recorded by the runtime
(`src/continuum/recording.py`), through the same Raw Input capture
detection uses, so the model learns from the exact signal it is later
judged on and from the physical keyboard that typed:

1. `POST /training/start` adds a `baseline_sessions` row and a
   `baseline_start` command. The runtime polls commands every second,
   starts recording, and pauses detection, so training typing can never
   trigger a lock.
2. While recording, the runtime keeps the session's key-press count
   current, and the page shows it.
3. `POST /training/stop` sends `baseline_stop`. The runtime turns the
   typing into feature windows and appends them to the baseline file,
   then marks the session saved, or failed with a reason (too little
   continuous typing, or a different keyboard than the baseline's).
4. `POST /training/train` fits and calibrates the model in the connector,
   exactly as `tools/train_model.py` does. The runtime notices the new
   model file within 5 seconds and starts protecting with it; until a
   model exists it runs in recording-only mode.

The dashboard talks only to the connector API, with the bearer token. It
never opens the database or the vector store. Everything that came from
outside (notes, device names, model answers, snippets) is HTML-escaped,
so a crafted note cannot inject markup or make the browser fetch
anything. Streamlit's usage statistics are turned off.

## Data flow of one attack

1. A Digispark is plugged in and starts typing. Each keystroke reaches
   the focused window and, in parallel, the Capture Layer.
2. After 30 presses the first window is scored. A burst scores far above
   the threshold, so it is `suspicious`.
3. Ten presses later the second window is flagged as well, so it is
   `blocked`. In the evaluation this happened about 270 ms after the
   first keystroke.
4. The handler locks the session and tries to disable the device. Windows
   refuses to disable a keyboard in use, so the device is quarantined:
   every later key press from it locks the session again. It then raises
   a toast and posts the incident, readable through the API within
   milliseconds.
5. Within about 3 seconds the connector's watcher has embedded the
   incident, and IncidentRAG can answer questions about it.
6. The device is released after the timeout, through the dashboard's
   Unblock device button (Live status or Incidents), or with
   `--release-all`. The runtime polls for unblock commands every second.

Measured results and known limits are in [EVALUATION.md](EVALUATION.md).
