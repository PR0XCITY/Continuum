"""End-to-end latency: first injected keystroke to incident visible and retrievable.

A simulated burst injection is replayed in real time, one event at a time
at its own timestamps, through continuum.runtime.process_event: the real
windowing, scorer, debounce, incident building and posting code. It
posts to a real connector app (in-process, with its lifespan running, so
the background RAG watcher ingests incidents exactly as in production)
backed by a throwaway SQLite file and Chroma store.

Stood in for: the Raw Input capture layer (events come from the
simulator instead of a device), the Win32 response (alert-only mode, so
nothing locks during evaluation), toast notifications, and the TCP hop
between runtime and connector (the in-process test client skips it).
"""

from __future__ import annotations

import os
import secrets
import time
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from continuum import runtime
from continuum.common.config import Settings
from continuum.common.schemas import DeviceInfo
from continuum.connector.app import create_app
from continuum.detection.model import CadenceModel
from continuum.detection.scorer import Scorer
from continuum.rag.ingest import chunk_text
from continuum.rag.retrieve import hybrid_retrieve
from continuum.response.blocker_windows import DeviceBlocker
from tools.evaluation.common import (
    PALETTE,
    SectionResult,
    distribution,
    fmt,
    md_table,
    new_figure,
    save_figure,
)
from tools.run_hardware_trial import PAYLOAD_CHARS
from tools.simulate_attacks import generate_burst_injection

TOKEN_ENV_VAR = "CONTINUUM_EVALUATION_API_TOKEN"
CORPUS_READY_TIMEOUT_SECONDS = 300.0
STAGE_TIMEOUT_SECONDS = 60.0
POLL_SECONDS = 0.02

STAGES = (
    ("block", "blocking window scored"),
    ("posted", "incident accepted by the connector"),
    ("visible", "incident readable through the API the dashboard uses"),
    ("retrievable", "incident retrievable by IncidentRAG"),
)


class _FakeCapture:
    def __init__(self, devices: list[DeviceInfo]) -> None:
        self._devices = devices

    def list_devices(self) -> list[DeviceInfo]:
        return list(self._devices)


def _sleep_until(target: float) -> None:
    while (remaining := target - time.perf_counter()) > 0:
        time.sleep(remaining - 0.002 if remaining > 0.003 else 0)


def _wait_for(predicate, timeout: float) -> float | None:
    """perf_counter time at which predicate() first held, or None on timeout."""
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if predicate():
            return time.perf_counter()
        time.sleep(POLL_SECONDS)
    return None


def _device(device_id: str, *, name: str, usb: bool = True) -> DeviceInfo:
    return DeviceInfo(
        device_id=device_id,
        vendor_id="16C0" if usb else "0001",
        product_id="27DB" if usb else "0001",
        name=name,
        bus_type="USB" if usb else "PS2",
        is_usb=usb,
        instance_id=device_id,
        first_seen=datetime.now(UTC),
    )


def _expected_playbook_chunks(corpus_path: Path, settings: Settings) -> int:
    return sum(
        len(
            chunk_text(
                path.read_text(encoding="utf-8"),
                chunk_size_tokens=settings.rag.chunk_size_tokens,
                overlap_tokens=settings.rag.chunk_overlap_tokens,
            )
        )
        for path in corpus_path.rglob("*.md")
    )


def _one_run(run: int, *, client, app, model: CadenceModel, workdir: Path, token: str) -> dict:
    injector = _device(rf"HID\VID_16C0&PID_27DB\EVAL{run:03d}", name="Simulated Digispark")
    builtin = _device(r"ACPI\PNP0303\EVAL", name="Built-in keyboard", usb=False)
    capture = _FakeCapture([injector, builtin])
    blocker = DeviceBlocker(dry_run=True, disabled_devices_path=workdir / f"disabled_{run}.json")
    outbox = runtime.IncidentOutbox(workdir / f"outbox_{run}.sqlite3")
    scorer = Scorer(model)
    buffers: dict = {}
    pending: dict = {}
    posted: dict[str, object] = {}

    original_post = runtime.post_or_queue_incident

    def recording_post(outbox_, client_, base_url, token_, incident):
        original_post(outbox_, client_, base_url, token_, incident)
        posted.setdefault("incident", incident)
        posted.setdefault("at", time.perf_counter())

    events = generate_burst_injection(injector.device_id, PAYLOAD_CHARS, seed=9_000 + run)
    first_ns = events[0].timestamp_ns
    runtime.post_or_queue_incident = recording_post
    try:
        start = time.perf_counter()
        for event in events:
            _sleep_until(start + (event.timestamp_ns - first_ns) / 1e9)
            runtime.process_event(
                event,
                device_buffers=buffers,
                pending_since=pending,
                scorer=scorer,
                capture=capture,
                blocker=blocker,
                outbox=outbox,
                http_client=client,
                base_url="",
                token=token,
                effective_mode="alert_only",
                allowlist=[],
                connector_db_path=workdir / "connector.sqlite3",
            )
            if posted:
                break
    finally:
        runtime.post_or_queue_incident = original_post
        outbox.close()

    if not posted:
        return {"run": run, "detected": False}

    incident = posted["incident"]
    incident_id = str(incident.incident_id)
    summary = incident.features_summary
    block_ms = summary[runtime.TRIAL_MS_TO_BLOCK]
    headers = {"Authorization": f"Bearer {token}"}
    collection = app.state.rag_collection

    visible_at = _wait_for(
        lambda: client.get(f"/incidents/{incident_id}", headers=headers).status_code == 200,
        STAGE_TIMEOUT_SECONDS,
    )

    def retrievable() -> bool:
        if not collection.get(where={"doc_id": incident_id})["ids"]:
            return False
        chunks = hybrid_retrieve(collection, f"What happened in incident {incident_id}?", top_k=5)
        return any(c.doc_id == incident_id for c in chunks)

    retrievable_at = _wait_for(retrievable, STAGE_TIMEOUT_SECONDS)

    def ms_since_start(moment: float | None) -> float | None:
        return None if moment is None else (moment - start) * 1000

    return {
        "run": run,
        "detected": True,
        "presses": summary[runtime.TRIAL_PRESSES_TO_BLOCK],
        "block": block_ms,
        "posted": ms_since_start(posted["at"]),
        "visible": ms_since_start(visible_at),
        "retrievable": ms_since_start(retrievable_at),
    }


def end_to_end_section(
    *,
    model: CadenceModel,
    settings: Settings,
    corpus_path: Path,
    workdir: Path,
    figures_dir: Path,
    runs: int,
) -> SectionResult:
    token = secrets.token_urlsafe(24)
    previous_token = os.environ.get(TOKEN_ENV_VAR)
    os.environ[TOKEN_ENV_VAR] = token
    original_notify = runtime.notify
    runtime.notify = lambda *args, **kwargs: None

    connector = settings.connector.model_copy(
        update={"database_path": workdir / "connector.sqlite3", "auth_token_env_var": TOKEN_ENV_VAR}
    )
    rag = settings.rag.model_copy(
        update={"chroma_path": workdir / "chroma", "corpus_path": corpus_path}
    )
    app = create_app(
        settings.model_copy(update={"connector": connector, "rag": rag}),
        local_override_path=workdir / "local.yaml",
        model_dir=workdir / "models",
        baseline_dir=workdir / "baselines",
        eval_results_path=workdir / "eval_results.md",
    )
    expected_chunks = _expected_playbook_chunks(corpus_path, settings)

    try:
        with TestClient(app) as client:
            ready = _wait_for(
                lambda: app.state.rag_collection.count() >= expected_chunks,
                CORPUS_READY_TIMEOUT_SECONDS,
            )
            if ready is None:
                raise RuntimeError("the connector's RAG worker never finished ingesting the corpus")
            results = [
                _one_run(run, client=client, app=app, model=model, workdir=workdir, token=token)
                for run in range(runs)
            ]
    finally:
        runtime.notify = original_notify
        if previous_token is None:
            os.environ.pop(TOKEN_ENV_VAR, None)
        else:
            os.environ[TOKEN_ENV_VAR] = previous_token

    detected = [r for r in results if r["detected"]]
    stage_stats = {key: distribution([r[key] for r in detected if r[key] is not None])
                   for key, _ in STAGES}
    presses = distribution([r["presses"] for r in detected])

    rows = [
        [
            label,
            fmt(stage_stats[key]["mean"], 0),
            fmt(stage_stats[key]["median"], 0),
            fmt(stage_stats[key]["p95"], 0),
            fmt(stage_stats[key]["max"], 0),
        ]
        for key, label in STAGES
    ]
    table = md_table(["ms from the first injected keystroke to", "mean", "median", "p95", "max"],
                     rows)

    fig, ax = new_figure(7.5, 3.8)
    for i, ((key, _), colour) in enumerate(zip(STAGES, PALETTE[1:], strict=False)):
        values = [r[key] for r in detected if r[key] is not None]
        ax.scatter([i] * len(values), values, color=colour, s=34, alpha=0.85)
    ax.set_xticks(range(len(STAGES)), [key for key, _ in STAGES])
    ax.set_yscale("log")
    ax.set_ylabel("ms after first keystroke (log scale)")
    ax.set_title("End to end, per run")
    figure = save_figure(fig, figures_dir, "end_to_end_latency.png")

    markdown = f"""{runs} runs of a simulated {PAYLOAD_CHARS}-keystroke burst injection, replayed in
real time through the runtime's own event handling and posted to a live in-process connector,
whose background watcher ingests new incidents into IncidentRAG's store. {len(detected)} of
{runs} runs were blocked, after {fmt(presses['mean'], 0)} key presses on average (every one
of which would already have reached the focused window; see Limitations).

{table}

Not included: the Raw Input delivery delay before the runtime sees a keystroke, the
LockWorkStation and pnputil calls (the evaluation runs in alert-only mode), and the loopback
TCP hop to the connector. The dashboard's Incidents page caches the incident list for up to
10 seconds, so an incident can take that much longer to show there than through the API.
Retrieval latency is dominated by the watcher's 3-second polling interval.

![End-to-end latency per run]({figure})
"""
    return SectionResult(
        markdown,
        facts={"e2e": stage_stats, "e2e_presses": presses, "e2e_detected": len(detected)},
    )
