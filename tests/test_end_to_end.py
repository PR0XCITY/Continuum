"""End-to-end integration test: injection, detection, response, incident, IncidentRAG.

Real throughout: feature windowing, a fitted and calibrated CadenceModel,
the scorer and its debounce, continuum.runtime.process_event, the
blocker's safety checks, the FastAPI connector running its lifespan
(including the background RAG ingest watcher), SQLite, ChromaDB, the
sentence-transformers embedding model, hybrid retrieval, the confidence
gate and POST /query.

Mocked, and nothing else: the Win32 layer (LockWorkStation, pnputil, the
device status check, the elevation check, toast notifications) and the
LLM (continuum.rag.answer.call_llm, whichever provider is configured).

Needs the embedding model in the local cache, which setup downloads
(python -m continuum.rag.embed); the test is skipped, not failed, without
it, since it must never reach for the network.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from tests.conftest import CONNECTOR_TEST_TOKEN
from tools.simulate_attacks import generate_burst_injection, generate_human

import continuum.response.blocker_windows as blocker_module
from continuum import runtime
from continuum.common.config import get_settings
from continuum.common.schemas import TRIAL_PRESSES_TO_BLOCK, DeviceInfo
from continuum.connector import db
from continuum.connector.app import create_app
from continuum.detection.baseline import feature_windows_to_matrix
from continuum.detection.features import FEATURE_NAMES, iter_feature_windows
from continuum.detection.model import fit_and_calibrate
from continuum.detection.scorer import Scorer
from continuum.rag import answer as answer_module
from continuum.rag.embed import is_model_cached
from continuum.rag.retrieve import hybrid_retrieve
from continuum.response.blocker_windows import DeviceBlocker

pytestmark = pytest.mark.skipif(
    not is_model_cached(get_settings().rag.embedding_model),
    reason="embedding model not downloaded yet; run `python -m continuum.rag.embed` once",
)

BUILTIN_ID = r"ACPI\PNP0303\4&1A2B3C4D&0"
INJECTOR_ID = r"HID\VID_16C0&PID_27DB\7&2F3E4D5C&0&0000"
INGEST_TIMEOUT_SECONDS = 60.0


def _device(device_id: str, *, name: str, usb: bool) -> DeviceInfo:
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


class _Capture:
    def __init__(self, devices: list[DeviceInfo]) -> None:
        self.devices = devices

    def list_devices(self) -> list[DeviceInfo]:
        return list(self.devices)


@pytest.fixture
def trained_model():
    """A real model, fitted and calibrated on human-like typing on the built-in keyboard."""
    windows = []
    for seed in range(30):
        events = generate_human(BUILTIN_ID, 150, seed=50_000 + seed)
        windows.extend(iter_feature_windows(events, BUILTIN_ID))
    return fit_and_calibrate(
        feature_windows_to_matrix(windows, FEATURE_NAMES),
        feature_names=list(FEATURE_NAMES),
        baseline_device_id=BUILTIN_ID,
    )


@pytest.fixture
def win32(monkeypatch):
    """Every Win32 entry point the response path touches, recorded instead of called."""
    calls: dict[str, list] = {"lock": [], "pnputil_disable": [], "notify": []}

    def lock() -> bool:
        calls["lock"].append(time.perf_counter())
        return True

    monkeypatch.setattr(runtime, "lock_workstation", lock)
    monkeypatch.setattr(blocker_module, "is_elevated", lambda: True)
    monkeypatch.setattr(blocker_module, "_pnputil_disable", calls["pnputil_disable"].append)
    monkeypatch.setattr(blocker_module, "is_devnode_started", lambda instance_id: False)
    monkeypatch.setattr(runtime, "notify", lambda *a, **k: calls["notify"].append(k))
    return calls


def _wait_for(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


def test_burst_injection_is_blocked_recorded_ingested_and_retrievable(
    tmp_path, monkeypatch, connector_settings, connector_paths, trained_model, win32
):
    injector = _device(INJECTOR_ID, name="Digispark Keyboard", usb=True)
    builtin = _device(BUILTIN_ID, name="Built-in Keyboard", usb=False)
    capture = _Capture([builtin, injector])
    blocker = DeviceBlocker(disabled_devices_path=tmp_path / "disabled_devices.json")
    outbox = runtime.IncidentOutbox(tmp_path / "outbox.sqlite3")
    scorer = Scorer(trained_model)
    database_path = db.resolve_database_path(connector_settings)
    app = create_app(connector_settings, **connector_paths)

    with TestClient(app) as client:
        # 1. The injection stream goes through the runtime's real event handling.
        buffers: dict = {}
        pending: dict = {}
        for event in generate_burst_injection(INJECTOR_ID, 137, seed=7):
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
                token=CONNECTOR_TEST_TOKEN,
                effective_mode="lock_and_disable",
                allowlist=[],
                connector_db_path=database_path,
            )
            if win32["lock"]:
                break  # once disabled, a real device sends nothing more

        # 2. Response: locked first, then the device disabled through pnputil.
        assert len(win32["lock"]) == 1
        assert win32["pnputil_disable"] == [INJECTOR_ID]
        assert blocker.is_disabled(INJECTOR_ID)
        assert not blocker.is_disabled(BUILTIN_ID)
        assert [n["event_type"] for n in win32["notify"]] == ["blocked"]

        # 3. The incident reached the connector directly, not the offline outbox.
        assert len(outbox) == 0
        listing = client.get(
            "/incidents",
            params={"device_id": INJECTOR_ID},
            headers={"Authorization": f"Bearer {CONNECTOR_TEST_TOKEN}"},
        ).json()
        assert listing["total"] == 1
        incident = listing["items"][0]
        incident_id = incident["incident_id"]
        assert incident["verdict"] == "blocked"
        assert incident["action_taken"] == "locked_and_disabled"
        assert incident["attack_pattern"] == "burst_injection"
        assert 40 <= incident["features_summary"][TRIAL_PRESSES_TO_BLOCK] <= 60

        # 4. The connector's background watcher ingests it into IncidentRAG.
        def ingested() -> bool:
            session = app.state.session_factory()
            try:
                row = session.execute(
                    db.select(db.RagIngestQueueRow).where(
                        db.RagIngestQueueRow.incident_id == incident_id
                    )
                ).scalar_one()
                return row.status == "ingested"
            finally:
                session.close()

        assert _wait_for(ingested, INGEST_TIMEOUT_SECONDS), "incident was never ingested"

        # 5. Retrieval finds it.
        chunks = hybrid_retrieve(
            app.state.rag_collection, f"What happened in incident {incident_id}?", top_k=5
        )
        assert incident_id in [chunk.doc_id for chunk in chunks]

        # 6. /query answers from it, with the LLM mocked and the prompt inspected.
        prompts: list[str] = []

        def fake_llm(prompt: str, _llm, **_kwargs) -> str:
            prompts.append(prompt)
            numbers = re.findall(r"^\[(\d+)\] \(incident, Incident " + incident_id, prompt, re.M)
            source = numbers[0] if numbers else "1"
            return (
                f"Incident {incident_id} was a burst injection from the Digispark Keyboard; "
                f"the workstation was locked and the device disabled [{source}]."
            )

        monkeypatch.setattr(answer_module, "call_llm", fake_llm)
        response = client.post(
            "/query",
            json={"question": f"What happened in incident {incident_id}?"},
            headers={"Authorization": f"Bearer {CONNECTOR_TEST_TOKEN}"},
        )

    outbox.close()
    assert response.status_code == 200
    body = response.json()
    assert len(prompts) == 1 and incident_id in prompts[0]
    assert incident_id in [citation["doc_id"] for citation in body["citations"]]
    assert 0.0 < body["confidence"] <= 1.0
    if not body["abstained"]:
        assert incident_id in body["answer"]
