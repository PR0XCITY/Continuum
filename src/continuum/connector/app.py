"""FastAPI application for the connector layer.

Responsibility: the HTTP surface that turns a "blocked" verdict from
the runtime into a stored, queryable incident, and the one place
outside the runtime itself allowed to request a device be unblocked.
Wires together auth.py (bearer token, every route but /health), db.py
(SQLAlchemy persistence, plus the two tables shared file-level with
continuum.runtime), document.py (notes sanitising, suspicious-notes
detection, the fixed RAG document template), middleware.py (request
size and rate limits), and continuum.rag (POST /query, answered by
IncidentRAG's retrieve -> generate -> confidence-gate pipeline).

Runs local-only: binds to 127.0.0.1 by default (see justfile /
tasks.ps1's run-api target), makes no outbound network calls other
than to the local Ollama HTTP API, and sends no telemetry anywhere.

create_app() is the real entry point, used directly by tests so each
test gets its own isolated SQLite file; the module-level `app` below
is what `uvicorn continuum.connector.app:app` serves, built against
the real configured settings at import time.
"""

from __future__ import annotations

import getpass
import json
import threading
from collections.abc import AsyncIterator, Generator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from continuum.common.config import LOCAL_OVERRIDE_PATH, REPO_ROOT, Settings, get_settings
from continuum.common.logging import get_logger
from continuum.common.schemas import AttackPattern, IncidentRecord, Verdict
from continuum.connector import calibration, db, settings_store, training
from continuum.connector.auth import make_bearer_token_dependency
from continuum.connector.document import (
    detect_suspicious_notes,
    render_incident_document,
    sanitise_notes,
)
from continuum.connector.middleware import InMemoryRateLimitMiddleware, RequestSizeLimitMiddleware
from continuum.rag import ingest as rag_ingest
from continuum.rag.answer import answer_question_with_settings

logger = get_logger("connector")

API_TITLE = "Continuum Connector"
API_VERSION = "0.1.0"

DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 500

# The runtime heartbeats every 5 seconds; three missed beats means it is
# no longer running, even if it never got to write "stopped".
RUNTIME_STALE_AFTER_SECONDS = 15.0

DEFAULT_MODEL_DIR = REPO_ROOT / "data" / "models"
DEFAULT_BASELINE_DIR = REPO_ROOT / "data" / "baselines"
DEFAULT_EVAL_RESULTS_PATH = REPO_ROOT / "docs" / "eval_results.md"


# --- request/response models ---------------------------------------------


class IncidentCreateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    status: Literal["created", "already_exists"]


class IncidentListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[IncidentRecord]
    total: int
    limit: int
    offset: int


class UnblockResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["queued"]
    device_id: str


class LiveSnapshotResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    verdict: str
    anomaly_score: float
    threshold: float
    features: dict[str, float]
    updated_at: str


class StatsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_incidents: int
    mean_anomaly_score: float | None
    mean_time_to_detect_ms: float | None
    counts_by_attack_pattern: dict[str, int]
    counts_by_day: list[dict[str, object]]


class QueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    question: str = Field(min_length=1, max_length=2000)


class QueryCitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    doc_id: str
    title: str
    snippet: str
    score: float


class QueryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str | None
    confidence: float
    citations: list[QueryCitation]
    abstained: bool
    message: str
    # Which provider and model wrote the answer (for example
    # "Groq (cloud API), qwen/qwen3.8-27b"); None when no LLM was called.
    generated_by: str | None = None


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"]


class RuntimeDevice(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    name: str
    vendor_id: str
    product_id: str
    bus_type: str
    is_usb: bool
    disabled: bool
    # Blocked by Continuum because Windows refused to disable it.
    quarantined: bool = False


class RuntimeStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    running: bool
    state: Literal["running", "stopped", "never_started"]
    started_at: str | None = None
    last_heartbeat: str | None = None
    seconds_since_heartbeat: float | None = None
    pid: int | None = None
    elevated: bool | None = None
    configured_mode: str | None = None
    effective_mode: str | None = None
    dry_run: bool | None = None
    model_version: str | None = None
    calibrated_threshold: float | None = None
    threshold: float | None = None
    sensitivity: int | None = None
    devices: list[RuntimeDevice] = Field(default_factory=list)


class CalibrationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    configured_sensitivity: int
    models: list[dict[str, object]]
    baselines: list[dict[str, object]]
    eval_results_markdown: str | None


class SettingsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    settings: settings_store.EditableSettings
    env_overridden_fields: list[str]
    applies_on: Literal["runtime_restart"] = "runtime_restart"


class TrainingStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    paragraph_index: int = Field(default=0, ge=0, le=1000)


class BaselineSessionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    state: str
    paragraph_index: int
    device_id: str | None
    presses: int
    windows_saved: int
    message: str
    created_at: str
    updated_at: str


class TrainingStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    runtime_running: bool
    session: BaselineSessionResponse | None
    saved_sessions: int
    baseline: dict[str, object]
    model: dict[str, object]
    minimum_windows: int
    recommended_windows: int


# --- app factory ---------------------------------------------------------


def _runtime_running(row: db.RuntimeStatusRow | None) -> bool:
    """Running, and heard from recently enough to trust it."""
    if row is None or row.state != "running":
        return False
    age_seconds = (datetime.now(UTC) - datetime.fromisoformat(row.heartbeat_at)).total_seconds()
    return age_seconds <= RUNTIME_STALE_AFTER_SECONDS


def _session_response(row: db.BaselineSessionRow | None) -> BaselineSessionResponse | None:
    if row is None:
        return None
    return BaselineSessionResponse(
        id=row.id,
        state=row.state,
        paragraph_index=row.paragraph_index,
        device_id=row.device_id,
        presses=row.presses,
        windows_saved=row.windows_saved,
        message=row.message,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def create_app(
    settings: Settings | None = None,
    *,
    local_override_path: Path = LOCAL_OVERRIDE_PATH,
    model_dir: Path = DEFAULT_MODEL_DIR,
    baseline_dir: Path = DEFAULT_BASELINE_DIR,
    eval_results_path: Path = DEFAULT_EVAL_RESULTS_PATH,
    user: str | None = None,
) -> FastAPI:
    resolved_settings = settings if settings is not None else get_settings()
    # Whose baseline and model the Train page manages: the Windows user, the
    # same name the runtime uses to find its model.
    training_user = user or getpass.getuser()
    database_path = db.resolve_database_path(resolved_settings)
    engine = db.create_db_engine(database_path)
    session_factory = db.make_session_factory(engine)

    # Cheap: just opens/creates the persistent Chroma client and
    # collection. The heavy sentence-transformers model is loaded lazily,
    # on first embedding call, not here.
    chroma_path = rag_ingest.resolve_chroma_path(resolved_settings)
    rag_collection = rag_ingest.get_chroma_collection(
        chroma_path, resolved_settings.rag.chroma_collection
    )

    def get_db() -> Generator[Session, None, None]:
        yield from db.session_scope(session_factory)

    corpus_path = rag_ingest.resolve_corpus_path(resolved_settings)

    def _rag_background_worker(stop_event: threading.Event) -> None:
        try:
            rag_ingest.ingest_corpus_directory(
                corpus_path,
                rag_collection,
                chunk_size_tokens=resolved_settings.rag.chunk_size_tokens,
                overlap_tokens=resolved_settings.rag.chunk_overlap_tokens,
            )
        except Exception:
            logger.exception("playbook corpus ingestion failed; incident API still serving")
        while not stop_event.is_set():
            try:
                rag_ingest.watch_ingest_queue(database_path, rag_collection, stop_event=stop_event)
            except Exception:
                logger.exception("RAG ingest watcher failed; retrying")
                stop_event.wait(timeout=5.0)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        stop_event = threading.Event()
        worker = threading.Thread(
            target=_rag_background_worker, args=(stop_event,), name="rag-ingest", daemon=True
        )
        worker.start()
        try:
            yield
        finally:
            stop_event.set()
            worker.join(timeout=5.0)

    app = FastAPI(title=API_TITLE, version=API_VERSION, lifespan=lifespan)
    app.add_middleware(InMemoryRateLimitMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware)

    # Exposed for tests (and any future admin/debug tooling) to inspect
    # or query the database directly; routes below use the get_db
    # dependency, never this, for request handling.
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.rag_collection = rag_collection

    require_bearer_token = make_bearer_token_dependency(resolved_settings)
    auth = Depends(require_bearer_token)

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @app.post(
        "/incidents",
        response_model=IncidentCreateResponse,
        status_code=status.HTTP_201_CREATED,
        dependencies=[auth],
    )
    def create_incident(
        incident: IncidentRecord, session: Session = Depends(get_db)
    ) -> IncidentCreateResponse:
        incident_id = str(incident.incident_id)

        existing = db.get_incident_by_incident_id(session, incident_id)
        if existing is not None:
            return IncidentCreateResponse(incident_id=incident_id, status="already_exists")

        # Defense in depth: re-sanitise server-side even though
        # IncidentRecord's own validator already did this on construction.
        clean_notes = sanitise_notes(incident.notes)
        suspicious = detect_suspicious_notes(clean_notes)
        if suspicious:
            logger.warning("incident %s has suspicious notes content", incident_id)

        raw_json = incident.model_dump_json()

        db.insert_incident(
            session,
            incident_id=incident_id,
            detected_at=incident.detected_at.isoformat(),
            device_id=incident.device.device_id,
            device_name=incident.device.name,
            verdict=incident.verdict,
            attack_pattern=incident.attack_pattern.value,
            anomaly_score=incident.anomaly_score,
            threshold=incident.threshold,
            action_taken=incident.action_taken.value,
            time_to_detect_ms=incident.time_to_detect_ms,
            notes=clean_notes,
            suspicious_notes=suspicious,
            raw_json=raw_json,
        )

        document_text = render_incident_document(incident)
        db.enqueue_rag_document(session, incident_id=incident_id, document_text=document_text)

        return IncidentCreateResponse(incident_id=incident_id, status="created")

    @app.get("/incidents", response_model=IncidentListResponse, dependencies=[auth])
    def list_incidents_route(
        start_time: datetime | None = Query(default=None),
        end_time: datetime | None = Query(default=None),
        device_id: str | None = Query(default=None),
        verdict: Verdict | None = Query(default=None),
        attack_pattern: AttackPattern | None = Query(default=None),
        limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
        offset: int = Query(default=0, ge=0),
        session: Session = Depends(get_db),
    ) -> IncidentListResponse:
        rows, total = db.list_incidents(
            session,
            start_time=start_time.isoformat() if start_time else None,
            end_time=end_time.isoformat() if end_time else None,
            device_id=device_id,
            verdict=verdict,
            attack_pattern=attack_pattern.value if attack_pattern else None,
            limit=limit,
            offset=offset,
        )
        items = [IncidentRecord.model_validate_json(row.raw_json) for row in rows]
        return IncidentListResponse(items=items, total=total, limit=limit, offset=offset)

    @app.get("/incidents/{incident_id}", response_model=IncidentRecord, dependencies=[auth])
    def get_incident_route(incident_id: str, session: Session = Depends(get_db)) -> IncidentRecord:
        row = db.get_incident_by_incident_id(session, incident_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
        return IncidentRecord.model_validate_json(row.raw_json)

    @app.post(
        "/devices/{device_id}/unblock",
        response_model=UnblockResponse,
        dependencies=[auth],
    )
    def unblock_device(device_id: str, session: Session = Depends(get_db)) -> UnblockResponse:
        db.insert_command(session, command_type="unblock", device_id=device_id)
        logger.info("queued unblock command for %s", device_id)
        return UnblockResponse(status="queued", device_id=device_id)

    @app.get("/live", response_model=list[LiveSnapshotResponse], dependencies=[auth])
    def live_snapshot(session: Session = Depends(get_db)) -> list[LiveSnapshotResponse]:
        rows = db.get_live_snapshots(session)
        return [
            LiveSnapshotResponse(
                device_id=row.device_id,
                verdict=row.verdict,
                anomaly_score=row.anomaly_score,
                threshold=row.threshold,
                features=json.loads(row.features_json),
                updated_at=row.updated_at,
            )
            for row in rows
        ]

    @app.get("/stats", response_model=StatsResponse, dependencies=[auth])
    def stats(session: Session = Depends(get_db)) -> StatsResponse:
        return StatsResponse(**db.compute_stats(session))

    @app.post("/query", response_model=QueryResponse, dependencies=[auth])
    def query(request: QueryRequest) -> QueryResponse:
        result = answer_question_with_settings(
            request.question, rag_collection, resolved_settings
        )
        return QueryResponse(
            generated_by=result.generated_by,
            answer=result.answer,
            confidence=result.confidence,
            citations=[
                QueryCitation(
                    doc_id=c.doc_id, title=c.title, snippet=c.snippet, score=c.score
                )
                for c in result.citations
            ],
            abstained=result.abstained,
            message=result.message or "",
        )

    @app.get("/runtime", response_model=RuntimeStatusResponse, dependencies=[auth])
    def runtime_status(session: Session = Depends(get_db)) -> RuntimeStatusResponse:
        row = db.get_runtime_status(session)
        if row is None:
            return RuntimeStatusResponse(running=False, state="never_started")

        heartbeat = datetime.fromisoformat(row.heartbeat_at)
        age_seconds = (datetime.now(UTC) - heartbeat).total_seconds()
        running = _runtime_running(row)
        return RuntimeStatusResponse(
            running=running,
            state="running" if running else "stopped",
            started_at=row.started_at,
            last_heartbeat=row.heartbeat_at,
            seconds_since_heartbeat=round(age_seconds, 1),
            pid=row.pid,
            elevated=row.elevated,
            configured_mode=row.configured_mode,
            effective_mode=row.effective_mode,
            dry_run=row.dry_run,
            model_version=row.model_version,
            calibrated_threshold=row.calibrated_threshold,
            threshold=row.base_threshold,
            sensitivity=row.sensitivity,
            devices=[RuntimeDevice(**device) for device in json.loads(row.devices_json or "[]")],
        )

    @app.get("/calibration", response_model=CalibrationResponse, dependencies=[auth])
    def calibration_summary() -> CalibrationResponse:
        sensitivity = settings_store.read_editable(local_override_path).sensitivity
        return CalibrationResponse(
            configured_sensitivity=sensitivity,
            models=calibration.describe_models(model_dir, sensitivity=sensitivity),
            baselines=calibration.describe_baselines(baseline_dir),
            eval_results_markdown=calibration.read_eval_results(eval_results_path),
        )

    @app.get("/settings", response_model=SettingsResponse, dependencies=[auth])
    def get_editable_settings() -> SettingsResponse:
        return SettingsResponse(
            settings=settings_store.read_editable(local_override_path),
            env_overridden_fields=settings_store.env_overridden_fields(),
        )

    @app.put("/settings", response_model=SettingsResponse, dependencies=[auth])
    def put_editable_settings(new: settings_store.EditableSettings) -> SettingsResponse:
        try:
            saved = settings_store.write_editable(local_override_path, new)
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)
            ) from error
        logger.info(
            "settings saved: sensitivity=%d mode=%s dry_run=%s allowlist=%d entries",
            saved.sensitivity,
            saved.response_mode,
            saved.dry_run,
            len(saved.allowlist),
        )
        return SettingsResponse(
            settings=saved, env_overridden_fields=settings_store.env_overridden_fields()
        )

    # --- Train page: record a baseline through the runtime, then train ---------

    def training_status(session: Session) -> TrainingStatusResponse:
        return TrainingStatusResponse(
            runtime_running=_runtime_running(db.get_runtime_status(session)),
            session=_session_response(db.latest_baseline_session(session)),
            saved_sessions=db.count_saved_baseline_sessions(session),
            baseline=training.baseline_summary(baseline_dir, training_user),
            model=training.model_summary(model_dir, training_user),
            minimum_windows=training.MIN_TRAIN_WINDOWS,
            recommended_windows=training.RECOMMENDED_WINDOWS,
        )

    def active_session(session: Session) -> db.BaselineSessionRow | None:
        latest = db.latest_baseline_session(session)
        return latest if latest and latest.state in db.ACTIVE_SESSION_STATES else None

    @app.get("/training", response_model=TrainingStatusResponse, dependencies=[auth])
    def get_training(session: Session = Depends(get_db)) -> TrainingStatusResponse:
        return training_status(session)

    @app.post("/training/start", response_model=TrainingStatusResponse, dependencies=[auth])
    def start_training(
        request: TrainingStartRequest, session: Session = Depends(get_db)
    ) -> TrainingStatusResponse:
        if active_session(session) is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A recording session is already in progress. Stop it first.",
            )
        row = db.create_baseline_session(session, paragraph_index=request.paragraph_index)
        logger.info("baseline session %d requested", row.id)
        return training_status(session)

    @app.post("/training/stop", response_model=TrainingStatusResponse, dependencies=[auth])
    def stop_training(session: Session = Depends(get_db)) -> TrainingStatusResponse:
        row = active_session(session)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="No recording session is in progress."
            )
        if row.state == db.SESSION_REQUESTED:
            # The runtime never picked it up; it ignores the start command now.
            row.state = db.SESSION_CANCELLED
            row.message = "Cancelled before recording started."
            row.updated_at = datetime.now(UTC).isoformat()
        else:
            db.insert_command(
                session, command_type=db.COMMAND_BASELINE_STOP, device_id=str(row.id)
            )
        session.flush()
        return training_status(session)

    @app.post("/training/train", response_model=TrainingStatusResponse, dependencies=[auth])
    def train(session: Session = Depends(get_db)) -> TrainingStatusResponse:
        if active_session(session) is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Stop the recording session before training.",
            )
        try:
            summary = training.train_model(baseline_dir, model_dir, training_user)
        except training.TrainingError as error:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
        logger.info("trained model %s for %s", summary["version"], training_user)
        return training_status(session)

    @app.delete("/training/baseline", response_model=TrainingStatusResponse, dependencies=[auth])
    def reset_training(session: Session = Depends(get_db)) -> TrainingStatusResponse:
        if active_session(session) is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Stop the recording session before starting over.",
            )
        training.reset_baseline(baseline_dir, training_user)
        logger.info("baseline reset for %s", training_user)
        return training_status(session)

    return app


app = create_app()
