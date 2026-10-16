"""SQLAlchemy models and session management for the connector's database.

Responsibility: define the tables backing the connector API, and the
two tables it shares directly, file-level, with the elevated runtime
process, so device-unblock commands and live per-device status do not
need their own separate HTTP round trip on top of incident posting.

Shared-file contract with continuum.runtime (see that module):
    commands        this module's POST /devices/{id}/unblock INSERTs a
                     row here; continuum.runtime polls it with plain
                     sqlite3 (not SQLAlchemy, to avoid a runtime ->
                     connector import of the whole web stack), calls
                     DeviceBlocker.enable(device_id) for each pending
                     row, and marks it "done".
    live_snapshots   continuum.runtime UPSERTs one row per device here
                     after every scored window; GET /live just reads
                     it back. Primary key is device_id, so there is
                     always exactly one row per device: the latest.
    runtime_status   continuum.runtime UPSERTs a single row (id 1) at
                     startup, on every maintenance tick (its heartbeat)
                     and on shutdown: elevation, response mode, model,
                     threshold and the attached keyboards. GET /runtime
                     reads it back.
    baseline_sessions
                     one row per typing-baseline recording session from
                     the dashboard's Train page. POST /training/start
                     inserts it ("requested") plus a baseline_start
                     command; continuum.runtime records the session's
                     key timings (never key identity) through Raw
                     Input, keeps "presses" current while recording,
                     and on baseline_stop saves the windows to the
                     baseline file and marks the row "saved" or
                     "failed" with a message.
    remote_status    a single row (id 1) about remote-access typing.
                     continuum.runtime UPSERTs which configured
                     remote-access tools are running and its last
                     detection; POST /remote/allow and DELETE
                     /remote/allow write allowed_until, which the
                     runtime reads before reacting to remote typing.

These tables are created here with SQLAlchemy and written there with
raw sqlite3 against the exact same column names; if this schema
changes, continuum.runtime's queries must change with it.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Boolean, Engine, Float, Integer, String, Text, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from continuum.common.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[3]

COMMANDS_TABLE = "commands"
LIVE_SNAPSHOTS_TABLE = "live_snapshots"
RUNTIME_STATUS_TABLE = "runtime_status"
RUNTIME_STATUS_ROW_ID = 1
BASELINE_SESSIONS_TABLE = "baseline_sessions"
REMOTE_STATUS_TABLE = "remote_status"
REMOTE_STATUS_ROW_ID = 1

COMMAND_UNBLOCK = "unblock"
COMMAND_BASELINE_START = "baseline_start"
COMMAND_BASELINE_STOP = "baseline_stop"

SESSION_REQUESTED = "requested"
SESSION_RECORDING = "recording"
SESSION_SAVED = "saved"
SESSION_FAILED = "failed"
SESSION_CANCELLED = "cancelled"
ACTIVE_SESSION_STATES = (SESSION_REQUESTED, SESSION_RECORDING)


class Base(DeclarativeBase):
    pass


class IncidentRow(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    detected_at: Mapped[str] = mapped_column(String(64), index=True)
    device_id: Mapped[str] = mapped_column(String(256), index=True)
    device_name: Mapped[str] = mapped_column(String(256))
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    attack_pattern: Mapped[str] = mapped_column(String(32), index=True)
    anomaly_score: Mapped[float] = mapped_column(Float)
    threshold: Mapped[float] = mapped_column(Float)
    action_taken: Mapped[str] = mapped_column(String(32))
    time_to_detect_ms: Mapped[int] = mapped_column(Integer)
    notes: Mapped[str] = mapped_column(String(280), default="")
    suspicious_notes: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(64))


class RagIngestQueueRow(Base):
    __tablename__ = "rag_ingest_queue"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(36), index=True)
    document_text: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    created_at: Mapped[str] = mapped_column(String(64))


class CommandRow(Base):
    __tablename__ = COMMANDS_TABLE

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    command_type: Mapped[str] = mapped_column(String(32))
    device_id: Mapped[str] = mapped_column(String(256), index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    created_at: Mapped[str] = mapped_column(String(64))
    completed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)


class LiveSnapshotRow(Base):
    __tablename__ = LIVE_SNAPSHOTS_TABLE

    device_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(32))
    anomaly_score: Mapped[float] = mapped_column(Float)
    threshold: Mapped[float] = mapped_column(Float)
    features_json: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[str] = mapped_column(String(64))


class BaselineSessionRow(Base):
    __tablename__ = BASELINE_SESSIONS_TABLE

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    state: Mapped[str] = mapped_column(String(16), index=True)
    paragraph_index: Mapped[int] = mapped_column(Integer, default=0)
    device_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    presses: Mapped[int] = mapped_column(Integer, default=0)
    windows_saved: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[str] = mapped_column(String(64))


class RuntimeStatusRow(Base):
    __tablename__ = RUNTIME_STATUS_TABLE

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    state: Mapped[str] = mapped_column(String(16))
    started_at: Mapped[str] = mapped_column(String(64))
    heartbeat_at: Mapped[str] = mapped_column(String(64))
    pid: Mapped[int] = mapped_column(Integer)
    elevated: Mapped[bool] = mapped_column(Boolean)
    configured_mode: Mapped[str] = mapped_column(String(32))
    effective_mode: Mapped[str] = mapped_column(String(32))
    dry_run: Mapped[bool] = mapped_column(Boolean)
    model_version: Mapped[str] = mapped_column(String(64))
    calibrated_threshold: Mapped[float] = mapped_column(Float)
    base_threshold: Mapped[float] = mapped_column(Float)
    sensitivity: Mapped[int] = mapped_column(Integer)
    devices_json: Mapped[str] = mapped_column(Text, default="[]")


class RemoteStatusRow(Base):
    __tablename__ = REMOTE_STATUS_TABLE

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    allowed_until: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tools_running_json: Mapped[str] = mapped_column(Text, default="[]")
    last_detected_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_action: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_tools_json: Mapped[str] = mapped_column(Text, default="[]")
    updated_at: Mapped[str] = mapped_column(String(64))


def resolve_database_path(settings: Settings) -> Path:
    """Where the connector's SQLite file lives, resolved against the repo root."""
    path = settings.connector.database_path
    return path if path.is_absolute() else REPO_ROOT / path


def create_db_engine(database_path: Path) -> Engine:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


def session_scope(session_factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    """A request-scoped session: commit on success, roll back on error."""
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# --- incidents ----------------------------------------------------------------


def get_incident_by_incident_id(session: Session, incident_id: str) -> IncidentRow | None:
    stmt = select(IncidentRow).where(IncidentRow.incident_id == incident_id)
    return session.execute(stmt).scalar_one_or_none()


def insert_incident(
    session: Session,
    *,
    incident_id: str,
    detected_at: str,
    device_id: str,
    device_name: str,
    verdict: str,
    attack_pattern: str,
    anomaly_score: float,
    threshold: float,
    action_taken: str,
    time_to_detect_ms: int,
    notes: str,
    suspicious_notes: bool,
    raw_json: str,
) -> IncidentRow:
    row = IncidentRow(
        incident_id=incident_id,
        detected_at=detected_at,
        device_id=device_id,
        device_name=device_name,
        verdict=verdict,
        attack_pattern=attack_pattern,
        anomaly_score=anomaly_score,
        threshold=threshold,
        action_taken=action_taken,
        time_to_detect_ms=time_to_detect_ms,
        notes=notes,
        suspicious_notes=suspicious_notes,
        raw_json=raw_json,
        created_at=datetime.now(UTC).isoformat(),
    )
    session.add(row)
    session.flush()
    return row


def enqueue_rag_document(session: Session, *, incident_id: str, document_text: str) -> None:
    session.add(
        RagIngestQueueRow(
            incident_id=incident_id,
            document_text=document_text,
            status="pending",
            created_at=datetime.now(UTC).isoformat(),
        )
    )


def list_incidents(
    session: Session,
    *,
    start_time: str | None = None,
    end_time: str | None = None,
    device_id: str | None = None,
    verdict: str | None = None,
    attack_pattern: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[IncidentRow], int]:
    filters = []
    if start_time is not None:
        filters.append(IncidentRow.detected_at >= start_time)
    if end_time is not None:
        filters.append(IncidentRow.detected_at <= end_time)
    if device_id is not None:
        filters.append(IncidentRow.device_id == device_id)
    if verdict is not None:
        filters.append(IncidentRow.verdict == verdict)
    if attack_pattern is not None:
        filters.append(IncidentRow.attack_pattern == attack_pattern)

    count_stmt = select(func.count()).select_from(IncidentRow)
    stmt = select(IncidentRow)
    for condition in filters:
        count_stmt = count_stmt.where(condition)
        stmt = stmt.where(condition)

    total = session.execute(count_stmt).scalar_one()
    stmt = stmt.order_by(IncidentRow.detected_at.desc()).limit(limit).offset(offset)
    rows = list(session.execute(stmt).scalars().all())
    return rows, total


# --- commands (shared with continuum.runtime) --------------------------------


def insert_command(session: Session, *, command_type: str, device_id: str) -> CommandRow:
    row = CommandRow(
        command_type=command_type,
        device_id=device_id,
        status="pending",
        created_at=datetime.now(UTC).isoformat(),
    )
    session.add(row)
    session.flush()
    return row


# --- live snapshots (shared with continuum.runtime) ---------------------------


def get_live_snapshots(session: Session) -> list[LiveSnapshotRow]:
    stmt = select(LiveSnapshotRow).order_by(LiveSnapshotRow.device_id)
    return list(session.execute(stmt).scalars().all())


# --- runtime status (shared with continuum.runtime) ---------------------------


def get_runtime_status(session: Session) -> RuntimeStatusRow | None:
    return session.get(RuntimeStatusRow, RUNTIME_STATUS_ROW_ID)


# --- remote-access status (shared with continuum.runtime) ---------------------


def get_remote_status(session: Session) -> RemoteStatusRow | None:
    return session.get(RemoteStatusRow, REMOTE_STATUS_ROW_ID)


def set_remote_allowance(session: Session, allowed_until: datetime | None) -> RemoteStatusRow:
    """Let remote typing through until the given time, or stop allowing it (None)."""
    now = datetime.now(UTC).isoformat()
    row = get_remote_status(session)
    if row is None:
        row = RemoteStatusRow(id=REMOTE_STATUS_ROW_ID, updated_at=now)
        session.add(row)
    row.allowed_until = allowed_until.astimezone(UTC).isoformat() if allowed_until else None
    session.commit()
    session.refresh(row)
    return row


# --- baseline recording sessions (shared with continuum.runtime) --------------


def latest_baseline_session(session: Session) -> BaselineSessionRow | None:
    stmt = select(BaselineSessionRow).order_by(BaselineSessionRow.id.desc()).limit(1)
    return session.execute(stmt).scalar_one_or_none()


def count_saved_baseline_sessions(session: Session) -> int:
    stmt = select(func.count()).select_from(BaselineSessionRow).where(
        BaselineSessionRow.state == SESSION_SAVED
    )
    return session.execute(stmt).scalar_one()


def create_baseline_session(session: Session, *, paragraph_index: int) -> BaselineSessionRow:
    now = datetime.now(UTC).isoformat()
    row = BaselineSessionRow(
        state=SESSION_REQUESTED,
        paragraph_index=paragraph_index,
        presses=0,
        windows_saved=0,
        message="",
        created_at=now,
        updated_at=now,
    )
    session.add(row)
    session.flush()
    insert_command(session, command_type=COMMAND_BASELINE_START, device_id=str(row.id))
    return row


# --- stats ----------------------------------------------------------------


def compute_stats(session: Session) -> dict[str, object]:
    total = session.execute(select(func.count()).select_from(IncidentRow)).scalar_one()
    mean_score = session.execute(select(func.avg(IncidentRow.anomaly_score))).scalar_one()
    mean_ttd = session.execute(select(func.avg(IncidentRow.time_to_detect_ms))).scalar_one()

    by_pattern_rows = session.execute(
        select(IncidentRow.attack_pattern, func.count()).group_by(IncidentRow.attack_pattern)
    ).all()
    counts_by_attack_pattern = dict(by_pattern_rows)

    day_expr = func.substr(IncidentRow.detected_at, 1, 10)
    by_day_rows = session.execute(
        select(day_expr, func.count()).group_by(day_expr).order_by(day_expr)
    ).all()
    counts_by_day = [{"date": day, "count": count} for day, count in by_day_rows]

    return {
        "total_incidents": total,
        "mean_anomaly_score": mean_score,
        "mean_time_to_detect_ms": mean_ttd,
        "counts_by_attack_pattern": counts_by_attack_pattern,
        "counts_by_day": counts_by_day,
    }
