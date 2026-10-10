"""Tests for continuum.connector.db, independent of the HTTP layer."""

from __future__ import annotations

import contextlib
from pathlib import Path

from continuum.common.config import get_settings
from continuum.connector import db


def _make_engine_and_session(tmp_path):
    engine = db.create_db_engine(tmp_path / "test.sqlite3")
    session_factory = db.make_session_factory(engine)
    return session_factory()


def test_resolve_database_path_resolves_relative_paths_against_repo_root():
    settings = get_settings()
    resolved = db.resolve_database_path(settings)

    assert resolved.is_absolute()
    assert resolved.name == settings.connector.database_path.name


def test_resolve_database_path_leaves_absolute_paths_alone(tmp_path):
    settings = get_settings()
    absolute_settings = settings.model_copy(
        update={
            "connector": settings.connector.model_copy(
                update={"database_path": tmp_path / "already_absolute.sqlite3"}
            )
        }
    )

    resolved = db.resolve_database_path(absolute_settings)

    assert resolved == tmp_path / "already_absolute.sqlite3"


def test_create_db_engine_creates_all_tables(tmp_path):
    db_path = tmp_path / "test.sqlite3"
    db.create_db_engine(db_path)

    assert db_path.exists()


def test_insert_and_get_incident_roundtrip(tmp_path):
    session = _make_engine_and_session(tmp_path)
    try:
        inserted = db.insert_incident(
            session,
            incident_id="abc-123",
            detected_at="2026-01-01T00:00:00+00:00",
            device_id="dev-1",
            device_name="Test Keyboard",
            verdict="blocked",
            attack_pattern="burst_injection",
            anomaly_score=2.0,
            threshold=1.0,
            action_taken="locked_and_disabled",
            time_to_detect_ms=100,
            notes="",
            suspicious_notes=False,
            raw_json="{}",
        )
        session.commit()

        fetched = db.get_incident_by_incident_id(session, "abc-123")

        assert fetched is not None
        assert fetched.id == inserted.id
        assert fetched.device_id == "dev-1"
    finally:
        session.close()


def test_get_incident_by_incident_id_returns_none_when_missing(tmp_path):
    session = _make_engine_and_session(tmp_path)
    try:
        assert db.get_incident_by_incident_id(session, "does-not-exist") is None
    finally:
        session.close()


def test_list_incidents_applies_filters_and_pagination(tmp_path):
    session = _make_engine_and_session(tmp_path)
    try:
        for i in range(5):
            db.insert_incident(
                session,
                incident_id=f"id-{i}",
                detected_at=f"2026-01-0{i + 1}T00:00:00+00:00",
                device_id="dev-a" if i % 2 == 0 else "dev-b",
                device_name="Test Keyboard",
                verdict="blocked",
                attack_pattern="burst_injection",
                anomaly_score=float(i),
                threshold=1.0,
                action_taken="locked_and_disabled",
                time_to_detect_ms=100,
                notes="",
                suspicious_notes=False,
                raw_json="{}",
            )
        session.commit()

        dev_a_rows, dev_a_total = db.list_incidents(session, device_id="dev-a")
        assert dev_a_total == 3
        assert all(row.device_id == "dev-a" for row in dev_a_rows)

        page_rows, total = db.list_incidents(session, limit=2, offset=1)
        assert total == 5
        assert len(page_rows) == 2
    finally:
        session.close()


def test_enqueue_rag_document_is_queryable(tmp_path):
    session = _make_engine_and_session(tmp_path)
    try:
        db.enqueue_rag_document(session, incident_id="abc-123", document_text="Incident abc-123\n")
        session.commit()

        rows = session.execute(db.select(db.RagIngestQueueRow)).scalars().all()
        assert len(rows) == 1
        assert rows[0].status == "pending"
        assert rows[0].incident_id == "abc-123"
    finally:
        session.close()


def test_insert_command_defaults_to_pending(tmp_path):
    session = _make_engine_and_session(tmp_path)
    try:
        row = db.insert_command(session, command_type="unblock", device_id="dev-1")
        session.commit()

        assert row.status == "pending"
        assert row.completed_at is None
    finally:
        session.close()


def test_get_live_snapshots_returns_all_devices(tmp_path):
    session = _make_engine_and_session(tmp_path)
    try:
        session.execute(
            db.LiveSnapshotRow.__table__.insert(),
            [
                {
                    "device_id": "dev-a",
                    "verdict": "normal",
                    "anomaly_score": 0.1,
                    "threshold": 1.0,
                    "features_json": "{}",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                },
                {
                    "device_id": "dev-b",
                    "verdict": "suspicious",
                    "anomaly_score": 1.5,
                    "threshold": 1.0,
                    "features_json": "{}",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                },
            ],
        )
        session.commit()

        snapshots = db.get_live_snapshots(session)

        assert {row.device_id for row in snapshots} == {"dev-a", "dev-b"}
    finally:
        session.close()


def test_compute_stats_on_an_empty_database_does_not_error(tmp_path):
    session = _make_engine_and_session(tmp_path)
    try:
        stats = db.compute_stats(session)

        assert stats["total_incidents"] == 0
        assert stats["mean_anomaly_score"] is None
        assert stats["counts_by_attack_pattern"] == {}
        assert stats["counts_by_day"] == []
    finally:
        session.close()


def test_compute_stats_aggregates_correctly(tmp_path):
    session = _make_engine_and_session(tmp_path)
    try:
        db.insert_incident(
            session,
            incident_id="a",
            detected_at="2026-01-01T00:00:00+00:00",
            device_id="dev-1",
            device_name="Test Keyboard",
            verdict="blocked",
            attack_pattern="burst_injection",
            anomaly_score=2.0,
            threshold=1.0,
            action_taken="locked_and_disabled",
            time_to_detect_ms=100,
            notes="",
            suspicious_notes=False,
            raw_json="{}",
        )
        db.insert_incident(
            session,
            incident_id="b",
            detected_at="2026-01-01T12:00:00+00:00",
            device_id="dev-2",
            device_name="Test Keyboard",
            verdict="blocked",
            attack_pattern="slowed_injection",
            anomaly_score=4.0,
            threshold=1.0,
            action_taken="locked_and_disabled",
            time_to_detect_ms=300,
            notes="",
            suspicious_notes=False,
            raw_json="{}",
        )
        session.commit()

        stats = db.compute_stats(session)

        assert stats["total_incidents"] == 2
        assert stats["mean_anomaly_score"] == 3.0
        assert stats["mean_time_to_detect_ms"] == 200.0
        assert stats["counts_by_attack_pattern"] == {"burst_injection": 1, "slowed_injection": 1}
        assert stats["counts_by_day"] == [{"date": "2026-01-01", "count": 2}]
    finally:
        session.close()


def test_session_scope_commits_on_success(tmp_path):
    engine = db.create_db_engine(tmp_path / "test.sqlite3")
    session_factory = db.make_session_factory(engine)

    generator = db.session_scope(session_factory)
    session = next(generator)
    db.insert_command(session, command_type="unblock", device_id="dev-1")
    with contextlib.suppress(StopIteration):
        next(generator)

    verify_session = session_factory()
    try:
        rows = verify_session.execute(db.select(db.CommandRow)).scalars().all()
        assert len(rows) == 1
    finally:
        verify_session.close()


def test_session_scope_rolls_back_on_error(tmp_path):
    engine = db.create_db_engine(tmp_path / "test.sqlite3")
    session_factory = db.make_session_factory(engine)

    generator = db.session_scope(session_factory)
    session = next(generator)
    db.insert_command(session, command_type="unblock", device_id="dev-1")
    with contextlib.suppress(RuntimeError):
        generator.throw(RuntimeError("boom"))

    verify_session = session_factory()
    try:
        rows = verify_session.execute(db.select(db.CommandRow)).scalars().all()
        assert len(rows) == 0
    finally:
        verify_session.close()


def test_repo_root_is_a_real_directory():
    assert db.REPO_ROOT.exists()
    assert isinstance(db.REPO_ROOT, Path)
