"""Tests for continuum.rag.ingest."""

from __future__ import annotations

import sqlite3

from continuum.rag import ingest

VALID_INCIDENT_DOCUMENT = """Incident abc-123
Detected at: 2026-01-01T00:00:00+00:00
Device: Test Keyboard (dev-1, USB, vendor 046D product C52B)
Verdict: blocked
Attack pattern: burst_injection
Anomaly score: 2.500 (threshold 1.000)
Action taken: locked_and_disabled
Time to detect: 450 ms
MITRE technique: T1200
Recommended followups: none
Notes:
"""


def _collection(tmp_path, name="test_collection"):
    return ingest.get_chroma_collection(tmp_path / "chroma", name)


# --- chunk_text -----------------------------------------------------------


def test_chunk_text_returns_one_chunk_for_short_text():
    chunks = ingest.chunk_text("one two three", chunk_size_tokens=10, overlap_tokens=2)
    assert chunks == ["one two three"]


def test_chunk_text_splits_long_text_with_overlap():
    words = [f"w{i}" for i in range(25)]
    text = " ".join(words)

    chunks = ingest.chunk_text(text, chunk_size_tokens=10, overlap_tokens=3)

    assert len(chunks) > 1
    # The overlap region is shared between consecutive chunks.
    first_words = chunks[0].split()
    second_words = chunks[1].split()
    assert first_words[-3:] == second_words[:3]


def test_chunk_text_handles_empty_text():
    assert ingest.chunk_text("") == []


# --- is_valid_incident_document --------------------------------------------


def test_is_valid_incident_document_accepts_the_fixed_template():
    assert ingest.is_valid_incident_document(VALID_INCIDENT_DOCUMENT) is True


def test_is_valid_incident_document_rejects_raw_text():
    assert ingest.is_valid_incident_document("just some free text, not a template") is False


def test_is_valid_incident_document_rejects_wrong_field_order():
    scrambled = "Verdict: blocked\nIncident abc-123\n"
    assert ingest.is_valid_incident_document(scrambled) is False


def test_is_valid_incident_document_rejects_non_string_input():
    assert ingest.is_valid_incident_document(None) is False  # type: ignore[arg-type]


# --- ingest_incident_document -----------------------------------------------


def test_ingest_incident_document_rejects_non_template_text(tmp_path, fake_embeddings):
    collection = _collection(tmp_path)

    try:
        ingest.ingest_incident_document("abc-123", "not the template", collection)
        raised = False
    except ValueError:
        raised = True

    assert raised is True
    assert collection.count() == 0


def test_ingest_incident_document_adds_chunks(tmp_path, fake_embeddings):
    collection = _collection(tmp_path)

    count = ingest.ingest_incident_document("abc-123", VALID_INCIDENT_DOCUMENT, collection)

    assert count >= 1
    assert collection.count() == count
    result = collection.get(where={"doc_id": "abc-123"})
    assert result["metadatas"][0]["source_type"] == "incident"


# --- playbook ingestion and content-hash skip/re-ingest --------------------


def test_ingest_corpus_directory_ingests_markdown_files(tmp_path, fake_embeddings):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "playbook_a.md").write_text(
        "# Playbook A\n\nSome guidance about burst injection.\n", encoding="utf-8"
    )
    collection = _collection(tmp_path)

    changed = ingest.ingest_corpus_directory(corpus_dir, collection)

    assert changed == 1
    result = collection.get(where={"doc_id": "playbook_a"})
    assert result["metadatas"][0]["source_type"] == "playbook"
    assert result["metadatas"][0]["title"] == "Playbook A"


def test_ingest_corpus_directory_skips_unchanged_files(tmp_path, fake_embeddings):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "playbook_a.md").write_text("# Playbook A\n\nContent.\n", encoding="utf-8")
    collection = _collection(tmp_path)

    first_pass = ingest.ingest_corpus_directory(corpus_dir, collection)
    second_pass = ingest.ingest_corpus_directory(corpus_dir, collection)

    assert first_pass == 1
    assert second_pass == 0


def test_ingest_corpus_directory_reingests_changed_files(tmp_path, fake_embeddings):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    playbook_path = corpus_dir / "playbook_a.md"
    playbook_path.write_text("# Playbook A\n\nOriginal content.\n", encoding="utf-8")
    collection = _collection(tmp_path)

    ingest.ingest_corpus_directory(corpus_dir, collection)
    playbook_path.write_text("# Playbook A\n\nUpdated content, now different.\n", encoding="utf-8")
    changed = ingest.ingest_corpus_directory(corpus_dir, collection)

    assert changed == 1
    result = collection.get(where={"doc_id": "playbook_a"})
    assert "Updated content" in result["documents"][0]
    # Old chunks for this doc_id were removed, not left stale alongside new ones.
    assert len(result["documents"]) == 1


def test_ingest_corpus_directory_recurses_into_subdirectories(tmp_path, fake_embeddings):
    playbook_dir = tmp_path / "corpus" / "playbooks"
    playbook_dir.mkdir(parents=True)
    (playbook_dir / "pb-nested.md").write_text("# Nested\n\nContent.\n", encoding="utf-8")
    collection = _collection(tmp_path)

    changed = ingest.ingest_corpus_directory(tmp_path / "corpus", collection)

    assert changed == 1
    assert collection.get(where={"doc_id": "pb-nested"})["ids"]


def test_ingest_corpus_directory_removes_playbooks_whose_file_is_gone(tmp_path, fake_embeddings):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "keep.md").write_text("# Keep\n\nStays.\n", encoding="utf-8")
    (corpus_dir / "gone.md").write_text("# Gone\n\nRemoved later.\n", encoding="utf-8")
    collection = _collection(tmp_path)
    ingest.ingest_corpus_directory(corpus_dir, collection)

    (corpus_dir / "gone.md").unlink()
    changed = ingest.ingest_corpus_directory(corpus_dir, collection)

    assert changed == 1
    assert collection.get(where={"doc_id": "gone"})["ids"] == []
    assert collection.get(where={"doc_id": "keep"})["ids"]


def test_ingest_corpus_directory_does_not_touch_incident_chunks(tmp_path, fake_embeddings):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    collection = _collection(tmp_path)
    ingest.ingest_incident_document("abc-123", VALID_INCIDENT_DOCUMENT, collection)

    ingest.ingest_corpus_directory(corpus_dir, collection)

    assert collection.get(where={"doc_id": "abc-123"})["ids"]


def test_ingest_corpus_directory_skips_duplicate_doc_ids(tmp_path, fake_embeddings):
    corpus_dir = tmp_path / "corpus"
    (corpus_dir / "a").mkdir(parents=True)
    (corpus_dir / "b").mkdir()
    (corpus_dir / "a" / "same.md").write_text("# First\n\nOne.\n", encoding="utf-8")
    (corpus_dir / "b" / "same.md").write_text("# Second\n\nTwo.\n", encoding="utf-8")
    collection = _collection(tmp_path)

    changed = ingest.ingest_corpus_directory(corpus_dir, collection)

    assert changed == 1
    assert collection.get(where={"doc_id": "same"})["metadatas"][0]["title"] == "First"


def test_ingest_corpus_directory_missing_directory_returns_zero(tmp_path, fake_embeddings):
    collection = _collection(tmp_path)
    changed = ingest.ingest_corpus_directory(tmp_path / "does_not_exist", collection)
    assert changed == 0


# --- watching the connector's rag_ingest_queue table ------------------------


def _make_queue_db(tmp_path):
    db_path = tmp_path / "connector.sqlite3"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE rag_ingest_queue ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, "
        "document_text TEXT, status TEXT, created_at TEXT)"
    )
    conn.commit()
    conn.close()
    return db_path


def test_process_pending_incidents_ingests_valid_documents(tmp_path, fake_embeddings):
    db_path = _make_queue_db(tmp_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO rag_ingest_queue (incident_id, document_text, status, created_at) "
        "VALUES (?, ?, 'pending', '2026-01-01T00:00:00+00:00')",
        ("abc-123", VALID_INCIDENT_DOCUMENT),
    )
    conn.commit()
    conn.close()
    collection = _collection(tmp_path)

    ingested = ingest.process_pending_incidents(db_path, collection)

    assert ingested == 1
    conn = sqlite3.connect(str(db_path))
    query = "SELECT status FROM rag_ingest_queue WHERE incident_id = ?"
    status = conn.execute(query, ("abc-123",)).fetchone()[0]
    conn.close()
    assert status == "ingested"
    # Chunks carry the incident's own detection time, so date filters work.
    metadata = collection.get(where={"doc_id": "abc-123"})["metadatas"][0]
    assert metadata["timestamp"] == "2026-01-01T00:00:00+00:00"


def test_process_pending_incidents_rejects_malformed_documents(tmp_path, fake_embeddings):
    db_path = _make_queue_db(tmp_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO rag_ingest_queue (incident_id, document_text, status, created_at) "
        "VALUES (?, ?, 'pending', '2026-01-01T00:00:00+00:00')",
        ("bad-doc", "not a real template, just raw text"),
    )
    conn.commit()
    conn.close()
    collection = _collection(tmp_path)

    ingested = ingest.process_pending_incidents(db_path, collection)

    assert ingested == 0
    assert collection.count() == 0
    conn = sqlite3.connect(str(db_path))
    query = "SELECT status FROM rag_ingest_queue WHERE incident_id = ?"
    status = conn.execute(query, ("bad-doc",)).fetchone()[0]
    conn.close()
    assert status == "rejected"


def test_process_pending_incidents_never_reprocesses_a_row(tmp_path, fake_embeddings):
    db_path = _make_queue_db(tmp_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO rag_ingest_queue (incident_id, document_text, status, created_at) "
        "VALUES (?, ?, 'pending', '2026-01-01T00:00:00+00:00')",
        ("abc-123", VALID_INCIDENT_DOCUMENT),
    )
    conn.commit()
    conn.close()
    collection = _collection(tmp_path)

    first_pass = ingest.process_pending_incidents(db_path, collection)
    second_pass = ingest.process_pending_incidents(db_path, collection)

    assert first_pass == 1
    assert second_pass == 0


def test_watch_ingest_queue_stops_after_max_iterations(tmp_path, fake_embeddings):
    db_path = _make_queue_db(tmp_path)
    collection = _collection(tmp_path)

    # Should return promptly, not loop forever, with an empty queue.
    ingest.watch_ingest_queue(db_path, collection, poll_interval_seconds=0.0, max_iterations=2)


def test_watch_ingest_queue_stops_when_stop_event_is_set(tmp_path, fake_embeddings):
    import threading

    db_path = _make_queue_db(tmp_path)
    collection = _collection(tmp_path)
    stop_event = threading.Event()
    stop_event.set()

    ingest.watch_ingest_queue(
        db_path, collection, poll_interval_seconds=60.0, stop_event=stop_event
    )


# --- path resolution --------------------------------------------------------


def test_resolve_chroma_path_resolves_relative_paths_against_repo_root():
    from continuum.common.config import get_settings

    settings = get_settings()
    resolved = ingest.resolve_chroma_path(settings)
    assert resolved.is_absolute()


def test_resolve_corpus_path_resolves_relative_paths_against_repo_root():
    from continuum.common.config import get_settings

    settings = get_settings()
    resolved = ingest.resolve_corpus_path(settings)
    assert resolved.is_absolute()
    assert resolved.name == "corpus"
